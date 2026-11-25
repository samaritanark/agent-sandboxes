package app

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/release"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/sizing"
)

// InstallDeps are install's host-specific parts.
type InstallDeps struct {
	// RecordDriver records the VM driver (kind "vfkit", "qemu", or "lima"; "" for this host's
	// default) and
	// verifies its tool (an explicit path, or "" to find it on PATH), then opens the driver.
	RecordDriver func(kind, tool string) (driver.Driver, error)
	// GenerateKey makes an ed25519 key pair in OpenSSH format.
	GenerateKey func(comment string) (private, public string, err error)
	HostCPUs    int
	HostMemGiB  int
	// ReadyTimeout bounds the wait for the VM's first handshake (default two minutes).
	ReadyTimeout time.Duration
	// Poll is the wait between handshake attempts (default two seconds).
	Poll time.Duration
}

// removedInstallFlags are design section 6's removed install flags, with their replacements.
var removedInstallFlags = map[string]string{
	"--dns":            "the VM uses the host's upstream DNS and split zones (design 5.8.9)",
	"--apiserver-port": "not needed: v3 runs no Kubernetes",
	"--pod-cidr":       "not needed: v3 runs no Kubernetes",
	"--service-cidr":   "not needed: v3 runs no Kubernetes",
}

const installUsage = `Usage: sandbox install --dev-image <path> [options]

Create and start the sandbox VM.

Options:
  --dev-image <path>   A local appliance image (raw; qcow2 for --driver lima).
                       Development builds only: its signature is not checked.
  --vm-cpus <n>        VM CPUs (default: host CPUs less 2, at least 4)
  --vm-memory <GiB>    VM memory (default: host memory less 6 GiB, at least 8)
  --vm-disk <GiB>      VM state disk (default: 60)
  --driver <name>      The VM driver: vfkit (macOS) or qemu (Linux), the defaults,
                       whose only network is sandbox netd, which keeps the VM from
                       reaching this host; or lima, which cannot block the host's
                       LAN address
  --vfkit <path>       The vfkit binary to use (default: vfkit on PATH)
  --qemu <path>        The qemu-system binary to use (default: on PATH)
  --limactl <path>     The Lima binary to use (default: limactl on PATH)
`

func (a *app) install(args []string) int {
	var image, tool, kind string
	tools := map[string]string{} // driver -> tool path given
	var o sizing.Overrides
	for len(args) > 0 {
		f := args[0]
		args = args[1:]
		name, val, hasVal := strings.Cut(f, "=")
		if why, ok := removedInstallFlags[name]; ok {
			a.die("'sandbox install %s' was removed in v3: %s.", name, why)
		}
		value := func() string {
			if hasVal {
				return val
			}
			if len(args) == 0 {
				a.die("install: %s needs a value", name)
			}
			v := args[0]
			args = args[1:]
			return v
		}
		switch name {
		case "-h", "--help":
			fmt.Fprint(a.env.Stdout, installUsage)
			return 0
		case "--dev-image":
			image = value()
		case "--vm-cpus":
			o.CPUs = value()
		case "--vm-memory":
			o.MemoryGiB = value()
		case "--vm-disk":
			o.DiskGiB = value()
		case "--driver":
			kind = value()
		case "--vfkit":
			tools["vfkit"] = value()
		case "--qemu":
			tools["qemu"] = value()
		case "--limactl":
			tools["lima"] = value()
		default:
			fmt.Fprint(a.env.Stderr, installUsage)
			a.die("install: unknown option '%s'", f)
		}
	}
	if image == "" {
		fmt.Fprint(a.env.Stderr, installUsage)
		a.die("install: no image. Signed appliance images are not published yet; pass a development image with --dev-image.")
	}
	cpus, err := sizing.CPUs(o, a.env.Install.HostCPUs)
	if err != nil {
		a.die("%v", err)
	}
	mem, err := sizing.MemoryGiB(o, a.env.Install.HostMemGiB)
	if err != nil {
		a.die("%v", err)
	}
	disk, err := sizing.DiskGiB(o)
	if err != nil {
		a.die("%v", err)
	}
	img, err := filepath.Abs(image)
	if err != nil {
		a.die("%v", err)
	}
	if st, err := os.Stat(img); err != nil || !st.Mode().IsRegular() {
		a.die("the image %s is not a file", img)
	}
	if err := checkDiskImage(img); err != nil {
		a.die("%v", err)
	}

	if len(tools) > 1 {
		a.die("install: --vfkit, --qemu, and --limactl choose different drivers; pass one")
	}
	for k, p := range tools {
		if kind != "" && kind != k {
			a.die("install: the %s path does not apply to the %s driver", k, kind)
		}
		kind, tool = k, p
	}
	if kind != "" && kind != "vfkit" && kind != "qemu" && kind != "lima" {
		a.die("install: unknown driver '%s' (vfkit, qemu, or lima)", kind)
	}
	d, err := a.env.Install.RecordDriver(kind, tool)
	if err != nil {
		a.die("%v", err)
	}
	a.env.Driver = d
	st, err := d.Status(a.ctx)
	if err != nil {
		a.die("cannot read the sandbox VM's state: %v", err)
	}
	if st != driver.NotCreated {
		a.die("the sandbox VM already exists (%s). To start over: sandbox uninstall, then sandbox install.", st)
	}
	caps, err := d.Probe(a.ctx)
	if err != nil {
		a.die("cannot probe this host: %v", err)
	}
	if !caps.NestedVirt {
		a.die("this host cannot give the VM nested virtualization, which v3 requires (design 5.2.3):\n  %s",
			strings.Join(caps.Problems, "\n  "))
	}
	for _, p := range caps.Problems {
		fmt.Fprintf(a.env.Stderr, "WARNING: %s\n", p)
	}
	fmt.Fprintf(a.env.Stderr, "WARNING: %s is a development image; its signature is not checked.\n", img)

	vmState := filepath.Join(a.env.StateDir, "vm")
	if err := os.MkdirAll(vmState, 0o700); err != nil {
		a.die("%v", err)
	}
	fmt.Fprintln(a.env.Stdout, "==> Generating the VM's SSH keys...")
	clientPriv, clientPub, err := a.env.Install.GenerateKey("sandbox-client")
	if err != nil {
		a.die("%v", err)
	}
	hostPriv, hostPub, err := a.env.Install.GenerateKey("sandbox-vm")
	if err != nil {
		a.die("%v", err)
	}
	if err := os.WriteFile(filepath.Join(vmState, "id_ed25519"), []byte(clientPriv), 0o600); err != nil {
		a.die("%v", err)
	}
	os.WriteFile(filepath.Join(vmState, "id_ed25519.pub"), []byte(clientPub+"\n"), 0o600)

	seed := driver.SeedConfig{Hostname: "sandbox", AuthorizedKey: clientPub, HostKeyPrivate: hostPriv,
		HostKeyPublic: hostPub, CABundle: a.caBundle()}
	res := driver.Resources{CPUs: cpus, MemoryMiB: mem * 1024, DiskGiB: disk}
	fmt.Fprintf(a.env.Stdout, "==> Creating the sandbox VM (%s; %d CPUs, %d GiB memory, %d GiB disk)...\n", d.Name(), cpus, mem, disk)
	if err := d.Create(a.ctx, driver.ImageRef{Path: img}, res, seed); err != nil {
		a.die("could not create the sandbox VM: %v", err)
	}
	fmt.Fprintln(a.env.Stdout, "==> Starting the sandbox VM...")
	if err := d.Start(a.ctx); err != nil {
		a.die("could not start the sandbox VM: %v", err)
	}
	info, err := a.waitReady()
	if err != nil {
		a.die("the sandbox VM started but is not answering: %v\n  See: sandbox vm status", err)
	}
	fmt.Fprintf(a.env.Stdout, "The sandbox VM is installed and running (image %s, control API %d).\n", info.ImageVersion, info.ControlAPI)
	return 0
}

// waitReady retries the handshake until the VM answers or the timeout passes.
func (a *app) waitReady() (info release.Info, err error) {
	timeout, poll := a.env.Install.ReadyTimeout, a.env.Install.Poll
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	if poll == 0 {
		poll = 2 * time.Second
	}
	deadline := a.env.Now().Add(timeout)
	for {
		var ep driver.SSHEndpoint
		if ep, err = a.env.Driver.Endpoint(a.ctx); err == nil {
			if info, err = a.checkRelease(ep); err == nil {
				return info, nil
			}
		}
		if !a.env.Now().Before(deadline) {
			return info, err
		}
		select {
		case <-a.ctx.Done():
			return info, a.ctx.Err()
		case <-time.After(poll):
		}
	}
}

// caBundle is every certificate file in ~/.sandbox/extra-ca-certs (*.crt, *.pem), for the
// first-boot seed; the same files are pushed before each command (5.1.4, 5.10).
func (a *app) caBundle() string {
	var b strings.Builder
	dir := filepath.Join(a.env.StateDir, "extra-ca-certs")
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, ".") || !(strings.HasSuffix(n, ".crt") || strings.HasSuffix(n, ".pem")) || !e.Type().IsRegular() {
			continue
		}
		if c, err := os.ReadFile(filepath.Join(dir, n)); err == nil {
			b.Write(c)
			if len(c) > 0 && c[len(c)-1] != '\n' {
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}

const uninstallUsage = `Usage: sandbox uninstall [--keep-vm] [--purge]

Delete the sandbox VM and its SSH keys. On a terminal, ask whether to remove
each kind of state in ~/.sandbox as well; otherwise keep it.

Options:
  --keep-vm   Keep the VM and its keys
  --purge     Remove every kind of state below without asking
`

// stateCategory is one kind of operator state uninstall offers to remove (design 5.1.6).
type stateCategory struct {
	what  string
	paths []string // relative to ~/.sandbox
}

var stateCategories = []stateCategory{
	{"secrets and agent tokens", []string{"secrets", "agent-home"}},
	{"withheld workspace changes", []string{"quarantine"}},
	{"logs", []string{"logs"}},
	{"settings and profiles", []string{"config.yaml", "profiles", "vetting", "extra-ca-certs", "overlays"}},
}

func (a *app) uninstall(args []string) int {
	keepVM, purge := false, false
	for _, f := range args {
		switch f {
		case "-h", "--help":
			fmt.Fprint(a.env.Stdout, uninstallUsage)
			return 0
		case "--keep-vm":
			keepVM = true
		case "--purge":
			purge = true
		case "--keep-lima", "--keep-kubetools":
			a.die("'sandbox uninstall %s' was removed in v3: use --keep-vm.", f)
		default:
			fmt.Fprint(a.env.Stderr, uninstallUsage)
			a.die("uninstall: unknown option '%s'", f)
		}
	}
	if !keepVM {
		a.removeVM()
	}
	kept := a.removeState(purge)
	switch {
	case keepVM && len(kept) == 0:
		fmt.Fprintln(a.env.Stdout, "Kept the sandbox VM.")
	case keepVM:
		fmt.Fprintf(a.env.Stdout, "Kept the sandbox VM and your %s in ~/.sandbox.\n", strings.Join(kept, ", "))
	case len(kept) == 0:
		fmt.Fprintln(a.env.Stdout, "The sandbox VM is removed.")
	default:
		fmt.Fprintf(a.env.Stdout, "The sandbox VM is removed. Kept your %s in ~/.sandbox.\n", strings.Join(kept, ", "))
	}
	return 0
}

func (a *app) removeVM() {
	st, err := a.env.Driver.Status(a.ctx)
	if err != nil {
		a.die("cannot read the sandbox VM's state: %v", err)
	}
	if st == driver.Running {
		if ep, err := a.env.Driver.Endpoint(a.ctx); err == nil {
			a.pullAudit(ep) // the sessions' last records, before the VM is deleted
		}
		fmt.Fprintln(a.env.Stdout, "==> Stopping the sandbox VM...")
		if err := a.env.Driver.Stop(a.ctx); err != nil {
			// deleting stops it by force
			fmt.Fprintf(a.env.Stderr, "WARNING: could not stop the sandbox VM cleanly: %v\n", err)
		}
	}
	if st != driver.NotCreated {
		fmt.Fprintln(a.env.Stdout, "==> Deleting the sandbox VM...")
		if err := a.env.Driver.Delete(a.ctx); err != nil {
			a.die("could not delete the sandbox VM: %v", err)
		}
	}
	vmState := filepath.Join(a.env.StateDir, "vm")
	for _, f := range []string{"id_ed25519", "id_ed25519.pub", "known_hosts", "ssh_host_key.pub", "limactl.path", "vfkit.path", "qemu.path"} {
		if err := os.Remove(filepath.Join(vmState, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			a.die("%v", err)
		}
	}
	os.Remove(vmState) // only if now empty
}

// removeState offers each category that exists; it returns the ones kept.
func (a *app) removeState(purge bool) []string {
	var kept []string
	in := bufio.NewReader(a.env.Stdin)
	for _, c := range stateCategories {
		var present []string
		for _, p := range c.paths {
			if _, err := os.Lstat(filepath.Join(a.env.StateDir, p)); err == nil {
				present = append(present, p)
			}
		}
		if len(present) == 0 {
			continue
		}
		remove := purge
		if !purge && a.env.StdinTTY && a.env.Stdin != nil {
			fmt.Fprintf(a.env.Stdout, "Remove your %s (~/.sandbox/%s)? [y/N] ", c.what, strings.Join(present, ", ~/.sandbox/"))
			reply, _ := in.ReadString('\n')
			r := strings.TrimSpace(reply)
			remove = r == "y" || r == "Y" || r == "yes" || r == "YES"
		}
		if !remove {
			kept = append(kept, c.what)
			continue
		}
		for _, p := range present {
			if err := os.RemoveAll(filepath.Join(a.env.StateDir, p)); err != nil {
				a.die("could not remove ~/.sandbox/%s: %v", p, err)
			}
		}
		fmt.Fprintf(a.env.Stdout, "Removed your %s.\n", c.what)
	}
	return kept
}

// checkDiskImage refuses a file that is plainly not a VM disk before anything is created: it must
// be qcow2 (magic QFI\xfb) or a raw disk with a GPT header (EFI PART at byte 512), which is what
// the image pipeline produces (design 5.3.2).
func checkDiskImage(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	head := make([]byte, 520)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	if bytes.HasPrefix(head, []byte("QFI\xfb")) || len(head) >= 520 && string(head[512:520]) == "EFI PART" {
		return nil
	}
	return fmt.Errorf("%s is neither a qcow2 image nor a raw disk image with a GPT partition table", p)
}
