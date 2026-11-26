// Package netdvm is the VM driver whose network is `sandbox netd` (design 5.2.2, 5.2.6, D-31;
// spike S7): the hypervisor runs as a child of `sandbox __netd`, which owns the VM's only NIC (one
// end of a datagram socket pair) and its SSH listener for the VM's whole life, so the host-reach
// control holds while the CLI is not running. Lima cannot do this on either host: its own
// user-mode NIC is always attached.
//
// Two hypervisors share everything but their command line, seed delivery, and shutdown channel:
// vfkit on macOS (Apple's Virtualization framework) and qemu with KVM on Linux.
package netdvm

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/hostbin"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/netd"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/sizing"
)

// keyRecord is the guest's pinned SSH host key, under the host binary's VM state directory.
const keyRecord = "ssh_host_key.pub"

// The VM directory's files (the directory is ~/.sandbox/vm/<kind>).
const (
	vmConfig = "vm.json" // written last by Create: its presence means the VM exists
	diskFile = "disk.raw"
	efiVars  = "efivars"
	userData = "user-data"
	metaData = "meta-data"
	console  = "console.log"
	netdLog  = "netd.log"
)

// Grace is how long the guest gets to shut down before it is stopped by force.
const Grace = time.Minute

// vmSpec is vm.json.
type vmSpec struct {
	CPUs      int    `json:"cpus"`
	MemoryMiB int    `json:"memoryMiB"`
	MAC       string `json:"mac"`
	Nested    bool   `json:"nested"`
	Firmware  string `json:"firmware,omitempty"` // qemu: the UEFI code image
}

// hypervisor is what differs between vfkit and qemu.
type hypervisor interface {
	kind() string                             // the driver's name and VM directory
	defaultTool() string                      // the binary looked up on PATH
	checkVersion(versionOutput string) error  // `tool --version`
	prepare(dir string, spec *vmSpec) error   // at Create: firmware, variables
	seed(dir string, user, meta []byte) error // at Create: deliver the NoCloud seed
	command(d *Driver, s vmSpec) []string     // argv; the link is fd 3, netd's lock fd 4
	env(dir string) []string                  // extra environment for the hypervisor
	requestStop(d *Driver) error              // ask the guest to shut down
	supported(goos string) error              // whether this host can run it
}

func hypervisorFor(kind string) (hypervisor, error) {
	switch kind {
	case "vfkit":
		return vfkit{}, nil
	case "qemu":
		return qemu{goarch: runtime.GOARCH}, nil
	}
	return nil, fmt.Errorf("unknown VM driver %q", kind)
}

// Kinds are the drivers this package provides.
var Kinds = []string{"vfkit", "qemu"}

// Driver drives one netd VM.
type Driver struct {
	hv       hypervisor
	Tool     string // verified absolute path of vfkit or qemu-system-*
	StateDir string // ~/.sandbox/vm
	Self     string // this binary, which runs as `__netd`
}

func toolRecord(kind string) string { return kind + ".path" }

func (d *Driver) dir() string { return filepath.Join(d.StateDir, d.hv.kind()) }

// Recorded is the kind install chose, or "" when it chose none of this package's drivers.
func Recorded(stateDir string) string {
	for _, k := range Kinds {
		if _, err := os.Stat(filepath.Join(stateDir, toolRecord(k))); err == nil {
			return k
		}
	}
	return ""
}

// Record resolves the hypervisor binary (an absolute path, or found on PATH), verifies it, checks
// its version, and records it.
func Record(stateDir, kind, tool string) (string, error) {
	hv, err := hypervisorFor(kind)
	if err != nil {
		return "", err
	}
	if err := hv.supported(runtime.GOOS); err != nil {
		return "", err
	}
	p := tool
	if p == "" {
		p = hv.defaultTool()
	}
	if !filepath.IsAbs(p) {
		lp, err := exec.LookPath(p)
		if err != nil {
			return "", fmt.Errorf("%s not found: install it, or pass --driver lima: %w", p, err)
		}
		if p, err = filepath.Abs(lp); err != nil {
			return "", err
		}
	}
	if err := hostbin.Verify(kind, p, os.Getuid()); err != nil {
		return "", err
	}
	out, err := exec.Command(p, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("%s --version: %w", p, err)
	}
	if err := hv.checkVersion(string(out)); err != nil {
		return "", err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	return p, os.WriteFile(filepath.Join(stateDir, toolRecord(kind)), []byte(p+"\n"), 0o600)
}

// Open loads the recorded binary for kind and re-verifies it (5.1.2).
func Open(stateDir, kind string) (*Driver, error) {
	hv, err := hypervisorFor(kind)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(stateDir, toolRecord(kind)))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, driver.ErrNotCreated
		}
		return nil, err
	}
	p := strings.TrimSuffix(string(b), "\n")
	if err := hostbin.Verify(kind, p, os.Getuid()); err != nil {
		return nil, fmt.Errorf("%w (if %s was reinstalled or moved, reinstall the sandbox VM with --%s <path>)", err, kind, kind)
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return &Driver{hv: hv, Tool: p, StateDir: stateDir, Self: self}, nil
}

func (d *Driver) Name() string { return d.hv.kind() }

func (d *Driver) spec() (vmSpec, error) {
	var s vmSpec
	b, err := os.ReadFile(filepath.Join(d.dir(), vmConfig))
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("%s: %w", vmConfig, err)
	}
	if s.CPUs < 1 || s.MemoryMiB < 512 || !macRE.MatchString(s.MAC) {
		return s, fmt.Errorf("%s: invalid VM settings", vmConfig)
	}
	return s, nil
}

func (d *Driver) Status(context.Context) (driver.State, error) {
	if _, err := os.Stat(filepath.Join(d.dir(), vmConfig)); errors.Is(err, os.ErrNotExist) {
		return driver.NotCreated, nil
	}
	running, err := netd.Running(d.dir())
	if err != nil {
		return driver.Broken, err
	}
	if running {
		return driver.Running, nil
	}
	if _, err := d.spec(); err != nil {
		return driver.Broken, nil
	}
	if _, err := os.Stat(filepath.Join(d.dir(), diskFile)); err != nil {
		return driver.Broken, nil
	}
	return driver.Stopped, nil
}

var (
	macRE      = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
	hostnameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// isRawGPT reports whether p is a raw disk with a GPT header, the format both hypervisors boot.
func isRawGPT(p string) (bool, error) {
	f, err := os.Open(p)
	if err != nil {
		return false, err
	}
	defer f.Close()
	head := make([]byte, 520)
	if _, err := io.ReadFull(f, head); err != nil {
		return false, nil
	}
	return string(head[512:520]) == "EFI PART", nil
}

// copySparse copies src to dst, skipping runs of zeros so the copy stays as sparse as the image.
func copySparse(dst, src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	zero := make([]byte, len(buf))
	var off int64
	for {
		n, err := io.ReadFull(in, buf)
		if n > 0 {
			if !bytes.Equal(buf[:n], zero[:n]) {
				if _, werr := out.WriteAt(buf[:n], off); werr != nil {
					out.Close()
					return werr
				}
			}
			off += int64(n)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			out.Close()
			return err
		}
	}
	if err := out.Truncate(off); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// seedFiles renders the cloud-init NoCloud seed: user-data writes the seed file (driver.SeedEnv)
// root-owned and 0600 on first boot, as Lima's data provision does.
func seedFiles(seed driver.SeedConfig, instanceID string) (user, meta []byte, err error) {
	env, err := driver.SeedEnv(seed)
	if err != nil {
		return nil, nil, err
	}
	host := seed.Hostname
	if host == "" {
		host = "sandbox"
	}
	if !hostnameRE.MatchString(host) {
		return nil, nil, fmt.Errorf("invalid hostname %q", host)
	}
	// JSON is YAML, so every value is quoted and no seed value can change the document's shape.
	doc, err := json.Marshal(map[string]interface{}{
		"write_files": []map[string]string{{
			"path": "/etc/sandbox/seed.env", "owner": "root:root", "permissions": "0600", "content": env,
		}},
	})
	if err != nil {
		return nil, nil, err
	}
	user = append([]byte("#cloud-config\n"), doc...)
	user = append(user, '\n')
	meta = []byte("instance-id: " + instanceID + "\nlocal-hostname: " + host + "\n")
	return user, meta, nil
}

func randomMAC() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[0] = b[0]&0xfc | 0x02 // locally administered, unicast
	parts := make([]string, 6)
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":"), nil
}

func (d *Driver) Create(ctx context.Context, img driver.ImageRef, res driver.Resources, seed driver.SeedConfig) error {
	if st, err := d.Status(ctx); err != nil {
		return err
	} else if st != driver.NotCreated {
		return errors.New("the sandbox VM already exists")
	}
	if !filepath.IsAbs(img.Path) {
		return fmt.Errorf("image path must be absolute: %q", img.Path)
	}
	if ok, err := isRawGPT(img.Path); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%s is not a raw disk image with a GPT partition table, which the %s driver needs (convert a qcow2 image with: qemu-img convert -O raw IN OUT)", img.Path, d.hv.kind())
	}
	if res.CPUs < 1 || res.MemoryMiB < 512 || res.DiskGiB < 1 {
		return fmt.Errorf("invalid VM resources %+v", res)
	}
	dir := d.dir()
	// vfkit's and qemu's device options are comma-separated key=value lists.
	if strings.ContainsAny(dir, ",=") {
		return fmt.Errorf("the VM directory %s holds a comma or '=', which the hypervisor's options cannot carry", dir)
	}
	mac, err := randomMAC()
	if err != nil {
		return err
	}
	id := make([]byte, 8)
	rand.Read(id)
	user, meta, err := seedFiles(seed, "sandbox-"+hex.EncodeToString(id))
	if err != nil {
		return err
	}
	spec := vmSpec{CPUs: res.CPUs, MemoryMiB: res.MemoryMiB, MAC: mac, Nested: true}
	if err := os.MkdirAll(d.StateDir, 0o700); err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil { // the remains of a failed create
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(dir)
		}
	}()
	// The pin comes first: nothing may connect to the guest before its key is recorded.
	if err := os.WriteFile(filepath.Join(d.StateDir, keyRecord), []byte(strings.TrimSpace(seed.HostKeyPublic)+"\n"), 0o600); err != nil {
		return err
	}
	if err := d.hv.prepare(dir, &spec); err != nil {
		return err
	}
	if err := d.hv.seed(dir, user, meta); err != nil {
		return err
	}
	disk := filepath.Join(dir, diskFile)
	if err := copySparse(disk, img.Path); err != nil {
		return fmt.Errorf("copying the image: %w", err)
	}
	// The image grows its root partition to fill the disk on first boot (cloud-init growpart).
	if st, err := os.Stat(disk); err != nil {
		return err
	} else if want := int64(res.DiskGiB) << 30; st.Size() < want {
		if err := os.Truncate(disk, want); err != nil {
			return err
		}
	}
	b, _ := json.MarshalIndent(spec, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, vmConfig), append(b, '\n'), 0o600); err != nil {
		return err
	}
	ok = true
	return nil
}

func (d *Driver) Endpoint(ctx context.Context) (driver.SSHEndpoint, error) {
	st, err := d.Status(ctx)
	if err != nil {
		return driver.SSHEndpoint{}, err
	}
	switch st {
	case driver.NotCreated:
		return driver.SSHEndpoint{}, driver.ErrNotCreated
	case driver.Running:
	default:
		return driver.SSHEndpoint{}, fmt.Errorf("the sandbox VM is %s", st)
	}
	if !d.Network(ctx).Running {
		return driver.SSHEndpoint{}, errNoNetd
	}
	port, err := netd.SSHPort(d.dir())
	if err != nil {
		return driver.SSHEndpoint{}, fmt.Errorf("netd has not published the VM's SSH port: %w", err)
	}
	key, err := os.ReadFile(filepath.Join(d.StateDir, keyRecord))
	if err != nil {
		return driver.SSHEndpoint{}, fmt.Errorf("the guest's pinned host key is missing: %w", err)
	}
	return driver.SSHEndpoint{Host: "127.0.0.1", Port: port, User: "root", HostKey: strings.TrimSpace(string(key))}, nil
}

// errNoNetd is the state of a VM whose netd supervisor died: the link died with it.
var errNoNetd = errors.New("sandbox netd is not running, so the sandbox VM has no network; restart the VM with: sandbox vm start")

// Network reports on netd (driver.NetworkOwner).
func (d *Driver) Network(ctx context.Context) driver.NetworkReport {
	if st, err := d.Status(ctx); err != nil || st != driver.Running {
		return driver.NetworkReport{Detail: "the VM is not running"}
	}
	if pid := d.ours(netd.PIDFile, "__netd "+d.dir()); pid > 0 {
		return driver.NetworkReport{Running: true, Detail: fmt.Sprintf("running (pid %d)", pid)}
	}
	return driver.NetworkReport{Detail: errNoNetd.Error()}
}

func (d *Driver) HostReach(context.Context) (driver.HostReachControl, error) {
	return driver.HostReachControl{Mechanism: "sandbox netd (the VM's only network; host addresses refused, declared endpoints allowed)", Scoped: true}, nil
}

// semver reads the first "a.b.c" after prefix in out.
func semver(out, prefix string) ([3]int, error) {
	var v [3]int
	i := strings.Index(out, prefix)
	if i < 0 {
		return v, fmt.Errorf("cannot read the version in %q", strings.TrimSpace(out))
	}
	if n, _ := fmt.Sscanf(out[i+len(prefix):], "%d.%d.%d", &v[0], &v[1], &v[2]); n != 3 {
		return v, fmt.Errorf("cannot read the version in %q", strings.TrimSpace(out))
	}
	return v, nil
}

// atLeast reports whether v >= min.
func atLeast(v, min [3]int) bool {
	for i := range v {
		if v[i] != min[i] {
			return v[i] > min[i]
		}
	}
	return true
}

func (d *Driver) Probe(ctx context.Context) (driver.Capabilities, error) {
	c := driver.Capabilities{CPUs: runtime.NumCPU(), DriverBinary: d.Tool, MemoryBytes: sizing.HostMemory()}
	if out, err := exec.CommandContext(ctx, d.Tool, "--version").Output(); err != nil {
		c.Problems = append(c.Problems, fmt.Sprintf("%s --version: %v", d.Tool, err))
	} else if err := d.hv.checkVersion(string(out)); err != nil {
		c.Problems = append(c.Problems, err.Error())
	}
	if err := d.hv.supported(runtime.GOOS); err != nil {
		c.Problems = append(c.Problems, err.Error())
	}
	c.Hypervisor, c.NestedVirt = probeHost(d.hv.kind(), &c)
	return c, nil
}
