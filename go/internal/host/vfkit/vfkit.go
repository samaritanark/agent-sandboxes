// Package vfkit is the macOS VM driver that gives `sandbox netd` the VM's only NIC (design 5.2.2,
// 5.2.6, D-31; spike S7). It runs vfkit (Apple's Virtualization framework, crc-org/vfkit) as a
// child of `sandbox __netd`, which owns the VM's network link and SSH listener for the VM's
// whole life, so the host-reach control holds while the CLI is not running. Lima cannot do this:
// its own user-mode NIC is always attached.
package vfkit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

// Files under the host binary's VM state directory (~/.sandbox/vm).
const (
	toolRecord = "vfkit.path"       // the verified vfkit path, recorded at install
	keyRecord  = "ssh_host_key.pub" // the guest's pinned SSH host key
	subdir     = "vfkit"            // the VM: disk, firmware variables, seed, netd's files
)

// The VM directory's files.
const (
	vmConfig = "vm.json" // written last by Create: its presence means the VM exists
	diskFile = "disk.raw"
	efiVars  = "efivars"
	userData = "user-data"
	metaData = "meta-data"
	console  = "console.log"
	netdLog  = "netd.log"
	restSock = "rest.sock"
)

// Grace is how long the guest gets to shut down before it is stopped by force.
const Grace = time.Minute

// vmSpec is vm.json.
type vmSpec struct {
	CPUs      int    `json:"cpus"`
	MemoryMiB int    `json:"memoryMiB"`
	MAC       string `json:"mac"`
	Nested    bool   `json:"nested"`
}

// Driver drives one vfkit VM.
type Driver struct {
	Vfkit    string // verified absolute path
	StateDir string // ~/.sandbox/vm
	Self     string // this binary, which runs as `__netd`
}

func (d *Driver) dir() string { return filepath.Join(d.StateDir, subdir) }

// Recorded reports whether install chose this driver.
func Recorded(stateDir string) bool {
	_, err := os.Stat(filepath.Join(stateDir, toolRecord))
	return err == nil
}

// Record resolves vfkit (an absolute path, or found on PATH), verifies it, and records it.
func Record(stateDir, tool string) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", errors.New("the vfkit driver runs on macOS only")
	}
	p := tool
	if !filepath.IsAbs(p) {
		lp, err := exec.LookPath(p)
		if err != nil {
			return "", fmt.Errorf("vfkit not found: install it (brew install vfkit), or pass --driver lima: %w", err)
		}
		if p, err = filepath.Abs(lp); err != nil {
			return "", err
		}
	}
	if err := hostbin.Verify("vfkit", p, os.Getuid()); err != nil {
		return "", err
	}
	out, err := exec.Command(p, "--version").Output()
	if err != nil {
		return "", fmt.Errorf("vfkit --version: %w", err)
	}
	if err := checkVersion(string(out)); err != nil {
		return "", err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	return p, os.WriteFile(filepath.Join(stateDir, toolRecord), []byte(p+"\n"), 0o600)
}

// Open loads the recorded vfkit path and re-verifies it (5.1.2).
func Open(stateDir string) (*Driver, error) {
	b, err := os.ReadFile(filepath.Join(stateDir, toolRecord))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, driver.ErrNotCreated
		}
		return nil, err
	}
	p := strings.TrimSuffix(string(b), "\n")
	if err := hostbin.Verify("vfkit", p, os.Getuid()); err != nil {
		return nil, fmt.Errorf("%w (if vfkit was reinstalled, run 'sandbox upgrade' to record it again)", err)
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return &Driver{Vfkit: p, StateDir: stateDir, Self: self}, nil
}

func (d *Driver) Name() string { return "vfkit" }

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

// isRawGPT reports whether p is a raw disk with a GPT header, the only format vfkit boots.
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

// seedFiles renders the cloud-init NoCloud seed that vfkit attaches: user-data writes the seed
// file (driver.SeedEnv) root-owned and 0600 on first boot, as Lima's data provision does.
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
		return fmt.Errorf("%s is not a raw disk image with a GPT partition table, which vfkit needs (convert a qcow2 image with: qemu-img convert -O raw IN OUT)", img.Path)
	}
	if res.CPUs < 1 || res.MemoryMiB < 512 || res.DiskGiB < 1 {
		return fmt.Errorf("invalid VM resources %+v", res)
	}
	dir := d.dir()
	// vfkit's device options are comma-separated key=value lists.
	if strings.ContainsAny(dir, ",=") {
		return fmt.Errorf("the VM directory %s holds a comma or '=', which vfkit's options cannot carry", dir)
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
	for name, b := range map[string][]byte{userData: user, metaData: meta} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			return err
		}
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
	b, _ := json.MarshalIndent(vmSpec{CPUs: res.CPUs, MemoryMiB: res.MemoryMiB, MAC: mac, Nested: true}, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, vmConfig), append(b, '\n'), 0o600); err != nil {
		return err
	}
	ok = true
	return nil
}

// vmCommand is the vfkit command line; the VM's link is fd 3 and netd's lock fd 4.
func (d *Driver) vmCommand(s vmSpec) []string {
	dir := d.dir()
	args := []string{d.Vfkit,
		"--cpus", fmt.Sprint(s.CPUs), "--memory", fmt.Sprint(s.MemoryMiB),
		"--bootloader", "efi,variable-store=" + filepath.Join(dir, efiVars) + ",create",
		"--device", "virtio-blk,path=" + filepath.Join(dir, diskFile),
		"--device", "virtio-net,fd=3,mac=" + s.MAC,
		"--device", "virtio-rng",
		"--device", "virtio-serial,logFilePath=" + filepath.Join(dir, console),
		"--cloud-init", filepath.Join(dir, userData) + "," + filepath.Join(dir, metaData),
		"--restful-uri", d.restURI(),
	}
	if s.Nested {
		args = append(args, "--nested")
	}
	return args
}

// restURI is vfkit's control socket, used only to ask the guest to shut down. A path too long for
// a Unix socket disables it, and stop falls back to force.
func (d *Driver) restURI() string {
	p := filepath.Join(d.dir(), restSock)
	if len(p) >= 104 {
		return "none://"
	}
	return "unix://" + p
}

// requestStop asks vfkit to request a guest shutdown (the guest sees a power button press).
func (d *Driver) requestStop() error {
	uri := d.restURI()
	if !strings.HasPrefix(uri, "unix://") {
		return errors.New("no control socket")
	}
	sock := strings.TrimPrefix(uri, "unix://")
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}}
	resp, err := c.Post("http://vfkit/vm/state", "application/json", strings.NewReader(`{"state":"Stop"}`))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 { // vfkit answers 202 Accepted
		return fmt.Errorf("vfkit: %s", resp.Status)
	}
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

// MinVersion is the oldest vfkit with everything the driver uses: virtio-net fd=, --nested, and
// --cloud-init.
var MinVersion = [3]int{0, 6, 0}

// checkVersion reads `vfkit --version` ("vfkit version: v0.6.4") and refuses older releases.
func checkVersion(out string) error {
	v, ok := strings.CutPrefix(strings.TrimSpace(out), "vfkit version: v")
	var got [3]int
	if n, _ := fmt.Sscanf(v, "%d.%d.%d", &got[0], &got[1], &got[2]); !ok || n != 3 {
		return fmt.Errorf("vfkit --version: cannot read %q", strings.TrimSpace(out))
	}
	for i := range got {
		if got[i] != MinVersion[i] {
			if got[i] < MinVersion[i] {
				return fmt.Errorf("vfkit %d.%d.%d is too old: the driver needs %d.%d.%d or later", got[0], got[1], got[2], MinVersion[0], MinVersion[1], MinVersion[2])
			}
			break
		}
	}
	return nil
}

func (d *Driver) Probe(ctx context.Context) (driver.Capabilities, error) {
	c := driver.Capabilities{Hypervisor: "vz", CPUs: runtime.NumCPU(), DriverBinary: d.Vfkit,
		MemoryBytes: sizing.HostMemory(), NestedVirt: runtime.GOOS == "darwin"} // decided by the VM start itself, as on lima-vz
	cmd := exec.CommandContext(ctx, d.Vfkit, "--version")
	if out, err := cmd.Output(); err != nil {
		c.Problems = append(c.Problems, fmt.Sprintf("vfkit --version: %v", err))
	} else if err := checkVersion(string(out)); err != nil {
		c.Problems = append(c.Problems, err.Error())
	}
	if runtime.GOOS != "darwin" {
		c.Problems = append(c.Problems, "the vfkit driver runs on macOS only")
	}
	return c, nil
}
