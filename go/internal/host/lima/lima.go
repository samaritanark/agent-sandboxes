// Package lima is the lima-vz (macOS) and lima-qemu (Linux) VM driver of design 5.2.2. It shells
// out to limactl rather than importing Lima's Go packages, which are not a stable API (5.1.2), and
// re-verifies the recorded limactl path on every use.
package lima

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/hostbin"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/sizing"
)

// Instance is the Lima instance name of the appliance VM.
const Instance = "sandbox-v3"

// Driver drives one Lima instance.
type Driver struct {
	Limactl  string // verified absolute path
	Instance string
	StateDir string // ~/.sandbox/vm: the recorded limactl path and the pinned host key
	GOOS     string
	GOARCH   string
	// Exec runs limactl with args and returns stdout; stderr is folded into the error.
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func execLimactl(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	// Lima reads proxy variables from the environment of `limactl start`; propagateProxyEnv is
	// off in the config, and the environment is passed as is otherwise.
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 2000 {
			msg = msg[len(msg)-2000:]
		}
		return out, fmt.Errorf("limactl %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	return out, nil
}

// limactlRecord is where `sandbox install` records the limactl path.
func limactlRecord(stateDir string) string { return filepath.Join(stateDir, "limactl.path") }

// hostKeyRecord is the guest's pinned SSH host public key.
func hostKeyRecord(stateDir string) string { return filepath.Join(stateDir, "ssh_host_key.pub") }

// Record resolves limactl (an absolute path, or found on PATH) at install or upgrade, verifies
// it, and records it. The unresolved path is recorded, so a Homebrew upgrade of Lima, which moves
// the link's target, still passes the next verification.
func Record(stateDir, limactl string) (string, error) {
	p := limactl
	if !filepath.IsAbs(p) {
		lp, err := exec.LookPath(p)
		if err != nil {
			return "", fmt.Errorf("limactl not found: install Lima (https://lima-vm.io) first: %w", err)
		}
		if p, err = filepath.Abs(lp); err != nil {
			return "", err
		}
	}
	if err := hostbin.Verify("limactl", p, os.Getuid()); err != nil {
		return "", err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	return p, os.WriteFile(limactlRecord(stateDir), []byte(p+"\n"), 0o600)
}

// Open loads the recorded limactl path and re-verifies it (5.1.2).
func Open(stateDir string) (*Driver, error) {
	b, err := os.ReadFile(limactlRecord(stateDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, driver.ErrNotCreated
		}
		return nil, err
	}
	p := strings.TrimSuffix(string(b), "\n")
	if err := hostbin.Verify("limactl", p, os.Getuid()); err != nil {
		return nil, fmt.Errorf("%w (if Lima was reinstalled or moved, reinstall the sandbox VM with --limactl <path>)", err)
	}
	return &Driver{Limactl: p, Instance: Instance, StateDir: stateDir, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Exec: execLimactl}, nil
}

func (d *Driver) Name() string {
	if d.GOOS == "darwin" {
		return "lima-vz"
	}
	return "lima-qemu"
}

func (d *Driver) limactl(ctx context.Context, args ...string) ([]byte, error) {
	return d.Exec(ctx, d.Limactl, append([]string{"--tty=false"}, args...)...)
}

// instance is one line of `limactl list --json`.
type instance struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	SSHLocalPort int    `json:"sshLocalPort"`
}

func (d *Driver) find(ctx context.Context) (*instance, error) {
	out, err := d.limactl(ctx, "list", "--json")
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var in instance
		if err := json.Unmarshal(sc.Bytes(), &in); err != nil {
			return nil, fmt.Errorf("limactl list: %w", err)
		}
		if in.Name == d.Instance {
			return &in, nil
		}
	}
	return nil, sc.Err()
}

func (d *Driver) Status(ctx context.Context) (driver.State, error) {
	in, err := d.find(ctx)
	if err != nil {
		return driver.Broken, err
	}
	if in == nil {
		return driver.NotCreated, nil
	}
	switch in.Status {
	case "Running":
		return driver.Running, nil
	case "Stopped":
		return driver.Stopped, nil
	}
	return driver.Broken, nil
}

func (d *Driver) Create(ctx context.Context, img driver.ImageRef, res driver.Resources, seed driver.SeedConfig) error {
	if st, err := d.Status(ctx); err != nil {
		return err
	} else if st != driver.NotCreated {
		return fmt.Errorf("the Lima instance %s already exists", d.Instance)
	}
	cfg, err := Config(d.GOOS, d.GOARCH, img, res, seed)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d.StateDir, 0o700); err != nil {
		return err
	}
	// The pin comes first: nothing may connect to the guest before its key is recorded.
	if err := os.WriteFile(hostKeyRecord(d.StateDir), []byte(strings.TrimSpace(seed.HostKeyPublic)+"\n"), 0o600); err != nil {
		return err
	}
	// The config holds the guest's private host key; Lima copies it into its 0700 instance
	// directory, and the staging copy is removed whatever happens.
	f, err := os.CreateTemp(d.StateDir, "lima-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(cfg); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, err = d.limactl(ctx, "create", "--name="+d.Instance, f.Name())
	return err
}

func (d *Driver) Start(ctx context.Context) error {
	_, err := d.limactl(ctx, "start", d.Instance)
	return err
}

// Stop asks the guest to shut down (Lima does it over its own SSH connection) and, if that fails
// within a minute, stops the VM by force.
func (d *Driver) Stop(ctx context.Context) error {
	gctx, cancel := context.WithTimeout(ctx, time.Minute)
	_, err := d.limactl(gctx, "stop", d.Instance)
	cancel()
	if err == nil {
		return nil
	}
	if _, ferr := d.limactl(ctx, "stop", "--force", d.Instance); ferr != nil {
		return fmt.Errorf("%v; forced stop: %v", err, ferr)
	}
	return nil
}

func (d *Driver) Delete(ctx context.Context) error {
	if _, err := d.limactl(ctx, "delete", "--force", d.Instance); err != nil {
		return err
	}
	return os.Remove(hostKeyRecord(d.StateDir))
}

func (d *Driver) Endpoint(ctx context.Context) (driver.SSHEndpoint, error) {
	in, err := d.find(ctx)
	if err != nil {
		return driver.SSHEndpoint{}, err
	}
	if in == nil {
		return driver.SSHEndpoint{}, driver.ErrNotCreated
	}
	if in.Status != "Running" || in.SSHLocalPort <= 0 || in.SSHLocalPort > 65535 {
		return driver.SSHEndpoint{}, fmt.Errorf("the Lima instance %s is %s", d.Instance, strings.ToLower(in.Status))
	}
	key, err := os.ReadFile(hostKeyRecord(d.StateDir))
	if err != nil {
		return driver.SSHEndpoint{}, fmt.Errorf("the guest's pinned host key is missing: %w", err)
	}
	// Lima forwards a localhost port to the guest's sshd; a different address from Lima is not
	// followed.
	return driver.SSHEndpoint{Host: "127.0.0.1", Port: in.SSHLocalPort, User: "root", HostKey: strings.TrimSpace(string(key))}, nil
}

func (d *Driver) HostReach(context.Context) (driver.HostReachControl, error) {
	if d.GOOS == "darwin" {
		return driver.HostReachControl{Mechanism: "lima hostLoopback=false (all host reach blocked)", BlocksAll: true}, nil
	}
	return driver.HostReachControl{Mechanism: "none yet: lima-qemu has no host-side control (spike S7)"}, nil
}

func (d *Driver) Probe(ctx context.Context) (driver.Capabilities, error) {
	c := driver.Capabilities{Hypervisor: map[bool]string{true: "vz", false: "qemu"}[d.GOOS == "darwin"],
		CPUs: runtime.NumCPU(), DriverBinary: d.Limactl}
	if _, err := d.limactl(ctx, "--version"); err != nil {
		c.Problems = append(c.Problems, err.Error())
	}
	nested, why := hostNested(d.GOOS)
	c.NestedVirt = nested
	if why != "" {
		c.Problems = append(c.Problems, why)
	}
	c.MemoryBytes = sizing.HostMemory()
	return c, nil
}

// hostNested is what can be known on the host before the VM boots; the functional check is the
// VM starting with nested virtualization (5.2.3 check 1).
func hostNested(goos string) (bool, string) {
	if goos != "linux" {
		return true, "" // vz: decided by the VM start itself (Apple M3 or later, macOS 15 or later)
	}
	for _, m := range []string{"kvm_intel", "kvm_amd"} {
		b, err := os.ReadFile("/sys/module/" + m + "/parameters/nested")
		if err == nil {
			v := strings.TrimSpace(string(b))
			if v == "Y" || v == "1" {
				return true, ""
			}
			return false, "nested KVM is disabled (" + m + " nested=" + v + ")"
		}
	}
	if _, err := os.Stat("/dev/kvm"); err != nil {
		return false, "no /dev/kvm: KVM is not available on this host"
	}
	return false, "cannot tell whether nested KVM is enabled"
}
