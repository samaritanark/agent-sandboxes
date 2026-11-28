package netdvm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

// vfkit is the macOS hypervisor: crc-org/vfkit on Apple's Virtualization framework.
type vfkit struct{}

const restSock = "rest.sock"

// vfkitMin is the oldest vfkit with everything used here: virtio-net fd=, --nested, --cloud-init.
var vfkitMin = [3]int{0, 6, 0}

func (vfkit) kind() string        { return "vfkit" }
func (vfkit) defaultTool() string { return "vfkit" }

func (vfkit) supported(goos string) error {
	if goos != "darwin" {
		return errors.New("the vfkit driver runs on macOS only")
	}
	return nil
}

// checkVersion reads `vfkit --version` ("vfkit version: v0.6.4").
func (vfkit) checkVersion(out string) error {
	if !strings.HasPrefix(strings.TrimSpace(out), "vfkit version: v") {
		return fmt.Errorf("vfkit --version: cannot read %q", strings.TrimSpace(out))
	}
	v, err := semver(out, "vfkit version: v")
	if err != nil {
		return err
	}
	if !atLeast(v, vfkitMin) {
		return fmt.Errorf("vfkit %d.%d.%d is too old: the driver needs %d.%d.%d or later", v[0], v[1], v[2], vfkitMin[0], vfkitMin[1], vfkitMin[2])
	}
	return nil
}

// prepare: vfkit creates its EFI variable store itself.
func (vfkit) prepare(string, *vmSpec) error { return nil }

// seed: vfkit builds the NoCloud ISO from the two files at each start (in TMPDIR, see env).
func (vfkit) seed(dir string, user, meta []byte) error {
	for name, b := range map[string][]byte{userData: user, metaData: meta} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (vfkit) command(d *Driver, s vmSpec) []string {
	dir := d.dir()
	args := []string{d.Tool,
		"--cpus", fmt.Sprint(s.CPUs), "--memory", fmt.Sprint(s.MemoryMiB),
		"--bootloader", "efi,variable-store=" + filepath.Join(dir, efiVars) + ",create",
		"--device", "virtio-blk,path=" + filepath.Join(dir, diskFile),
		"--device", "virtio-blk,path=" + filepath.Join(dir, stateFile),
		"--device", "virtio-net,fd=3,mac=" + s.MAC,
		"--device", "virtio-rng",
		"--device", "virtio-serial,logFilePath=" + filepath.Join(dir, console),
		"--cloud-init", filepath.Join(dir, userData) + "," + filepath.Join(dir, metaData),
		"--restful-uri", vfkitRestURI(dir),
	}
	if s.Nested {
		args = append(args, "--nested")
	}
	return args
}

// env keeps the cloud-init ISO vfkit builds (which holds the seed) in the VM's 0700 directory.
func (vfkit) env(dir string) []string { return []string{"TMPDIR=" + dir} }

// vfkitRestURI is vfkit's control socket, used only to ask the guest to shut down. A path too long
// for a Unix socket disables it, and stop falls back to force.
func vfkitRestURI(dir string) string {
	p := filepath.Join(dir, restSock)
	if len(p) >= 104 {
		return "none://"
	}
	return "unix://" + p
}

// requestStop asks vfkit to request a guest shutdown (the guest sees a power button press).
func (vfkit) requestStop(d *Driver) error {
	uri := vfkitRestURI(d.dir())
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

// probeHost is what the host offers each hypervisor. On vz, nested virtualization is decided by
// the VM start itself (Apple M3 or later, macOS 15 or later), as on lima-vz.
func probeHost(kind string, c *driver.Capabilities) (string, bool) {
	if kind == "vfkit" {
		return "vz", true
	}
	nested, why := kvmNested()
	if why != "" {
		c.Problems = append(c.Problems, why)
	}
	if err := kvmUsable(); err != nil {
		c.Problems = append(c.Problems, err.Error())
	}
	return "kvm", nested
}
