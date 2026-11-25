package netdvm

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/hostbin"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/seedimg"
)

// qemu is the Linux hypervisor: qemu-system-* with KVM.
type qemu struct{ goarch string }

const (
	seedDisk = "seed.img"
	qmpSock  = "qmp.sock"
)

// qemuMin is the oldest qemu with -netdev dgram (an inherited datagram socket as the NIC).
var qemuMin = [3]int{7, 2, 0}

func (q qemu) kind() string { return "qemu" }

func (q qemu) defaultTool() string {
	if q.goarch == "arm64" {
		return "qemu-system-aarch64"
	}
	return "qemu-system-x86_64"
}

func (q qemu) supported(goos string) error {
	if goos != "linux" {
		return errors.New("the qemu driver runs on Linux only (on macOS the driver is vfkit)")
	}
	if q.goarch != "arm64" && q.goarch != "amd64" {
		return fmt.Errorf("the qemu driver does not support %s", q.goarch)
	}
	return nil
}

// checkVersion reads `qemu-system-* --version` ("QEMU emulator version 8.2.2 (Debian ...)").
func (qemu) checkVersion(out string) error {
	v, err := semver(out, "QEMU emulator version ")
	if err != nil {
		return err
	}
	if !atLeast(v, qemuMin) {
		return fmt.Errorf("qemu %d.%d.%d is too old: the driver needs %d.%d.%d or later", v[0], v[1], v[2], qemuMin[0], qemuMin[1], qemuMin[2])
	}
	return nil
}

// firmwarePairs are the UEFI code images and their variable-store templates, per architecture,
// where Debian/Ubuntu and Fedora/RHEL-family distributions install them. The code image must be
// the one without Secure Boot enforcement: the appliance's UKI is not signed with Microsoft's keys.
var firmwarePairs = map[string][][2]string{
	"arm64": {
		{"/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd", "/usr/share/AAVMF/AAVMF_VARS.fd"},
		{"/usr/share/AAVMF/AAVMF_CODE.fd", "/usr/share/AAVMF/AAVMF_VARS.fd"},
		{"/usr/share/edk2/aarch64/QEMU_EFI-silent-pflash.raw", "/usr/share/edk2/aarch64/vars-template-pflash.raw"},
		{"/usr/share/edk2/aarch64/QEMU_EFI-pflash.raw", "/usr/share/edk2/aarch64/vars-template-pflash.raw"},
	},
	"amd64": {
		{"/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"},
		{"/usr/share/OVMF/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_VARS.fd"},
		{"/usr/share/edk2/ovmf/OVMF_CODE.fd", "/usr/share/edk2/ovmf/OVMF_VARS.fd"},
		{"/usr/share/edk2/x64/OVMF_CODE.4m.fd", "/usr/share/edk2/x64/OVMF_VARS.4m.fd"},
	},
}

// findFirmware is the first installed, verified firmware pair for goarch.
func findFirmware(goarch string, exists func(string) bool) ([2]string, error) {
	for _, p := range firmwarePairs[goarch] {
		if exists(p[0]) && exists(p[1]) {
			return p, nil
		}
	}
	pkg := map[string]string{"arm64": "qemu-efi-aarch64 (Debian, Ubuntu) or edk2-aarch64 (Fedora)",
		"amd64": "ovmf (Debian, Ubuntu) or edk2-ovmf (Fedora, RHEL)"}[goarch]
	return [2]string{}, fmt.Errorf("no UEFI firmware for qemu found; install %s", pkg)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// prepare finds and verifies the firmware and copies its variable store into the VM directory.
func (q qemu) prepare(dir string, spec *vmSpec) error {
	fw, err := findFirmware(q.goarch, fileExists)
	if err != nil {
		return err
	}
	for _, p := range fw {
		if err := hostbin.VerifyFile("qemu firmware", p, os.Getuid()); err != nil {
			return err
		}
	}
	in, err := os.Open(fw[1])
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(filepath.Join(dir, efiVars), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	spec.Firmware = fw[0]
	return nil
}

// seed writes the NoCloud seed disk itself (seedimg: FAT12, label CIDATA).
func (qemu) seed(dir string, user, meta []byte) error {
	img, err := seedimg.Write(map[string][]byte{userData: user, metaData: meta})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, seedDisk), img, 0o600)
}

func (q qemu) command(d *Driver, s vmSpec) []string {
	dir := d.dir()
	machine := "q35,smm=off"
	if q.goarch == "arm64" {
		machine = "virt,gic-version=max"
	}
	args := []string{d.Tool,
		"-machine", machine, "-accel", "kvm", "-cpu", "host",
		"-smp", fmt.Sprint(s.CPUs), "-m", fmt.Sprint(s.MemoryMiB),
		"-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none",
		"-drive", "if=pflash,format=raw,readonly=on,file=" + s.Firmware,
		"-drive", "if=pflash,format=raw,file=" + filepath.Join(dir, efiVars),
		"-drive", "if=virtio,format=raw,discard=unmap,file=" + filepath.Join(dir, diskFile),
		"-drive", "if=virtio,format=raw,readonly=on,file=" + filepath.Join(dir, seedDisk),
		// netd's socket pair is the only NIC: no user-mode network, no shares
		"-netdev", "dgram,id=n0,local.type=fd,local.str=3",
		"-device", "virtio-net-pci,netdev=n0,mac=" + s.MAC,
		"-device", "virtio-rng-pci",
		"-chardev", "file,id=con,path=" + filepath.Join(dir, console), "-serial", "chardev:con",
	}
	if qmp := qemuQMPPath(dir); qmp != "" {
		args = append(args, "-qmp", "unix:"+qmp+",server=on,wait=off")
	}
	return args
}

func (qemu) env(string) []string { return nil }

// qemuQMPPath is the QMP control socket, used only to ask the guest to shut down ("" when the
// path is too long for a Unix socket: stop then falls back to force).
func qemuQMPPath(dir string) string {
	p := filepath.Join(dir, qmpSock)
	if len(p) >= 108 {
		return ""
	}
	return p
}

// requestStop sends ACPI power-off through QMP.
func (qemu) requestStop(d *Driver) error {
	p := qemuQMPPath(d.dir())
	if p == "" {
		return errors.New("no control socket")
	}
	c, err := net.DialTimeout("unix", p, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	if _, err := r.ReadBytes('\n'); err != nil { // the greeting
		return err
	}
	for _, cmd := range []string{"qmp_capabilities", "system_powerdown"} {
		b, _ := json.Marshal(map[string]string{"execute": cmd})
		if _, err := c.Write(append(b, '\n')); err != nil {
			return err
		}
		for { // skip events until the command's reply
			line, err := r.ReadBytes('\n')
			if err != nil {
				return err
			}
			var m map[string]json.RawMessage
			if json.Unmarshal(line, &m) != nil {
				continue
			}
			if e, ok := m["error"]; ok {
				return fmt.Errorf("qmp %s: %s", cmd, e)
			}
			if _, ok := m["return"]; ok {
				break
			}
		}
	}
	return nil
}

// kvmNested is what can be known on the host before the VM boots; the functional check is the VM
// itself (5.2.3 check 1, doctor's /dev/kvm check).
func kvmNested() (bool, string) {
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
	// arm64: nested KVM depends on the CPU and kernel; the VM start decides.
	return true, ""
}

// kvmUsable checks that this user may open /dev/kvm.
func kvmUsable() error {
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("cannot open /dev/kvm (%v): add yourself to the kvm group and log in again", err)
	}
	return f.Close()
}
