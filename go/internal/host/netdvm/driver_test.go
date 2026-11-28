//go:build !windows

package netdvm

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/seedimg"
)

var seed = driver.SeedConfig{Hostname: "sandbox", AuthorizedKey: "ssh-ed25519 AAAAclient c",
	HostKeyPrivate: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n",
	HostKeyPublic:  "ssh-ed25519 AAAAhost sandbox-vm", CABundle: "-----BEGIN CERTIFICATE-----\nx\n"}

func TestSeedFiles(t *testing.T) {
	user, meta, err := seedFiles(seed, "sandbox-01")
	if err != nil {
		t.Fatal(err)
	}
	first, rest, _ := bytes.Cut(user, []byte("\n"))
	if string(first) != "#cloud-config" {
		t.Fatalf("user-data header %q", first)
	}
	var doc struct {
		WriteFiles []map[string]string `json:"write_files"`
	}
	if err := json.Unmarshal(rest, &doc); err != nil || len(doc.WriteFiles) != 1 {
		t.Fatalf("user-data %s: %v", rest, err)
	}
	wf := doc.WriteFiles[0]
	env, _ := driver.SeedEnv(seed)
	if wf["path"] != "/etc/sandbox/seed.env" || wf["owner"] != "root:root" || wf["permissions"] != "0600" || wf["content"] != env {
		t.Errorf("write_files %v", wf)
	}
	if string(meta) != "instance-id: sandbox-01\nlocal-hostname: sandbox\n" {
		t.Errorf("meta-data %q", meta)
	}
	for _, h := range []string{"Sandbox", "a b", "x\ninstance-id: evil", "-x", strings.Repeat("a", 64)} {
		s := seed
		s.Hostname = h
		if _, _, err := seedFiles(s, "i"); err == nil {
			t.Errorf("hostname %q accepted", h)
		}
	}
	s := seed
	s.AuthorizedKey = "ssh-ed25519 A\nSANDBOX_SEED_PROXY=x"
	if _, _, err := seedFiles(s, "i"); err == nil {
		t.Error("a value with a newline was accepted")
	}
}

func rawImage(t *testing.T, dir string, size int) string {
	t.Helper()
	b := make([]byte, size)
	copy(b[512:], "EFI PART")
	copy(b[3<<20:], "data in the middle")
	p := filepath.Join(dir, "img.raw")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCopySparse(t *testing.T) {
	dir := t.TempDir()
	src := rawImage(t, dir, 5<<20+123)
	dst := filepath.Join(dir, "copy")
	if err := copySparse(dst, src); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(src)
	b, _ := os.ReadFile(dst)
	if !bytes.Equal(a, b) {
		t.Error("the copy differs")
	}
	if err := copySparse(dst, src); err == nil {
		t.Error("an existing destination was overwritten")
	}
}

func TestCreate(t *testing.T) {
	state := filepath.Join(t.TempDir(), "vm")
	d := &Driver{hv: vfkit{}, Tool: "/usr/local/bin/vfkit", StateDir: state, Self: "/x/sandbox"}
	ctx := context.Background()
	if st, _ := d.Status(ctx); st != driver.NotCreated {
		t.Fatalf("status %v", st)
	}
	if _, err := d.Endpoint(ctx); err != driver.ErrNotCreated {
		t.Errorf("endpoint before create: %v", err)
	}
	res := driver.Resources{CPUs: 4, MemoryMiB: 8192, DiskGiB: 1}
	img := rawImage(t, t.TempDir(), 4<<20)

	qcow := filepath.Join(t.TempDir(), "img.qcow2")
	os.WriteFile(qcow, append([]byte("QFI\xfb"), make([]byte, 1024)...), 0o644)
	if err := d.Create(ctx, driver.ImageRef{Path: qcow}, res, seed); err == nil || !strings.Contains(err.Error(), "qemu-img convert") {
		t.Errorf("qcow2: %v", err)
	}
	bad := seed
	bad.HostKeyPrivate = ""
	if err := d.Create(ctx, driver.ImageRef{Path: img}, res, bad); err == nil {
		t.Error("an incomplete seed was accepted")
	}
	if _, err := os.Stat(d.dir()); err == nil {
		t.Error("a failed create left the VM directory")
	}

	if err := d.Create(ctx, driver.ImageRef{Path: img}, res, seed); err != nil {
		t.Fatal(err)
	}
	if st, err := d.Status(ctx); st != driver.Stopped || err != nil {
		t.Errorf("after create: %v %v", st, err)
	}
	if err := d.Create(ctx, driver.ImageRef{Path: img}, res, seed); err == nil {
		t.Error("a second create succeeded")
	}
	for _, f := range []string{userData, metaData, vmConfig, diskFile} {
		st, err := os.Stat(filepath.Join(d.dir(), f))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, st.Mode(), err)
		}
	}
	if st, _ := os.Stat(d.dir()); st.Mode().Perm() != 0o700 {
		t.Errorf("VM directory mode %v", st.Mode())
	}
	// the system disk is the image grown to systemDiskGiB; the state disk is the resources' disk
	if st, _ := os.Stat(filepath.Join(d.dir(), diskFile)); st.Size() != systemDiskGiB<<30 {
		t.Errorf("system disk size %d", st.Size())
	}
	if st, err := os.Stat(filepath.Join(d.dir(), stateFile)); err != nil || st.Size() != int64(res.DiskGiB)<<30 || st.Mode().Perm() != 0o600 {
		t.Errorf("state disk %v %v", st, err)
	}
	if k, _ := os.ReadFile(filepath.Join(state, keyRecord)); string(k) != seed.HostKeyPublic+"\n" {
		t.Errorf("pinned key %q", k)
	}
	spec, err := d.spec()
	if err != nil || spec.CPUs != 4 || spec.MemoryMiB != 8192 || !spec.Nested || spec.MAC[1] != '2' && spec.MAC[1] != '6' && spec.MAC[1] != 'a' && spec.MAC[1] != 'e' {
		t.Errorf("spec %+v %v", spec, err)
	}
	if _, err := d.Endpoint(ctx); err == nil || !strings.Contains(err.Error(), "stopped") {
		t.Errorf("endpoint while stopped: %v", err)
	}

	argv := strings.Join(d.hv.command(d, spec), " ")
	for _, want := range []string{"/usr/local/bin/vfkit ", "--cpus 4 ", "--memory 8192 ", "virtio-net,fd=3,mac=" + spec.MAC,
		"virtio-blk,path=" + filepath.Join(d.dir(), diskFile) + " --device virtio-blk,path=" + filepath.Join(d.dir(), stateFile), "--nested", "efi,variable-store="} {
		if !strings.Contains(argv, want) {
			t.Errorf("vfkit command lacks %q: %s", want, argv)
		}
	}
	if strings.Contains(argv, "nat") || strings.Contains(argv, "virtio-fs") || strings.Contains(argv, "unixSocketPath") {
		t.Errorf("vfkit command has another network or a share: %s", argv)
	}

	os.Remove(filepath.Join(d.dir(), diskFile))
	if st, _ := d.Status(ctx); st != driver.Broken {
		t.Errorf("without its disk: %v", st)
	}
}

func TestRandomMAC(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		m, err := randomMAC()
		if err != nil || !macRE.MatchString(m) {
			t.Fatalf("%q %v", m, err)
		}
		var b byte
		for _, c := range m[:2] {
			b = b<<4 | byte(strings.IndexRune("0123456789abcdef", c))
		}
		if b&1 != 0 || b&2 == 0 {
			t.Errorf("%s is not a locally administered unicast address", m)
		}
		seen[m] = true
	}
	if len(seen) < 45 {
		t.Error("MAC addresses repeat")
	}
}

func TestCheckVersion(t *testing.T) {
	for out, ok := range map[string]bool{"vfkit version: v0.6.4\n": true, "vfkit version: v0.6.0": true,
		"vfkit version: v1.0.0": true, "vfkit version: v0.10.1": true, "vfkit version: v0.5.9": false,
		"vfkit version: v0.6": false, "vfkit 0.6.4": false, "": false} {
		if err := (vfkit{}).checkVersion(out); (err == nil) != ok {
			t.Errorf("vfkit %q: %v", out, err)
		}
	}
	for out, ok := range map[string]bool{
		"QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)\nCopyright (c) 2003-2023": true,
		"QEMU emulator version 7.2.0": true, "QEMU emulator version 10.0.3": true,
		"QEMU emulator version 7.1.0": false, "QEMU emulator version 6.2.0 (Debian)": false, "qemu 8.2.2": false} {
		if err := (qemu{}).checkVersion(out); (err == nil) != ok {
			t.Errorf("qemu %q: %v", out, err)
		}
	}
}

func TestFindFirmware(t *testing.T) {
	have := map[string]bool{"/usr/share/edk2/ovmf/OVMF_CODE.fd": true, "/usr/share/edk2/ovmf/OVMF_VARS.fd": true,
		"/usr/share/OVMF/OVMF_CODE_4M.fd": true} // a code image without its variables is skipped
	fw, err := findFirmware("amd64", func(p string) bool { return have[p] })
	if err != nil || fw[0] != "/usr/share/edk2/ovmf/OVMF_CODE.fd" {
		t.Errorf("%v %v", fw, err)
	}
	if _, err := findFirmware("arm64", func(string) bool { return false }); err == nil || !strings.Contains(err.Error(), "qemu-efi-aarch64") {
		t.Errorf("none: %v", err)
	}
	for _, pairs := range firmwarePairs {
		for _, p := range pairs {
			if strings.Contains(strings.ToLower(p[0]), "secboot.fd") && !strings.Contains(p[0], "no-secboot") || strings.Contains(p[0], ".ms.") {
				t.Errorf("%s enforces Secure Boot", p[0])
			}
		}
	}
}

func TestQemuCommand(t *testing.T) {
	state := filepath.Join(t.TempDir(), "vm")
	for _, arch := range []string{"arm64", "amd64"} {
		d := &Driver{hv: qemu{goarch: arch}, Tool: "/usr/bin/qemu-system-x", StateDir: state}
		spec := vmSpec{CPUs: 4, MemoryMiB: 8192, MAC: "02:00:00:00:00:01", Firmware: "/fw/CODE.fd"}
		argv := strings.Join(d.hv.command(d, spec), " ")
		for _, want := range []string{"-accel kvm", "-cpu host", "-smp 4 ", "-m 8192 ", "-nodefaults", "-no-user-config",
			"-netdev dgram,id=n0,local.type=fd,local.str=3", "virtio-net-pci,netdev=n0,mac=02:00:00:00:00:01",
			"readonly=on,file=/fw/CODE.fd",
			// the state disk comes second: the guest's /dev/vdb, before the seed disk
			"file=" + filepath.Join(state, "qemu", diskFile) + " -drive if=virtio,format=raw,discard=unmap,file=" + filepath.Join(state, "qemu", stateFile) + " -drive if=virtio,format=raw,readonly=on,file=" + filepath.Join(state, "qemu", seedDisk),
			"readonly=on,file=" + filepath.Join(state, "qemu", seedDisk), "-qmp unix:"} {
			if !strings.Contains(argv, want) {
				t.Errorf("%s: no %q in %s", arch, want, argv)
			}
		}
		for _, bad := range []string{"user,", "-nic", "hostfwd", "virtfs", "9p", "-netdev user", "smb="} {
			if strings.Contains(argv, bad) {
				t.Errorf("%s: %q in %s", arch, bad, argv)
			}
		}
		if strings.Count(argv, "-netdev") != 1 {
			t.Errorf("%s: more than one network: %s", arch, argv)
		}
	}
}

func TestQemuSeed(t *testing.T) {
	dir := t.TempDir()
	user, meta, err := seedFiles(seed, "sandbox-01")
	if err != nil {
		t.Fatal(err)
	}
	if err := (qemu{}).seed(dir, user, meta); err != nil {
		t.Fatal(err)
	}
	img, _ := os.ReadFile(filepath.Join(dir, seedDisk))
	files, err := seedimg.Read(img)
	if err != nil || !bytes.Equal(files[userData], user) || !bytes.Equal(files[metaData], meta) {
		t.Errorf("seed disk: %v", err)
	}
	if st, _ := os.Stat(filepath.Join(dir, seedDisk)); st.Mode().Perm() != 0o600 {
		t.Errorf("seed disk mode %v", st.Mode())
	}
}

// TestReplaceSystemDisk (design 10): an upgrade replaces only the system disk, keeping the state
// disk and the previous system disk, which RollBack puts back; a VM without a state disk (made
// before it existed) is refused, so its state is not lost.
func TestReplaceSystemDisk(t *testing.T) {
	state := filepath.Join(t.TempDir(), "vm")
	d := &Driver{hv: vfkit{}, Tool: "/usr/local/bin/vfkit", StateDir: state, Self: "/x/sandbox"}
	ctx := context.Background()
	if err := d.Create(ctx, driver.ImageRef{Path: rawImage(t, t.TempDir(), 4<<20)}, driver.Resources{CPUs: 4, MemoryMiB: 8192, DiskGiB: 1}, seed); err != nil {
		t.Fatal(err)
	}
	dir := d.dir()
	f, _ := os.OpenFile(filepath.Join(dir, stateFile), os.O_WRONLY, 0)
	f.WriteAt([]byte("STATE"), 4096)
	f.Close()
	head := func(p string) string {
		b := make([]byte, 600)
		f, err := os.Open(p)
		if err != nil {
			return ""
		}
		defer f.Close()
		f.Read(b)
		return string(b[512:520]) + string(b[520:528])
	}
	old := head(filepath.Join(dir, diskFile))
	newImg := rawImage(t, t.TempDir(), 4<<20)
	g, _ := os.OpenFile(newImg, os.O_WRONLY, 0)
	g.WriteAt([]byte("NEWIMAGE"), 520)
	g.Close()
	if d.CanRollBack(ctx) {
		t.Error("a fresh VM can roll back")
	}
	if err := d.ReplaceSystemDisk(ctx, driver.ImageRef{Path: newImg}); err != nil {
		t.Fatal(err)
	}
	if h := head(filepath.Join(dir, diskFile)); !strings.HasSuffix(h, "NEWIMAGE") {
		t.Errorf("system disk %q", h)
	}
	if st, _ := os.Stat(filepath.Join(dir, diskFile)); st.Size() != systemDiskGiB<<30 {
		t.Errorf("system disk size %d", st.Size())
	}
	b := make([]byte, 5)
	sf, _ := os.Open(filepath.Join(dir, stateFile))
	sf.ReadAt(b, 4096)
	sf.Close()
	if string(b) != "STATE" || !d.CanRollBack(ctx) || head(filepath.Join(dir, prevDisk)) != old {
		t.Errorf("state %q, previous kept %v", b, d.CanRollBack(ctx))
	}
	if err := d.RollBack(ctx); err != nil || head(filepath.Join(dir, diskFile)) != old || d.CanRollBack(ctx) {
		t.Errorf("rollback: %v", err)
	}
	if err := d.RollBack(ctx); err == nil {
		t.Error("a second rollback succeeded")
	}
	os.Remove(filepath.Join(dir, stateFile))
	if err := d.ReplaceSystemDisk(ctx, driver.ImageRef{Path: newImg}); err == nil || !strings.Contains(err.Error(), "reinstall it once") {
		t.Errorf("no state disk: %v", err)
	}
}
