//go:build !windows

package vfkit

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
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
	d := &Driver{Vfkit: "/usr/local/bin/vfkit", StateDir: state, Self: "/x/sandbox"}
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
	if st, _ := os.Stat(filepath.Join(d.dir(), diskFile)); st.Size() != 1<<30 {
		t.Errorf("disk size %d", st.Size())
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

	argv := strings.Join(d.vmCommand(spec), " ")
	for _, want := range []string{"/usr/local/bin/vfkit ", "--cpus 4 ", "--memory 8192 ", "virtio-net,fd=3,mac=" + spec.MAC,
		"virtio-blk,path=" + filepath.Join(d.dir(), diskFile), "--nested", "efi,variable-store="} {
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
