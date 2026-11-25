package seedimg

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func files() map[string][]byte {
	big := bytes.Repeat([]byte("0123456789abcdef"), 700) // 11200 bytes: several clusters
	return map[string][]byte{
		"user-data":      append([]byte("#cloud-config\n"), big...),
		"meta-data":      []byte("instance-id: sandbox-01\nlocal-hostname: sandbox\n"),
		"network-config": {},
	}
}

func TestRoundTrip(t *testing.T) {
	img, err := Write(files())
	if err != nil {
		t.Fatal(err)
	}
	if len(img) != totalSectors*sectorSize {
		t.Errorf("size %d", len(img))
	}
	got, err := Read(img)
	if err != nil {
		t.Fatal(err)
	}
	for n, want := range files() {
		if !bytes.Equal(got[n], want) {
			t.Errorf("%s: %d bytes back, want %d", n, len(got[n]), len(want))
		}
	}
	if len(got) != len(files()) {
		t.Errorf("files %v", len(got))
	}
	again, _ := Write(files())
	if !bytes.Equal(img, again) {
		t.Error("not deterministic")
	}
}

func TestRefusals(t *testing.T) {
	for _, n := range []string{"", "a/b", "a b", "../x", "ü", strings.Repeat("a", 65)} {
		if _, err := Write(map[string][]byte{n: nil}); err == nil {
			t.Errorf("%q accepted", n)
		}
	}
	if _, err := Write(map[string][]byte{"huge": make([]byte, 2<<20)}); err == nil {
		t.Error("oversized content accepted")
	}
}

func TestFAT12Packing(t *testing.T) {
	fat := []uint16{0xFF8, 0xFFF, 0x003, 0xFFF, 0x123}
	p := packFAT12(fat)
	if !bytes.Equal(p[:6], []byte{0xF8, 0xFF, 0xFF, 0x03, 0xF0, 0xFF}) {
		t.Errorf("packed % x", p)
	}
}

// TestWithLinuxTools checks the image with the system's own FAT tools when they are installed
// (dosfstools and mtools on the CI's Linux runner or the build VM).
func TestWithLinuxTools(t *testing.T) {
	fsck, err1 := exec.LookPath("fsck.vfat")
	mcopy, err2 := exec.LookPath("mcopy")
	if err1 != nil || err2 != nil {
		t.Skip("fsck.vfat or mcopy not installed")
	}
	img, _ := Write(files())
	p := filepath.Join(t.TempDir(), "seed.img")
	os.WriteFile(p, img, 0o600)
	if out, err := exec.Command(fsck, "-n", "-v", p).CombinedOutput(); err != nil {
		t.Fatalf("fsck.vfat: %v\n%s", err, out)
	}
	for n, want := range files() {
		out, err := exec.Command(mcopy, "-n", "-i", p, "::/"+n, "-").Output()
		if err != nil || !bytes.Equal(out, want) {
			t.Errorf("mcopy %s: %v (%d bytes)", n, err, len(out))
		}
	}
	if blkid, err := exec.LookPath("blkid"); err == nil {
		out, _ := exec.Command(blkid, "-p", "-o", "export", p).Output()
		if !strings.Contains(string(out), "LABEL=CIDATA") || !strings.Contains(string(out), "TYPE=vfat") {
			t.Errorf("blkid:\n%s", out)
		}
	}
}
