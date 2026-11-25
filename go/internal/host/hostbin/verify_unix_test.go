//go:build !windows

package hostbin

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestCheckOne(t *testing.T) {
	dir := t.TempDir()
	uid := os.Getuid()
	f := filepath.Join(dir, "f")
	os.WriteFile(f, nil, 0o755)
	if err := checkOne(f, uid); err != nil {
		t.Errorf("own 0755 file: %v", err)
	}
	if err := checkOne(f, uid+1); err == nil && uid != 0 {
		t.Error("a file owned by another account passed")
	}
	os.Chmod(f, 0o757)
	if err := checkOne(f, uid); err == nil || !strings.Contains(err.Error(), "every user") {
		t.Errorf("world-writable: %v", err)
	}
	os.Chmod(f, 0o775)
	var st syscall.Stat_t
	syscall.Stat(f, &st)
	if err := checkOne(f, uid); (err == nil) != trustedGroup(st.Gid) {
		t.Errorf("group-writable (gid %d): %v", st.Gid, err)
	}
	l := filepath.Join(dir, "l")
	os.Symlink("/nonexistent", l)
	if err := checkOne(l, uid); err != nil {
		t.Errorf("own symlink: %v", err)
	}
}

func TestVerify(t *testing.T) {
	if err := Verify("limactl", "/bin/sh", os.Getuid()); err != nil {
		t.Errorf("/bin/sh: %v", err)
	}
	for _, p := range []string{"bin/sh", "/bin/../bin/sh", "/bin//sh", "/nonexistent/limactl"} {
		if err := Verify("limactl", p, os.Getuid()); err == nil {
			t.Errorf("%q passed", p)
		}
	}
	// a directory others can write anywhere above the binary
	ww := filepath.Join(t.TempDir(), "ww")
	os.MkdirAll(filepath.Join(ww, "bin"), 0o755)
	os.Chmod(ww, 0o777)
	exe := filepath.Join(ww, "bin", "limactl")
	os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755)
	if err := Verify("limactl", exe, os.Getuid()); err == nil {
		t.Error("a binary below a world-writable directory passed")
	}
	// a link from a good place to a bad one is judged by its target too
	if err := Verify("limactl", "/etc/hosts", os.Getuid()); err == nil || !strings.Contains(err.Error(), "not an executable") {
		t.Errorf("non-executable: %v", err)
	}
}

func TestVerifyFile(t *testing.T) {
	// A root-owned system file (a test's own temporary directory may sit under the world-writable
	// /tmp, which the check rightly refuses).
	if err := VerifyFile("firmware", "/etc/hosts", os.Getuid()); err != nil {
		t.Errorf("/etc/hosts: %v", err)
	}
	if err := Verify("qemu", "/etc/hosts", os.Getuid()); err == nil {
		t.Error("a non-executable passed Verify")
	}
	if err := VerifyFile("firmware", "/etc", os.Getuid()); err == nil {
		t.Error("a directory passed")
	}
}
