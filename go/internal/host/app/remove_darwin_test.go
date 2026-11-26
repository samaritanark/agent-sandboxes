package app

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestRemoveAllImmutable: a file with the user-immutable flag (as git pack files under v2's state
// have) does not stop the removal.
func TestRemoveAllImmutable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent-home")
	os.MkdirAll(filepath.Join(dir, "x", "pack"), 0o700)
	f := filepath.Join(dir, "x", "pack", "p.pack")
	os.WriteFile(f, []byte("x"), 0o400)
	if err := syscall.Chflags(f, 0x2); err != nil { // UF_IMMUTABLE
		t.Skip("cannot set file flags here:", err)
	}
	t.Cleanup(func() { syscall.Chflags(f, 0) })
	if err := os.RemoveAll(dir); err == nil {
		t.Fatal("the flag did not stop os.RemoveAll; the test proves nothing")
	}
	if err := removeAll(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("left in place")
	}
}
