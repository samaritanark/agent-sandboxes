package main

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func tarOf(t *testing.T, entries ...[3]string) *bytes.Buffer { // name, type ("f", "d", "l"), body
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range entries {
		h := &tar.Header{Name: e[0], Mode: 0o644}
		switch e[1] {
		case "d":
			h.Typeflag = tar.TypeDir
		case "l":
			h.Typeflag, h.Linkname = tar.TypeSymlink, e[2]
		default:
			h.Typeflag, h.Size = tar.TypeReg, int64(len(e[2]))
		}
		tw.WriteHeader(h)
		if e[1] == "f" {
			tw.Write([]byte(e[2]))
		}
	}
	tw.Close()
	return &b
}

// TestImportHistory: files and directories land beneath the agent's history for the tier and key;
// links are skipped, an existing file is kept, and a path out of the directory is refused.
func TestImportHistory(t *testing.T) {
	store := t.TempDir()
	key := "0123456789abcdef"
	dir := filepath.Join(store, "claude", "tier2", key)
	n, err := importHistory(store, "claude", "2", key, os.Getuid(), tarOf(t,
		[3]string{"-workspace/", "d", ""}, [3]string{"-workspace/a.jsonl", "f", "one"},
		[3]string{"-workspace/a/sub/x.jsonl", "f", "deep"}, [3]string{"-workspace/l", "l", "/etc/passwd"}))
	if err != nil || n != 2 {
		t.Fatalf("%d %v", n, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "-workspace", "a", "sub", "x.jsonl")); string(b) != "deep" {
		t.Errorf("%q", b)
	}
	if _, err := os.Lstat(filepath.Join(dir, "-workspace", "l")); err == nil {
		t.Error("a link was imported")
	}
	// again: the existing file is kept
	if n, err := importHistory(store, "claude", "2", key, os.Getuid(), tarOf(t, [3]string{"-workspace/a.jsonl", "f", "two"})); err != nil || n != 0 {
		t.Errorf("rerun %d %v", n, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "-workspace", "a.jsonl")); string(b) != "one" {
		t.Errorf("overwritten: %q", b)
	}
	for _, bad := range []string{"../x", "/abs", "-workspace/../../y"} {
		if _, err := importHistory(store, "claude", "2", key, os.Getuid(), tarOf(t, [3]string{bad, "f", "z"})); err == nil {
			t.Errorf("%q imported", bad)
		}
	}
	// a link planted inside the history directory is not followed
	os.Symlink(t.TempDir(), filepath.Join(dir, "planted"))
	if _, err := importHistory(store, "claude", "2", key, os.Getuid(), tarOf(t, [3]string{"planted/x", "f", "z"})); err == nil {
		t.Error("wrote through a link")
	}
	if _, err := importHistory(store, "claude", "1", key, os.Getuid(), tarOf(t)); err == nil {
		t.Error("tier 1 history imported")
	}
}
