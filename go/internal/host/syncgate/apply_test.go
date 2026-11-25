package syncgate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fp(data string) string { return Fingerprint("file", []byte(data), false, "") }

func TestApply(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses symlinks")
	}
	repo := t.TempDir()
	w := func(p, c string) {
		os.MkdirAll(filepath.Dir(filepath.Join(repo, p)), 0o755)
		os.WriteFile(filepath.Join(repo, p), []byte(c), 0o644)
	}
	w("edit.txt", "old")
	w("stale.txt", "host changed this")
	w("gone.txt", "bye")
	w(".git/hooks/README", "hooks")
	w("typed.txt", "file")
	w(".gitattributes", "*.md text\n")
	os.Symlink(".git/hooks", filepath.Join(repo, "tools")) // an in-repo link into git state
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "shared"), []byte("shared"), 0o644)
	os.Link(filepath.Join(outside, "shared"), filepath.Join(repo, "linked.txt")) // a hard link on the host

	var quarantined []string
	a := &Applier{Repo: repo, MaxFile: 100, MaxBatch: 150, Quarantine: func(c Change, why string) error {
		quarantined = append(quarantined, c.Path+": "+why)
		return nil
	}}
	batch := []Change{
		{Path: "new/dir/file.go", Data: []byte("package x"), Base: ""},
		{Path: "edit.txt", Data: []byte("new"), Base: fp("old")},
		{Path: "stale.txt", Data: []byte("vm"), Base: fp("what the vm saw")},
		{Path: "gone.txt", Op: OpDelete, Base: fp("bye")},
		{Path: ".env", Data: []byte("SECRET=x"), Base: ""},
		{Path: "tools/pre-commit", Data: []byte("#!/bin/sh\nevil"), Exec: true, Base: ""},
		{Path: "esc", Op: OpSymlink, Target: "../../etc/passwd", Base: ""},
		{Path: "abs", Op: OpSymlink, Target: "/etc/passwd", Base: ""},
		{Path: "togit", Op: OpSymlink, Target: ".git/config", Base: ""},
		{Path: "docs/ok", Op: OpSymlink, Target: "../edit.txt", Base: ""},
		{Path: "typed.txt", Op: OpSymlink, Target: "edit.txt", Base: fp("file")},
		{Path: "big.bin", Data: []byte(strings.Repeat("x", 101)), Base: ""},
		{Path: "run.sh", Data: []byte("#!/bin/sh\n"), Exec: true, Base: ""},
		{Path: ".gitattributes", Data: []byte("*.md text\n* diff=evil\n"), Base: fp("*.md text\n")},
		{Path: "linked.txt", Data: []byte("replaced"), Base: fp("shared")},
		{Path: "a/../b", Data: []byte("x")},
		{Path: ".git/config", Data: []byte("[core]")},
	}
	out, err := a.Apply(batch)
	if err != nil {
		t.Fatal(err)
	}
	res := map[string]bool{}
	for _, o := range out {
		res[o.Path] = o.Applied
	}
	for p, applied := range map[string]bool{"new/dir/file.go": true, "edit.txt": true, "stale.txt": false, "gone.txt": true,
		".env": false, "tools/pre-commit": false, "esc": false, "abs": false, "togit": false, "docs/ok": true,
		"typed.txt": false, "big.bin": false, "run.sh": true, ".gitattributes": false, "linked.txt": true,
		"a/../b": false, ".git/config": false} {
		if res[p] != applied {
			t.Errorf("%s: applied=%v, want %v", p, res[p], applied)
		}
	}
	read := func(p string) string { b, _ := os.ReadFile(filepath.Join(repo, p)); return string(b) }
	if read("edit.txt") != "new" || read("stale.txt") != "host changed this" || read("new/dir/file.go") != "package x" {
		t.Error("file contents")
	}
	if _, err := os.Lstat(filepath.Join(repo, "gone.txt")); !os.IsNotExist(err) {
		t.Error("gone.txt not deleted")
	}
	if _, err := os.Stat(filepath.Join(repo, ".git/hooks/pre-commit")); err == nil {
		t.Fatal("a write through an in-repo symlink reached .git/hooks")
	}
	if b, _ := os.ReadFile(filepath.Join(outside, "shared")); string(b) != "shared" {
		t.Error("a hard-linked host file was written through")
	}
	if st, _ := os.Stat(filepath.Join(repo, "run.sh")); st.Mode().Perm()&0o111 == 0 {
		t.Error("exec bit lost")
	}
	if len(quarantined) != 11 {
		t.Errorf("%d quarantined:\n%s", len(quarantined), strings.Join(quarantined, "\n"))
	}
	ents, _ := os.ReadDir(repo)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".sandbox-sync-") {
			t.Errorf("temporary file left: %s", e.Name())
		}
	}

	// resuming: applying the same batch again finds the applied changes in place
	quarantined = nil
	out2, _ := a.Apply(batch[:2])
	for _, o := range out2 {
		if !o.Applied || o.Reason != "already in place" {
			t.Errorf("resume %s: %+v", o.Path, o)
		}
	}
}

func TestFingerprint(t *testing.T) {
	if fp("a") == Fingerprint("file", []byte("a"), true, "") || Fingerprint("link", nil, false, "x") != "link:x" {
		t.Error("fingerprints must distinguish the exec bit and links")
	}
}
