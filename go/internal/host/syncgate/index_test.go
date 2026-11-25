package syncgate

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.org", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.org")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// fixtureRepo builds a repository whose index exercises everything the parser must read.
func fixtureRepo(t *testing.T, format string) string {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	d := filepath.Join(t.TempDir(), "r")
	gitIn(t, filepath.Dir(d), "init", "-q", "--template=", "-b", "main", "--object-format="+format, d)
	w := func(p, c string, mode os.FileMode) {
		os.MkdirAll(filepath.Dir(filepath.Join(d, p)), 0o755)
		os.WriteFile(filepath.Join(d, p), []byte(c), mode)
	}
	w("a.txt", "a\n", 0o644)
	w("conflict.txt", "base\n", 0o644)
	w("dir/sub/deep name.txt", "x", 0o644)
	w("run.sh", "#!/bin/sh\n", 0o755)
	w("café.md", "c", 0o644)
	w(strings.Repeat("long/", 20)+"file", "l", 0o644)
	if runtime.GOOS != "windows" {
		os.Symlink("a.txt", filepath.Join(d, "link"))
	}
	gitIn(t, d, "add", "-A")
	gitIn(t, d, "commit", "-q", "-m", "base")
	head := strings.TrimSpace(gitIn(t, d, "rev-parse", "HEAD"))
	gitIn(t, d, "update-index", "--add", "--cacheinfo", "160000,"+head+",vendor/sub")
	gitIn(t, d, "checkout", "-q", "-b", "other")
	w("conflict.txt", "other\n", 0o644)
	gitIn(t, d, "commit", "-q", "-am", "other")
	gitIn(t, d, "checkout", "-q", "main")
	w("conflict.txt", "main\n", 0o644)
	gitIn(t, d, "commit", "-q", "-am", "main")
	cmd := exec.Command("git", "merge", "-q", "other")
	cmd.Dir = d
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@e", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@e")
	cmd.Run() // conflicts, as intended
	w("new.txt", "n", 0o644)
	gitIn(t, d, "add", "-N", "new.txt")
	gitIn(t, d, "update-index", "--skip-worktree", "a.txt")
	gitIn(t, d, "update-index", "--assume-unchanged", "run.sh")
	return d
}

// lsFiles is what git reports for the index: mode, id, stage, and path, one line each.
func lsFiles(t *testing.T, d string) string {
	return gitIn(t, d, "ls-files", "-s", "-z")
}

func render(es []Entry) string {
	var b strings.Builder
	for _, e := range es {
		fmt.Fprintf(&b, "%06o %s %d\t%s\x00", e.Mode, hex.EncodeToString(e.ID), e.Stage, e.Path)
	}
	return b.String()
}

func TestIndexAgainstGit(t *testing.T) {
	for _, format := range []string{"sha1", "sha256"} {
		for _, ver := range []string{"2", "3", "4"} {
			t.Run(format+"/v"+ver, func(t *testing.T) {
				d := fixtureRepo(t, format)
				gitIn(t, d, "update-index", "--index-version", ver)
				idLen := map[string]int{"sha1": 20, "sha256": 32}[format]
				raw, _ := os.ReadFile(filepath.Join(d, ".git", "index"))
				idx, err := ParseIndex(raw, idLen)
				if err != nil {
					t.Fatal(err)
				}
				want := ver
				if ver == "2" {
					want = "3" // git raises v2 to v3 when an entry needs extended flags
				}
				if fmt.Sprint(idx.Version) != want {
					t.Errorf("version %d, want %s", idx.Version, want)
				}
				if got := render(idx.Entries); got != lsFiles(t, d) {
					t.Fatalf("entries differ from git ls-files:\n got %q\nwant %q", got, lsFiles(t, d))
				}
				flags := map[string]string{}
				for _, e := range idx.Entries {
					if e.SkipWorktree || e.AssumeValid || e.IntentToAdd {
						flags[e.Path] = fmt.Sprint(e.SkipWorktree, e.AssumeValid, e.IntentToAdd)
					}
				}
				if flags["a.txt"] != "true false false" || flags["run.sh"] != "false true false" || flags["new.txt"] != "false false true" || len(flags) != 3 {
					t.Errorf("flags %v", flags)
				}
				// Round trip: git reads the gate's index with the same entries and no hiding flags.
				before := lsFiles(t, d)
				out, err := WriteIndex(idx.Entries, idLen)
				if err != nil {
					t.Fatal(err)
				}
				os.WriteFile(filepath.Join(d, ".git", "index"), out, 0o644)
				if got := lsFiles(t, d); got != before {
					t.Fatalf("git reads the rewritten index differently:\n got %q\nwant %q", got, before)
				}
				tags := gitIn(t, d, "ls-files", "-v")
				for _, l := range strings.Split(strings.TrimSpace(tags), "\n") {
					if l[0] == 'S' || l[0] >= 'a' && l[0] <= 'z' {
						t.Errorf("a hiding flag survived: %q", l)
					}
				}
				again, err := ParseIndex(out, idLen)
				if err != nil || render(again.Entries) != before {
					t.Fatalf("reparse: %v", err)
				}
				gitIn(t, d, "status", "--porcelain") // git is content to use it
			})
		}
	}
}

// sealed recomputes an index's checksum after a test edits its bytes.
func sealed(b []byte) []byte {
	body := b[:len(b)-20]
	s := sha1.Sum(body)
	return append(append([]byte(nil), body...), s[:]...)
}

func TestIndexRefusals(t *testing.T) {
	d := fixtureRepo(t, "sha1")
	gitIn(t, d, "update-index", "--index-version", "2", "--no-skip-worktree", "a.txt")
	gitIn(t, d, "rm", "-q", "--cached", "new.txt")
	good, _ := os.ReadFile(filepath.Join(d, ".git", "index"))
	if _, err := ParseIndex(good, 20); err != nil {
		t.Fatal(err)
	}
	mut := func(name string, f func(b []byte) []byte) {
		t.Helper()
		b := f(append([]byte(nil), good...))
		if _, err := ParseIndex(b, 20); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	firstName := 12 + 40 + 20 + 2
	mut("empty", func(b []byte) []byte { return nil })
	mut("truncated", func(b []byte) []byte { return b[:len(b)/2] })
	mut("bad checksum", func(b []byte) []byte { b[len(b)-1] ^= 1; return b })
	mut("signature", func(b []byte) []byte { b[0] = 'X'; return sealed(b) })
	mut("version 5", func(b []byte) []byte { b[7] = 5; return sealed(b) })
	mut("huge count", func(b []byte) []byte { binary.BigEndian.PutUint32(b[8:12], 1<<30); return sealed(b) })
	mut("count too high", func(b []byte) []byte {
		binary.BigEndian.PutUint32(b[8:12], binary.BigEndian.Uint32(b[8:12])+1)
		return sealed(b)
	})
	mut("bad mode", func(b []byte) []byte { binary.BigEndian.PutUint32(b[12+24:12+28], 0o100666); return sealed(b) })
	mut("dotdot name", func(b []byte) []byte { copy(b[firstName:], ".."); b[firstName+2] = '/'; return sealed(b) })
	mut("required extension", func(b []byte) []byte {
		body := b[:len(b)-20]
		body = append(body, []byte("link\x00\x00\x00\x00")...)
		return sealed(append(body, make([]byte, 20)...))
	})
	mut("extension overrun", func(b []byte) []byte {
		body := b[:len(b)-20]
		body = append(body, []byte("TREE\x00\x00\x10\x00")...)
		return sealed(append(body, make([]byte, 20)...))
	})
	mut("extended flags in v2", func(b []byte) []byte { b[firstName-2] |= 0x40; return sealed(b) })
	// an optional extension is skipped
	b := append([]byte(nil), good[:len(good)-20]...)
	b = append(b, []byte("ZZZZ\x00\x00\x00\x02ab")...)
	if _, err := ParseIndex(sealed(append(b, make([]byte, 20)...)), 20); err != nil {
		t.Errorf("optional extension: %v", err)
	}
	// .git in any case, and unsorted or duplicate entries, are refused by the writer's own checks too
	id := bytes.Repeat([]byte{1}, 20)
	for _, es := range [][]Entry{
		{{Path: ".GIT/config", Mode: 0o100644, ID: id}},
		{{Path: "a", Mode: 0o100644, ID: id}, {Path: "a", Mode: 0o100644, ID: id}},
		{{Path: "a", Mode: 0o100644, ID: id}, {Path: "a", Mode: 0o100644, ID: id, Stage: 2}},
		{{Path: "/abs", Mode: 0o100644, ID: id}},
		{{Path: "x", Mode: 0o040000, ID: id}},
	} {
		if _, err := WriteIndex(es, 20); err == nil {
			t.Errorf("WriteIndex(%v): accepted", es)
		}
	}
}

func FuzzParseIndex(f *testing.F) {
	if _, err := exec.LookPath("git"); err == nil {
		for _, v := range []string{"2", "4"} {
			d := t0(f)
			gitInF(f, d, "update-index", "--index-version", v)
			b, _ := os.ReadFile(filepath.Join(d, ".git", "index"))
			f.Add(b)
		}
	}
	f.Add([]byte("DIRC\x00\x00\x00\x02\x00\x00\x00\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, idLen := range []int{20, 32} {
			idx, err := ParseIndex(b, idLen)
			if err != nil {
				continue
			}
			out, err := WriteIndex(idx.Entries, idLen)
			if err != nil {
				t.Fatalf("a parsed index does not write: %v", err)
			}
			if again, err := ParseIndex(out, idLen); err != nil || len(again.Entries) != len(idx.Entries) {
				t.Fatalf("the written index does not parse back: %v", err)
			}
		}
	})
}

// t0 and gitInF build a small repository for the fuzz seeds.
func t0(f *testing.F) string {
	d := filepath.Join(f.TempDir(), "r")
	gitInF(f, filepath.Dir(d), "init", "-q", "--template=", d)
	os.WriteFile(filepath.Join(d, "a"), []byte("a"), 0o644)
	os.MkdirAll(filepath.Join(d, "b/c"), 0o755)
	os.WriteFile(filepath.Join(d, "b/c/d"), []byte("d"), 0o644)
	gitInF(f, d, "add", "-A")
	return d
}

func gitInF(f *testing.F, dir string, args ...string) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		f.Fatalf("git %v: %v %s", args, err, out)
	}
}
