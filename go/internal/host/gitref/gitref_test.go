package gitref

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// git runs git in dir with no user or system configuration.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.org", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.org",
		"GIT_AUTHOR_DATE=1700000000 +0000", "GIT_COMMITTER_DATE=1700000000 +0000")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func needGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
}

func repo(t *testing.T, extra ...string) string {
	d := filepath.Join(t.TempDir(), "r")
	git(t, filepath.Dir(d), append([]string{"init", "-q", "--template=", "-b", "main"}, append(extra, d)...)...)
	os.WriteFile(filepath.Join(d, "a"), []byte("a"), 0o644)
	git(t, d, "add", "a")
	git(t, d, "commit", "-q", "-m", "one")
	return d
}

func commit(t *testing.T, d, msg string) {
	os.WriteFile(filepath.Join(d, "a"), []byte(msg), 0o644)
	git(t, d, "commit", "-q", "-am", msg)
}

func head(t *testing.T, dir string) (string, error) {
	t.Helper()
	r, err := Open(dir)
	if err != nil {
		return "", err
	}
	return r.Head()
}

func TestHeadMatchesGit(t *testing.T) {
	needGit(t)
	cases := map[string]func(t *testing.T) string{
		"loose branch": func(t *testing.T) string { return repo(t) },
		"packed only": func(t *testing.T) string {
			d := repo(t)
			git(t, d, "pack-refs", "--all")
			return d
		},
		"loose newer than packed": func(t *testing.T) string {
			d := repo(t)
			git(t, d, "pack-refs", "--all")
			commit(t, d, "two")
			return d
		},
		"detached": func(t *testing.T) string {
			d := repo(t)
			commit(t, d, "two")
			git(t, d, "checkout", "-q", "--detach", "HEAD~1")
			return d
		},
		"symbolic chain": func(t *testing.T) string {
			d := repo(t)
			git(t, d, "symbolic-ref", "refs/heads/alias", "refs/heads/main")
			git(t, d, "symbolic-ref", "HEAD", "refs/heads/alias")
			return d
		},
		"linked worktree": func(t *testing.T) string {
			d := repo(t)
			wt := filepath.Join(filepath.Dir(d), "wt")
			git(t, d, "worktree", "add", "-q", "-b", "side", wt)
			commit(t, wt, "side")
			return wt
		},
		"separate git dir": func(t *testing.T) string {
			d := filepath.Join(t.TempDir(), "w")
			git(t, filepath.Dir(d), "init", "-q", "--template=", "-b", "main", "--separate-git-dir", filepath.Join(filepath.Dir(d), "store.git"), d)
			os.WriteFile(filepath.Join(d, "a"), []byte("x"), 0o644)
			git(t, d, "add", "a")
			git(t, d, "commit", "-q", "-m", "x")
			return d
		},
		"sha256": func(t *testing.T) string { return repo(t, "--object-format=sha256") },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			d := mk(t)
			want := git(t, d, "rev-parse", "HEAD")
			got, err := head(t, d)
			if err != nil || got != want {
				t.Fatalf("Head = %q, %v; git says %q", got, err, want)
			}
		})
	}
}

func TestHeadRefusals(t *testing.T) {
	needGit(t)
	unborn := filepath.Join(t.TempDir(), "u")
	git(t, filepath.Dir(unborn), "init", "-q", "--template=", "-b", "main", unborn)
	if _, err := head(t, unborn); err == nil {
		t.Error("unborn branch: no error")
	}
	if _, err := head(t, t.TempDir()); err == nil {
		t.Error("not a repository: no error")
	}
	bad := func(name string, mutate func(d string)) {
		d := repo(t)
		mutate(d)
		if got, err := head(t, d); err == nil {
			t.Errorf("%s: Head = %q, want an error", name, got)
		}
	}
	bad("HEAD outside refs", func(d string) { os.WriteFile(filepath.Join(d, ".git/HEAD"), []byte("ref: ../../etc/passwd\n"), 0o644) })
	bad("ref with dotdot", func(d string) { os.WriteFile(filepath.Join(d, ".git/HEAD"), []byte("ref: refs/heads/../../x\n"), 0o644) })
	bad("short hash", func(d string) { os.WriteFile(filepath.Join(d, ".git/HEAD"), []byte("abc\n"), 0o644) })
	bad("uppercase hash", func(d string) {
		h := git(t, d, "rev-parse", "HEAD")
		os.WriteFile(filepath.Join(d, ".git/HEAD"), []byte(strings.ToUpper(h)+"\n"), 0o644)
	})
	bad("self loop", func(d string) {
		os.WriteFile(filepath.Join(d, ".git/refs/heads/main"), []byte("ref: refs/heads/main\n"), 0o644)
	})
	bad("huge HEAD", func(d string) { os.WriteFile(filepath.Join(d, ".git/HEAD"), []byte(strings.Repeat("x", maxSmall+1)), 0o644) })
	bad("unknown object format", func(d string) {
		f, _ := os.OpenFile(filepath.Join(d, ".git/config"), os.O_APPEND|os.O_WRONLY, 0)
		f.WriteString("[extensions]\n\tobjectFormat = sha512\n")
		f.Close()
	})
	if runtime.GOOS != "windows" {
		bad("HEAD symlink", func(d string) {
			os.Rename(filepath.Join(d, ".git/HEAD"), filepath.Join(d, "realhead"))
			os.Symlink(filepath.Join(d, "realhead"), filepath.Join(d, ".git/HEAD"))
		})
		bad("ref symlink", func(d string) {
			p := filepath.Join(d, ".git/refs/heads/main")
			os.Rename(p, filepath.Join(d, "realref"))
			os.Symlink(filepath.Join(d, "realref"), p)
		})
		bad(".git symlink", func(d string) {
			os.Rename(filepath.Join(d, ".git"), filepath.Join(d, "real.git"))
			os.Symlink(filepath.Join(d, "real.git"), filepath.Join(d, ".git"))
		})
	}
}

func tagBody(commit, name string) []byte {
	return []byte(TagHeader(commit, name) + "Op <op@example.org> 1700000000 +0000\n\nvetted\n")
}

func TestWriteTagMatchesGit(t *testing.T) {
	needGit(t)
	for _, format := range []string{"sha1", "sha256"} {
		t.Run(format, func(t *testing.T) {
			d := repo(t, "--object-format="+format)
			r, err := Open(d)
			if err != nil {
				t.Fatal(err)
			}
			c, _ := r.Head()
			name := "agent-vetted/" + c
			body := tagBody(c, name)
			id, err := r.WriteTag(body, name, c)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("git", "hash-object", "-t", "tag", "--stdin")
			cmd.Dir = d
			cmd.Stdin = strings.NewReader(string(body))
			want, _ := cmd.Output()
			if id != strings.TrimSpace(string(want)) {
				t.Errorf("id %s, git hash-object says %s", id, want)
			}
			if got := git(t, d, "rev-parse", "refs/tags/"+name); got != id {
				t.Errorf("ref -> %s", got)
			}
			if got := git(t, d, "cat-file", "-p", id); got+"\n" != string(body) {
				t.Errorf("cat-file %q", got)
			}
			if got := git(t, d, "rev-parse", "refs/tags/"+name+"^{commit}"); got != c {
				t.Errorf("peels to %s", got)
			}
			git(t, d, "fsck", "--strict", "--no-dangling")
			// writing again is a no-op; a different tag under the same name is refused
			if id2, err := r.WriteTag(body, name, c); err != nil || id2 != id {
				t.Errorf("rewrite: %s %v", id2, err)
			}
			other := append(append([]byte{}, body...), []byte("more\n")...)
			if _, err := r.WriteTag(other, name, c); err == nil {
				t.Error("an existing tag ref was overwritten")
			}
		})
	}
}

func TestWriteTagRefusals(t *testing.T) {
	needGit(t)
	d := repo(t)
	r, _ := Open(d)
	c, _ := r.Head()
	name := "agent-vetted/" + c
	if _, err := r.WriteTag(tagBody(c, name), "agent-vetted/../x", c); err == nil {
		t.Error("dotdot tag name accepted")
	}
	if _, err := r.WriteTag(tagBody(c, "other"), name, c); err == nil {
		t.Error("a tag naming another tag accepted")
	}
	if _, err := r.WriteTag(tagBody(strings.Repeat("0", 40), name), name, c); err == nil {
		t.Error("a tag naming another commit accepted")
	}
	// a packed tag of the same name pointing elsewhere is not overwritten
	git(t, d, "tag", "-a", "-m", "x", name)
	git(t, d, "pack-refs", "--all")
	if _, err := r.WriteTag(tagBody(c, name), name, c); err == nil {
		t.Error("a packed tag ref was shadowed")
	}
	if runtime.GOOS != "windows" {
		d2 := repo(t)
		r2, _ := Open(d2)
		c2, _ := r2.Head()
		os.MkdirAll(filepath.Join(d2, "elsewhere"), 0o755)
		os.Symlink(filepath.Join(d2, "elsewhere"), filepath.Join(d2, ".git/refs/tags/agent-vetted"))
		if _, err := r2.WriteTag(tagBody(c2, "agent-vetted/"+c2), "agent-vetted/"+c2, c2); err == nil {
			t.Error("wrote through a symlinked refs directory")
		}
	}
}
