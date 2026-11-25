package gitobj

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func git(t *testing.T, dir string, args ...string) string {
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

// history builds a repository with branching history whose file contents compress well as
// deltas, then packs most of it and leaves a few objects loose.
func history(t *testing.T, format string) string {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	d := filepath.Join(t.TempDir(), "r")
	git(t, filepath.Dir(d), "init", "-q", "--template=", "-b", "main", "--object-format="+format, d)
	var text strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&text, "line %d of a file that changes a little each commit\n", i)
	}
	for i := 0; i < 30; i++ {
		s := strings.Replace(text.String(), fmt.Sprintf("line %d ", i*7), fmt.Sprintf("LINE %d ", i), 1)
		os.WriteFile(filepath.Join(d, "big.txt"), []byte(s), 0o644)
		os.WriteFile(filepath.Join(d, fmt.Sprintf("f%d", i%5)), []byte(fmt.Sprint(i)), 0o644)
		git(t, d, "add", "-A")
		git(t, d, "commit", "-q", "-m", fmt.Sprint("c", i))
		if i == 10 {
			git(t, d, "branch", "side")
		}
	}
	git(t, d, "checkout", "-q", "side")
	os.WriteFile(filepath.Join(d, "side.txt"), []byte("side"), 0o644)
	git(t, d, "add", "-A")
	git(t, d, "commit", "-q", "-m", "side")
	git(t, d, "checkout", "-q", "main")
	git(t, d, "merge", "-q", "--no-edit", "side")
	git(t, d, "repack", "-a", "-d", "-q", "--depth=50", "--window=50")
	os.WriteFile(filepath.Join(d, "loose.txt"), []byte("loose"), 0o644)
	git(t, d, "add", "-A")
	git(t, d, "commit", "-q", "-m", "loose")
	return d
}

func TestStoreMatchesGit(t *testing.T) {
	for format, idLen := range map[string]int{"sha1": 20, "sha256": 32} {
		t.Run(format, func(t *testing.T) {
			d := history(t, format)
			s, err := Open(filepath.Join(d, ".git", "objects"), idLen)
			if err != nil {
				t.Fatal(err)
			}
			// every object git knows, compared byte for byte
			ids := strings.Fields(git(t, d, "cat-file", "--batch-all-objects", "--batch-check=%(objectname)"))
			cmd := exec.Command("git", "cat-file", "--batch")
			cmd.Dir = d
			cmd.Stdin = strings.NewReader(strings.Join(ids, "\n") + "\n")
			out, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			r := bufio.NewReader(bytes.NewReader(out))
			deltas := 0 // objects stored as deltas: verify-pack -v gives them a depth and a base
			for _, l := range strings.Split(git(t, d, "verify-pack", "-v", mustGlob(t, filepath.Join(d, ".git/objects/pack/*.idx"))), "\n") {
				if len(strings.Fields(l)) == 7 {
					deltas++
				}
			}
			for _, id := range ids {
				hdr, _ := r.ReadString('\n')
				f := strings.Fields(hdr)
				n, _ := strconv.Atoi(f[2])
				body := make([]byte, n)
				if _, err := io_ReadFull(r, body); err != nil {
					t.Fatal(err)
				}
				r.ReadByte()
				kind, got, err := s.Read(id)
				if err != nil || kind != f[1] || !bytes.Equal(got, body) {
					t.Fatalf("%s: %s %v, git says %s", id, kind, err, f[1])
				}
				if !s.Has(id) {
					t.Errorf("Has(%s) false", id)
				}
			}
			if deltas == 0 {
				t.Error("the fixture has no deltas; the test proves less than it claims")
			}
			t.Logf("%d objects, %d stored as deltas", len(ids), deltas)
			// ancestry, against git merge-base --is-ancestor
			revs := strings.Fields(git(t, d, "rev-list", "--all"))
			for _, a := range []string{revs[0], revs[5], revs[len(revs)-1], strings.TrimSpace(git(t, d, "rev-parse", "side"))} {
				for _, b := range []string{revs[0], revs[3], strings.TrimSpace(git(t, d, "rev-parse", "side~0")), revs[len(revs)-1]} {
					got, err := s.IsAncestor(a, b)
					cmd := exec.Command("git", "merge-base", "--is-ancestor", a, b)
					cmd.Dir = d
					want := cmd.Run() == nil
					if err != nil || got != want {
						t.Errorf("IsAncestor(%s, %s) = %v %v, git says %v", a[:8], b[:8], got, err, want)
					}
				}
			}
			// VerifyPack accepts git's own pack
			idx := mustGlob(t, filepath.Join(d, ".git/objects/pack/*.idx"))
			ib, _ := os.ReadFile(idx)
			pb, _ := os.ReadFile(strings.TrimSuffix(idx, ".idx") + ".pack")
			if got, err := VerifyPack(pb, ib, idLen); err != nil || len(got) == 0 {
				t.Fatalf("VerifyPack: %v", err)
			}
		})
	}
}

func io_ReadFull(r *bufio.Reader, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := r.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func mustGlob(t *testing.T, p string) string {
	m, _ := filepath.Glob(p)
	if len(m) != 1 {
		t.Fatalf("%s: %v", p, m)
	}
	return m[0]
}

func zlibOf(b []byte) []byte {
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write(b)
	w.Close()
	return z.Bytes()
}

func TestVerifyLoose(t *testing.T) {
	body := []byte("hello\n")
	id := ID("blob", body, 20)
	if id != "ce013625030ba8dba906f756967f9e9ca394464a" {
		t.Fatalf("ID %s", id)
	}
	good := zlibOf(append([]byte("blob 6\x00"), body...))
	if k, err := VerifyLoose(good, id, 20); err != nil || k != "blob" {
		t.Fatal(k, err)
	}
	for name, raw := range map[string][]byte{
		"other id":     good,
		"bad size":     zlibOf([]byte("blob 7\x00hello\n")),
		"leading zero": zlibOf([]byte("blob 06\x00hello\n")),
		"unknown kind": zlibOf([]byte("evil 6\x00hello\n")),
		"no header":    zlibOf([]byte("hello")),
		"not zlib":     []byte("hello"),
		"truncated":    good[:len(good)-3],
	} {
		want := id
		if name == "other id" {
			want = strings.Repeat("0", 40)
		}
		if _, err := VerifyLoose(raw, want, 20); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVerifyPackRefusals(t *testing.T) {
	d := history(t, "sha1")
	idx := mustGlob(t, filepath.Join(d, ".git/objects/pack/*.idx"))
	ib, _ := os.ReadFile(idx)
	pb, _ := os.ReadFile(strings.TrimSuffix(idx, ".idx") + ".pack")
	bad := func(name string, p, i []byte) {
		if _, err := VerifyPack(p, i, 20); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	flip := func(b []byte, at int) []byte { c := append([]byte(nil), b...); c[at] ^= 1; return c }
	bad("pack byte flipped", flip(pb, len(pb)/2), ib)
	bad("index byte flipped", pb, flip(ib, len(ib)/2))
	bad("truncated pack", pb[:len(pb)-1], ib)
	bad("empty", nil, nil)
	// a pack whose checksums are right but whose index names a different id for an object:
	// re-seal the index after swapping two names, so only the hash check can catch it
	c := append([]byte(nil), ib...)
	o := 8 + 256*4
	copy(c[o:o+20], bytes.Repeat([]byte{0}, 20))
	h := hasher(20)
	h.Write(c[:len(c)-20])
	copy(c[len(c)-20:], h.Sum(nil))
	bad("index lies about an id", pb, c)
}
