package syncgate

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidBranchMatchesGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	names := []string{"main", "feature/x", "a.b", "a..b", ".hidden", "x/.y", "x.lock", "x/y.lock", "a@{b", "@", "a@b",
		"trailing/", "dot.", "sp ace", "ti~lde", "ca^ret", "co:lon", "q?", "st*r", "br[ack", "back\\slash", "café",
		"a//b", "-dash", "HEAD", "a/HEAD", "x\x7fy", "tab\tx", "ok-name_1.2", "a/b/c/d"}
	for _, n := range names {
		cmd := exec.Command("git", "check-ref-format", "--branch", n)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
		gitOK := cmd.Run() == nil
		// check-ref-format --branch accepts a leading dash where a full ref would not; the gate is
		// stricter there and that is fine. It must never accept what git refuses.
		if ValidBranch("refs/heads/"+n) && !gitOK {
			t.Errorf("%q: accepted, git refuses it", n)
		}
		// (git check-ref-format --branch expands "@" to the current branch; as a name it is refused)
		if !ValidBranch("refs/heads/"+n) && gitOK && n != "HEAD" && n != "a//b" && n != "@" {
			t.Errorf("%q: refused, git accepts it", n)
		}
	}
}

func TestParsePackedRefsFromGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	d := filepath.Join(t.TempDir(), "r")
	gitIn(t, filepath.Dir(d), "init", "-q", "--template=", "-b", "main", d)
	os.WriteFile(filepath.Join(d, "a"), []byte("a"), 0o644)
	gitIn(t, d, "add", "a")
	gitIn(t, d, "commit", "-q", "-m", "a")
	gitIn(t, d, "branch", "feature/x")
	gitIn(t, d, "tag", "-a", "-m", "t", "v1")
	gitIn(t, d, "pack-refs", "--all")
	b, _ := os.ReadFile(filepath.Join(d, ".git", "packed-refs"))
	refs, err := ParsePackedRefs(b, 20)
	if err != nil {
		t.Fatal(err)
	}
	head := strings.TrimSpace(gitIn(t, d, "rev-parse", "HEAD"))
	if refs["refs/heads/main"] != head || refs["refs/heads/feature/x"] != head || refs["refs/tags/v1"] == "" || len(refs) != 3 {
		t.Errorf("%v", refs)
	}
	for _, bad := range []string{"xyz refs/heads/a\n", "^" + head + "\n", head + " refs/heads/a\n" + head + " refs/heads/a\n", head + " heads/a\n", head + "  refs/heads/a\n"} {
		if _, err := ParsePackedRefs([]byte(bad), 20); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// graph is a fake object store: id -> parents.
type graph map[string][]string

func (g graph) Has(id string) bool { _, ok := g[id]; return ok }
func (g graph) Parents(id string) ([]string, error) {
	if p, ok := g[id]; ok {
		return p, nil
	}
	return nil, errors.New("missing")
}
func (g graph) IsAncestor(old, new string) (bool, error) {
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(c string) bool {
		if c == old {
			return true
		}
		if seen[c] {
			return false
		}
		seen[c] = true
		for _, p := range g[c] {
			if walk(p) {
				return true
			}
		}
		return false
	}
	return walk(new), nil
}

func sha(c byte) string { return strings.Repeat(string(c), 40) }

func TestDecideRefs(t *testing.T) {
	// a <- b <- c ; a <- x (a side line)
	g := graph{sha('a'): nil, sha('b'): {sha('a')}, sha('c'): {sha('b')}, sha('x'): {sha('a')}}
	base := Refs{"refs/heads/main": sha('a'), "refs/heads/ff": sha('a'), "refs/heads/rewind": sha('b'), "refs/heads/both": sha('a'),
		"refs/heads/gone": sha('a'), "refs/heads/dev": sha('a')}
	host := Refs{"refs/heads/main": sha('a'), "refs/heads/ff": sha('a'), "refs/heads/rewind": sha('b'), "refs/heads/both": sha('b'),
		"refs/heads/gone": sha('a'), "refs/heads/dev": sha('a')}
	vm := Refs{"refs/heads/main": sha('c'), "refs/heads/ff": sha('c'), "refs/heads/rewind": sha('a'), "refs/heads/both": sha('c'),
		"refs/heads/dev": sha('x'), "refs/heads/new": sha('b'), "refs/heads/ghost": sha('z'), "refs/heads/bad..name": sha('b'),
		"refs/heads/MAIN": sha('c'), "refs/heads/release": sha('c'), "refs/tags/v1": sha('c')}
	prot := Protected("ref: refs/remotes/origin/trunk\n", []string{"release"})
	got := map[string]string{}
	for _, d := range DecideRefs(base, host, vm, prot, Host{CaseInsensitive: true, NormInsensitive: true}, g) {
		v := "quarantine: " + d.Reason
		if d.Apply {
			v = "apply: " + d.Reason
		}
		got[d.Ref] = v
	}
	want := map[string]string{
		"refs/heads/main":      "quarantine: protected branch",
		"refs/heads/MAIN":      "quarantine: names the host branch refs/heads/main in another spelling",
		"refs/heads/release":   "quarantine: protected branch",
		"refs/heads/ff":        "apply: fast-forward",
		"refs/heads/rewind":    "quarantine: not a fast-forward",
		"refs/heads/both":      "quarantine: changed on the host and in the VM since the last sync",
		"refs/heads/gone":      "quarantine: branch deletion",
		"refs/heads/dev":       "apply: fast-forward", // a to x, whose parent is a
		"refs/heads/new":       "apply: new branch",
		"refs/heads/ghost":     "quarantine: commit " + sha('z') + " is not in the host object store",
		"refs/heads/bad..name": "quarantine: invalid branch name",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["refs/tags/v1"]; ok || len(got) != len(want) {
		t.Errorf("unexpected decisions: %v", got)
	}
	if p := Protected("", nil); len(p) != 2 {
		t.Errorf("default protected %v", p)
	}
}

func TestDecideHead(t *testing.T) {
	g := graph{sha('a'): nil, sha('b'): {sha('a')}}
	after := Refs{"refs/heads/main": sha('a'), "refs/heads/feature": sha('b')}
	ok := func(base, host, vm, want string) {
		t.Helper()
		got, err := DecideHead(base, host, vm, after, Host{}, g, 20)
		if err != nil || got != want {
			t.Errorf("HEAD %q: %q %v, want %q", vm, got, err, want)
		}
	}
	bad := func(base, host, vm string) {
		t.Helper()
		if got, err := DecideHead(base, host, vm, after, Host{}, g, 20); err == nil {
			t.Errorf("HEAD %q accepted as %q", vm, got)
		}
	}
	m := "ref: refs/heads/main\n"
	ok(m, m, m, "")
	ok(m, m, "ref: refs/heads/feature\n", "ref: refs/heads/feature\n")
	ok(m, m, sha('b')+"\n", sha('b')+"\n")
	bad(m, "ref: refs/heads/feature\n", sha('b')+"\n")           // both sides moved
	bad(m, m, "ref: refs/heads/nope\n")                          // no such branch
	bad(m, m, "ref: refs/tags/v1\n")                             // not a branch
	bad(m, m, "ref: refs/heads/../../config\n")                  // traversal
	bad(m, m, "ref: refs/heads/main\nref: refs/heads/feature\n") // extra line
	bad(m, m, sha('z')+"\n")                                     // unknown commit
	bad(m, m, "garbage")
}
