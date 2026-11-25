package syncgate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestQuarantineStore(t *testing.T) {
	repo := t.TempDir()
	os.WriteFile(filepath.Join(repo, ".env"), []byte("REAL=1\n"), 0o600)
	os.WriteFile(filepath.Join(repo, "old.txt"), []byte("host edited it"), 0o600)
	s := &Store{Dir: filepath.Join(t.TempDir(), "quarantine"), Session: "ses-1", Now: func() time.Time { return time.Unix(1800000000, 0) }}
	a := &Applier{Repo: repo, Quarantine: func(c Change, why string) error { _, err := s.Put(repo, c, why); return err }}
	out, err := a.Apply([]Change{
		{Path: ".env", Data: []byte("REAL=1\nAGENT=2\n"), Base: fp("REAL=1\n")},
		{Path: ".vscode/settings.json", Data: []byte("{}"), Base: ""},
		{Path: "old.txt", Op: OpDelete, Base: fp("x")},
	})
	if err != nil || len(out) != 3 {
		t.Fatal(out, err)
	}
	held, err := s.List()
	if err != nil || len(held) != 3 {
		t.Fatalf("%v %v", held, err)
	}
	for _, h := range held {
		if h.Session != "ses-1" || h.Repo != repo || h.Reason == "" || !strings.HasPrefix(h.ID, "20270115T080000Z-") {
			t.Errorf("record %+v", h)
		}
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(filepath.Join(s.Dir))
		if st.Mode().Perm()&0o077 != 0 {
			t.Errorf("quarantine dir mode %v", st.Mode())
		}
	}
	var envID, vsID string
	for _, h := range held {
		switch h.Path {
		case ".env":
			envID = h.ID
		case ".vscode/settings.json":
			vsID = h.ID
		}
	}
	h, c, err := s.Get(envID)
	if err != nil || string(c.Data) != "REAL=1\nAGENT=2\n" {
		t.Fatal(h, c, err)
	}
	hostNow, _ := os.ReadFile(filepath.Join(repo, ".env"))
	if d := LineDiff(hostNow, c.Data); d != "  REAL=1\n+ AGENT=2\n" {
		t.Errorf("diff %q", d)
	}
	// the operator approves the .vscode change: it is written; then the record can be discarded
	_, vc, _ := s.Get(vsID)
	if err := a.ApplyApproved(vc); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(repo, ".vscode/settings.json")); string(b) != "{}" {
		t.Error("approved change not written")
	}
	if err := s.Discard(vsID); err != nil {
		t.Fatal(err)
	}
	if held, _ := s.List(); len(held) != 2 {
		t.Errorf("after discard: %d held", len(held))
	}
	// tampering with held content is noticed
	m, _ := filepath.Glob(filepath.Join(s.Dir, "*", envID, "content"))
	os.WriteFile(m[0], []byte("swapped"), 0o600)
	if _, _, err := s.Get(envID); err == nil {
		t.Error("tampered content accepted")
	}
	for _, bad := range []string{"../x", "20270115T080000Z-zzzzzzzz", ""} {
		if _, _, err := s.Get(bad); err == nil {
			t.Errorf("Get(%q) accepted", bad)
		}
	}
	// approval still never writes git state, escapes, or goes through a parent symlink
	for _, c := range []Change{{Path: ".git/hooks/x", Data: []byte("x")}, {Path: "a/.GIT/config", Data: []byte("x")},
		{Path: "l", Op: OpSymlink, Target: "../../x"}, {Path: "../x", Data: []byte("x")}} {
		if err := a.ApplyApproved(c); err == nil {
			t.Errorf("ApplyApproved(%q) accepted", c.Path)
		}
	}
}

func TestGitRefCommand(t *testing.T) {
	id := strings.Repeat("a", 40)
	cmd, ok := GitRefCommand(Held{Repo: "/r/it's", Path: ".git/refs/heads/main", Op: "write"}, []byte(id+"\n"))
	if !ok || cmd != `git -C '/r/it'\''s' update-ref refs/heads/main `+id {
		t.Errorf("%q %v", cmd, ok)
	}
	if _, ok := GitRefCommand(Held{Path: ".git/refs/heads/main", Op: "write"}, []byte("$(id)")); ok {
		t.Error("non-id accepted")
	}
	if _, ok := GitRefCommand(Held{Path: ".git/hooks/x", Op: "write"}, []byte(id)); ok {
		t.Error("non-ref accepted")
	}
}

func TestLineDiff(t *testing.T) {
	if d := LineDiff([]byte("a\nb\nc\n"), []byte("a\nx\nc\n")); d != "  a\n- b\n+ x\n  c\n" {
		t.Errorf("%q", d)
	}
	if d := LineDiff([]byte("a"), []byte("\x00\x01")); !strings.Contains(d, "binary") {
		t.Errorf("%q", d)
	}
}

func TestProbeHost(t *testing.T) {
	h := ProbeHost(t.TempDir())
	want := map[string]Host{"darwin": {CaseInsensitive: true, NormInsensitive: true}, "linux": {}}[runtime.GOOS]
	if (runtime.GOOS == "darwin" || runtime.GOOS == "linux") && h != want {
		t.Logf("probe found %+v (a case-sensitive APFS volume or an unusual Linux file system would differ)", h)
	}
	if ents, _ := os.ReadDir(t.TempDir()); len(ents) != 0 {
		t.Error("probe left a file")
	}
	t.Logf("%s: %+v", runtime.GOOS, h)
}

func TestRepoMaskedPaths(t *testing.T) {
	repo := t.TempDir()
	if got, err := RepoMaskedPaths(repo); err != nil || got != nil {
		t.Fatalf("missing config: %v %v", got, err)
	}
	os.MkdirAll(filepath.Join(repo, ".sandbox"), 0o755)
	os.WriteFile(filepath.Join(repo, ".sandbox/config.yaml"), []byte("vetting: required\nmasked_paths:\n  - secrets/\n  - \"conf/db.yml\" # db\n  - -n\nother:\n  - x\n"), 0o644)
	got, err := RepoMaskedPaths(repo)
	if err != nil || strings.Join(got, ",") != "secrets/,conf/db.yml,-n" {
		t.Fatalf("%q %v", got, err)
	}
	if runtime.GOOS != "windows" {
		os.Remove(filepath.Join(repo, ".sandbox/config.yaml"))
		os.Symlink("/etc/hosts", filepath.Join(repo, ".sandbox/config.yaml"))
		if _, err := RepoMaskedPaths(repo); err == nil {
			t.Error("a symlinked config was read")
		}
	}
}
