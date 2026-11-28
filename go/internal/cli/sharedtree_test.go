package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/audit"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// TestSharedTrees (design 5.13, OQ-06): a launch that shares a repository with a running session
// of a different tier or allowlist warns and records an audit event, and the overlay's
// shared_tree_policy: deny refuses it; a session at the same tier and allowlist, a stopped one,
// and one on another repository are not reported.
func TestSharedTrees(t *testing.T) {
	home := t.TempDir()
	logs := filepath.Join(home, "logs")
	repo, other := "/home/u/code/app", "/home/u/code/lib"
	write := func(id, tier string, repos, domains []string) {
		d := filepath.Join(logs, id)
		os.MkdirAll(d, 0o755)
		if _, err := audit.WriteSessionJSON(d, audit.Session{ID: id, Agent: "claude", Tier: tier, Repos: repos, Domains: domains}); err != nil {
			t.Fatal(err)
		}
	}
	own := "ses-20261127-230000-0001"
	write(own, "3", []string{repo}, []string{"api.anthropic.com", "k8s.example.com"})
	write("ses-20261127-220000-0002", "2", []string{repo}, []string{"api.anthropic.com"})                      // lower tier: reported
	write("ses-20261127-220000-0003", "3", []string{repo}, []string{"k8s.example.com", "api.anthropic.com"})   // same tier and allowlist
	write("ses-20261127-220000-0004", "3", []string{repo}, []string{"api.anthropic.com", "other.example.com"}) // same tier, other allowlist
	write("ses-20261127-220000-0005", "1", []string{other}, nil)                                               // another repository
	write("ses-20261127-220000-0006", "1", []string{repo}, nil)                                                // not running
	write("ses-20261127-220000-0007", "2", []string{repo}, []string{"k8s.example.com", "api.anthropic.com"})   // other tier, same allowlist
	fs := &fakeSessions{}
	for _, id := range []string{own, "ses-20261127-220000-0002", "ses-20261127-220000-0003", "ses-20261127-220000-0004", "ses-20261127-220000-0005", "ses-20261127-220000-0007"} {
		fs.started = append(fs.started, &sessionspec.Spec{ID: id})
	}
	ov := filepath.Join(home, "overlay")
	os.MkdirAll(ov, 0o755)
	env := Env{Env: config.Env{Home: home, SandboxOverlay: ov}, LogsDir: logs, Launch: LaunchEnv{Sessions: fs}, Now: func() int64 { return 0 }}
	s := LaunchSpec{Tier: "3", Repos: []string{repo}}
	rec := SessionRecord{ID: own, LogDir: filepath.Join(logs, own)}

	var errb bytes.Buffer
	c := &cmdCtx{env: env, stdout: &bytes.Buffer{}, stderr: &errb}
	if rc := runDie(func() { c.checkSharedTrees(s, rec) }); rc != 0 {
		t.Fatalf("warn policy died: %s", errb.String())
	}
	got := errb.String()
	for _, want := range []string{"running session ses-20261127-220000-0002 (tier 2, a different allowlist)",
		"running session ses-20261127-220000-0004 (tier 3, a different allowlist)", "running session ses-20261127-220000-0007 (tier 2)",
		"share its working tree"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	for _, not := range []string{"0003", "0005", "0006"} {
		if strings.Contains(got, not) {
			t.Errorf("reported %s:\n%s", not, got)
		}
	}
	if ev, _ := os.ReadFile(filepath.Join(rec.LogDir, "session.json")); strings.Count(string(ev), "shared-tree") != 3 {
		t.Errorf("audit events:\n%s", ev)
	}

	os.WriteFile(filepath.Join(ov, "config.yaml"), []byte("shared_tree_policy: deny\n"), 0o644)
	errb.Reset()
	if rc := runDie(func() { c.checkSharedTrees(s, rec) }); rc != 1 || !strings.Contains(errb.String(), "shared_tree_policy: deny") {
		t.Errorf("deny policy: %d\n%s", rc, errb.String())
	}

	// no repository, or nothing else running: nothing to check
	errb.Reset()
	if runDie(func() { c.checkSharedTrees(LaunchSpec{Tier: "1"}, rec) }) != 0 || errb.Len() != 0 {
		t.Error("a session with no repository was checked")
	}
}
