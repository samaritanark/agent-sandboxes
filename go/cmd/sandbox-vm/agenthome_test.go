package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/agents"
)

// TestPrepareAgentHome (OQ-01): an unbrokered agent's home is made per tier, owned by the agent's
// user; a seed file is written only into a home without one; grok's privacy settings are added at
// every launch; a link where a file should be is refused, and no other agent gets a home.
func TestPrepareAgentHome(t *testing.T) {
	store := filepath.Join(t.TempDir(), "agent-home")
	uid := os.Getuid()
	prep := prepareAgentHome(store, uid)
	w, err := prep("copilot", 2, nil)
	home := filepath.Join(store, "copilot", "tier2")
	if st, serr := os.Lstat(home); err != nil || len(w) != 0 || serr != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Fatalf("copilot: %v %v %v", w, err, serr)
	}
	// grok: the operator's staged config seeds a new home, with the privacy settings added
	w, err = prep("grok", 3, map[string][]byte{"config.toml": []byte("[ui]\ntheme = \"dark\"\n")})
	gh := filepath.Join(store, "grok", "tier3")
	b, _ := os.ReadFile(filepath.Join(gh, "config.toml"))
	if err != nil || len(w) != 0 || !strings.HasPrefix(string(b), "[ui]\ntheme") || !strings.Contains(string(b), "disable_codebase_upload = true") {
		t.Fatalf("grok: %v %v\n%s", w, err, b)
	}
	// the agent's own changes stay; a seed never overwrites; settings it removed come back
	os.WriteFile(filepath.Join(gh, "config.toml"), []byte("[ui]\ntheme = \"light\"\n"), 0o600)
	w, err = prep("grok", 3, map[string][]byte{"config.toml": []byte("[ui]\ntheme = \"dark\"\n")})
	b, _ = os.ReadFile(filepath.Join(gh, "config.toml"))
	if err != nil || !strings.HasPrefix(string(b), "[ui]\ntheme = \"light\"") || !strings.Contains(string(b), agents.GrokPrivacyBlock) {
		t.Errorf("relaunch: %v %v\n%s", w, err, b)
	}
	// a setting turned off is warned about
	os.WriteFile(filepath.Join(gh, "config.toml"), []byte("[harness]\ndisable_codebase_upload = false\n"), 0o600)
	if w, err = prep("grok", 3, nil); err != nil || len(w) != 1 {
		t.Errorf("turned off: %v %v", w, err)
	}
	// a link in place of the file, or of the home, is refused
	os.Remove(filepath.Join(gh, "config.toml"))
	os.Symlink("/etc/passwd", filepath.Join(gh, "config.toml"))
	if _, err := prep("grok", 3, nil); err == nil {
		t.Error("a linked config.toml was followed")
	}
	os.RemoveAll(filepath.Join(store, "grok", "tier1"))
	os.Symlink(t.TempDir(), filepath.Join(store, "grok", "tier1"))
	if _, err := prep("grok", 1, nil); err == nil {
		t.Error("a linked home was used")
	}
	for _, c := range []struct {
		agent string
		tier  int
	}{{"claude", 2}, {"copilot", 0}, {"copilot", 4}} {
		if _, err := prep(c.agent, c.tier, nil); err == nil {
			t.Errorf("%s at tier %d got a home", c.agent, c.tier)
		}
	}
	if _, err := prep("copilot", 1, map[string][]byte{"..": nil}); err == nil {
		t.Error("a seed file outside the home was written")
	}
}
