package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// TestLaunchUnbrokered (OQ-01): copilot and grok run with their own login in an agent home kept in
// the VM per tier, mounted writable at their own directory, with no credential binding; the launch
// warns that the agent holds the login and records it in the session's audit record. Grok's home is
// seeded from the operator's onboarded config, and the VM's warnings are shown.
func TestLaunchUnbrokered(t *testing.T) {
	type prepared struct {
		agent string
		tier  int
		seed  map[string][]byte
	}
	for _, c := range []struct {
		agent, target, account string
	}{{"copilot", "/home/agent/.copilot", "GitHub"}, {"grok", "/home/agent/.grok", "xAI"}} {
		e, fs, home := launchEnv(t)
		e.Launch.AgentImage = func(tag string) (string, error) {
			if tag != "sandbox:"+c.agent {
				return "", errors.New("not preloaded")
			}
			return "docker.io/library/sandbox" + testDigest, nil
		}
		e.CredentialPresent = func(string) bool { return false } // nothing in the broker
		var got []prepared
		e.Launch.PrepareAgentHome = func(agent string, tier int, seed map[string][]byte) ([]string, error) {
			got = append(got, prepared{agent, tier, seed})
			return []string{"a warning from the VM"}, nil
		}
		os.MkdirAll(filepath.Join(home, ".sandbox", "agent-config", "grok"), 0o700)
		os.WriteFile(filepath.Join(home, ".sandbox", "agent-config", "grok", "config.toml"), []byte("[ui]\n"), 0o600)
		var out, errb bytes.Buffer
		if rc := Run([]string{"run", "--agent", c.agent}, e, &out, &errb); rc != 0 {
			t.Fatalf("%s: %d\n%s\n%s", c.agent, rc, out.String(), errb.String())
		}
		sp := fs.started[0]
		if err := sp.Validate(sessionspec.Options{}); err != nil {
			t.Errorf("%s: sandboxd refuses it: %v", c.agent, err)
		}
		var mount *sessionspec.Mount
		for i, m := range sp.Mounts {
			if m.Kind == sessionspec.AgentHome {
				mount = &sp.Mounts[i]
			}
		}
		if mount == nil || mount.Source != sessionspec.AgentHomePath(c.agent, 1) || mount.Target != c.target || mount.ReadOnly {
			t.Errorf("%s: mount %+v", c.agent, mount)
		}
		if len(sp.Bindings) != 0 {
			t.Errorf("%s: bindings %+v", c.agent, sp.Bindings)
		}
		if len(got) != 1 || got[0].agent != c.agent || got[0].tier != 1 || (c.agent == "grok") != (string(got[0].seed["config.toml"]) == "[ui]\n") {
			t.Errorf("%s: prepared %+v", c.agent, got)
		}
		if !strings.Contains(errb.String(), c.agent+"'s "+c.account+" login cannot be brokered: the agent holds it") || !strings.Contains(errb.String(), "a warning from the VM") {
			t.Errorf("%s: %s", c.agent, errb.String())
		}
		if !strings.Contains(out.String(), "==> "+c.agent+": not brokered (OQ-01)") {
			t.Errorf("%s: %s", c.agent, out.String())
		}
		if ev, _ := os.ReadFile(filepath.Join(e.LogsDir, sp.ID, "session.json")); !strings.Contains(string(ev), "unbrokered-credential") {
			t.Errorf("%s: no audit event:\n%s", c.agent, ev)
		}
		if a := strings.Join(fs.attached[0], " "); !strings.HasPrefix(a, sp.ID+" "+c.agent) {
			t.Errorf("%s: attached %q", c.agent, a)
		}
	}
	// without the VM's agent homes the launch stops before anything starts
	e, fs, _ := launchEnv(t)
	e.Launch.AgentImage = func(string) (string, error) { return "docker.io/library/sandbox" + testDigest, nil }
	var errb bytes.Buffer
	if rc := Run([]string{"run", "--agent", "copilot"}, e, &bytes.Buffer{}, &errb); rc != 1 || len(fs.started) != 0 || !strings.Contains(errb.String(), "agent homes") {
		t.Errorf("no homes: %d %s", rc, errb.String())
	}
}
