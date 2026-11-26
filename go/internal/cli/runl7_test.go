package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// TestL7Rules: the overlay's rules, then the operator's, each kept only for hosts the session's
// allowlist reaches; a file that does not parse stops the run.
func TestL7Rules(t *testing.T) {
	home, ov := t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(home, ".sandbox"), 0o700)
	os.WriteFile(filepath.Join(ov, EgressRulesFile), []byte("# org\nrules:\n"+
		`  - {"host": "*", "methods": ["DELETE"], "action": "deny"}`+"\n"+
		`  - {"host": "registry.corp.example", "methods": ["PUT"], "action": "deny"}`+"\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".sandbox", EgressRulesFile), []byte("rules:\n"+
		`  - {"host": "api.github.com", "methods": ["GET"], "path_patterns": ["/repos/**"], "action": "allow"}`+"\n"+
		`  - {"host": "*.example.org", "methods": ["POST"], "action": "deny"}`+"\n"+
		`  - {"host": "elsewhere.io", "action": "deny"}`+"\n"), 0o644)
	c := &cmdCtx{env: Env{Env: config.Env{Home: home, SandboxOverlay: ov}}, stdout: io.Discard, stderr: io.Discard}
	spec := &sessionspec.Spec{Egress: sessionspec.Egress{Allow: []string{"api.github.com", "*.example.org"}}}
	lines := c.l7Rules(spec)
	want := []string{"==> L7 rules (overlay): 1; left out for hosts not on this session's allowlist: registry.corp.example",
		"==> L7 rules (operator): 2; left out for hosts not on this session's allowlist: elsewhere.io"}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("lines\n%s", strings.Join(lines, "\n"))
	}
	var hosts []string
	for _, r := range spec.Egress.L7 {
		hosts = append(hosts, r.Host+" "+r.Action)
	}
	if strings.Join(hosts, ",") != "* deny,api.github.com allow,*.example.org deny" {
		t.Errorf("rules %q", hosts)
	}
	// none: nothing said
	if l := (&cmdCtx{env: Env{Env: config.Env{Home: t.TempDir()}}}).l7Rules(&sessionspec.Spec{}); len(l) != 0 {
		t.Errorf("%q", l)
	}
	// an allow rule on every host, or a malformed line: the run stops
	for _, bad := range []string{`  - {"host": "*", "action": "allow"}`, `  - {"host": "x.io", "action": "deny", "extra": 1}`, "rules: [x]"} {
		os.WriteFile(filepath.Join(home, ".sandbox", EgressRulesFile), []byte("rules:\n"+bad+"\n"), 0o644)
		if rc := runDie(func() { c.l7Rules(&sessionspec.Spec{}) }); rc != 1 {
			t.Errorf("%q accepted", bad)
		}
	}
}

// runDie runs f, which may die, and returns the status it died with (0 if it returned).
func runDie(f func()) (status int) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(exit); ok {
				status = int(e)
				return
			}
			panic(r)
		}
	}()
	f()
	return 0
}

// TestRegistryWarnings: an intercepted registry-like host with no write deny of its own is named;
// the baseline's public registries and hosts with a rule are not.
func TestRegistryWarnings(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "config"), 0o755)
	base, _ := os.ReadFile(filepath.Join("..", "..", "..", "config", "egress-baseline.yaml"))
	os.WriteFile(filepath.Join(root, "config", "egress-baseline.yaml"), base, 0o644)
	c := &cmdCtx{env: Env{SandboxRoot: root}}
	spec := &sessionspec.Spec{
		Egress: sessionspec.Egress{L7: []sessionspec.L7Rule{
			{Host: "npm.corp.example", Methods: []string{"GET"}, Action: "allow"},
			{Host: "nexus.corp.example", Methods: []string{"PUT", "DELETE"}, Action: "deny"},
			{Host: "*.artifactory.example", Methods: []string{"DELETE"}, Action: "deny"},
			{Host: "*", Methods: []string{"PUT"}, Action: "deny"},
		}},
		Bindings: []sessionspec.Binding{{Hosts: []string{"registry.npmjs.org", "api.github.com", "x.artifactory.example"}}},
	}
	got := strings.Join(c.registryWarnings(spec), "\n")
	if !strings.Contains(got, "WARNING: npm.corp.example looks like") || !strings.Contains(got, "WARNING: x.artifactory.example looks like") ||
		strings.Contains(got, "nexus.corp") || strings.Contains(got, "registry.npmjs.org") || strings.Contains(got, "api.github.com") ||
		strings.Count(got, "WARNING") != 2 {
		t.Errorf("%s", got)
	}
}
