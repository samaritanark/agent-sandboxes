package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// TestBindSecrets: each secret becomes what its sealed binding says, toward the hosts the session
// can reach, and run's lines say so; the rest are withheld with the reason.
func TestBindSecrets(t *testing.T) {
	bindings := map[string]brokerseal.Binding{
		"GH":     {Hosts: []string{"api.github.com", "uploads.github.com"}, Inject: "bearer"},
		"NPMRC":  {Readable: true},
		"OFF":    {Hosts: []string{"api.elsewhere.io"}, Inject: "basic"},
		"NONE":   {},
		"DEPTOK": {Hosts: []string{"pypi.org"}, Inject: "header:X-Token"},
		"DEPRD":  {Readable: true},
	}
	c := &cmdCtx{env: Env{SecretBinding: func(n string) (brokerseal.Binding, bool) {
		b, ok := bindings[n]
		return b, ok
	}}}
	spec := &sessionspec.Spec{Egress: sessionspec.Egress{Allow: []string{"api.github.com", "*.example.org"}},
		Env:          []sessionspec.EnvVar{{Name: "HOME", Value: "/home/agent"}},
		Dependencies: []sessionspec.Dependency{{Name: "db", Egress: sessionspec.Egress{Allow: []string{"pypi.org"}}}}}
	s := LaunchSpec{Secrets: []string{"GH", "NPMRC", "OFF", "NONE", "UNPUSHED"}}
	rec := SessionRecord{Dependencies: []Dependency{{Name: "db", Secrets: []string{"DEPTOK", "DEPRD"}}}}
	lines := c.bindSecrets(spec, s, rec)
	want := []string{
		"==> Secret GH: brokered to api.github.com (bearer); not to uploads.github.com (not on the allowlist)",
		"==> Secret NPMRC: readable by the agent ($NPMRC)",
		"==> Secret OFF: withheld (api.elsewhere.io not on this session's allowlist)",
		"==> Secret NONE: withheld (no binding; see 'sandbox secret bind NONE --bind HOST')",
		"==> Secret UNPUSHED: withheld (no binding; see 'sandbox secret bind UNPUSHED --bind HOST')",
		"==> Secret DEPTOK: brokered to pypi.org (header:X-Token)",
		"==> Secret DEPRD: withheld (a dependency cannot read a secret; bind it to hosts instead)",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("lines\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if len(spec.Bindings) != 1 || spec.Bindings[0].Ref != "secret.GH" || strings.Join(spec.Bindings[0].Hosts, ",") != "api.github.com" ||
		spec.Bindings[0].Inject != "bearer" || spec.Bindings[0].EnvVar != "GH" || !sessionspec.IsPlaceholder(spec.Bindings[0].Placeholder) {
		t.Errorf("bindings %+v", spec.Bindings)
	}
	if len(spec.Env) != 2 || spec.Env[1].Name != "GH" || spec.Env[1].Value != spec.Bindings[0].Placeholder {
		t.Errorf("env %+v", spec.Env)
	}
	if len(spec.Readable) != 1 || spec.Readable[0] != (sessionspec.Readable{Ref: "secret.NPMRC", EnvVar: "NPMRC"}) {
		t.Errorf("readable %+v", spec.Readable)
	}
	d := spec.Dependencies[0]
	if len(d.Bindings) != 1 || d.Bindings[0].Ref != "secret.DEPTOK" || len(d.Env) != 1 || d.Env[0].Value != d.Bindings[0].Placeholder ||
		d.Bindings[0].Placeholder == spec.Bindings[0].Placeholder {
		t.Errorf("dependency %+v", d)
	}
	// with no store to ask, every secret is withheld
	spec2 := &sessionspec.Spec{}
	if l := (&cmdCtx{}).bindSecrets(spec2, LaunchSpec{Secrets: []string{"GH"}}, SessionRecord{}); len(l) != 1 || !strings.Contains(l[0], "withheld") || len(spec2.Bindings) != 0 {
		t.Errorf("%q %+v", l, spec2)
	}
}

// TestBindInfraTokens: each infra token becomes a bearer binding to the endpoint hosts the host
// sealed it with, in its variable; one sealed with no hosts is withheld.
func TestBindInfraTokens(t *testing.T) {
	bound := map[string]brokerseal.Binding{
		"infra.INFRA_TOKEN_vault": {Hosts: []string{"vault.corp.example"}, Inject: "bearer"},
		"infra.INFRA_TOKEN":       {},
	}
	c := &cmdCtx{env: Env{CredentialBinding: func(ref string) (brokerseal.Binding, bool) { b, ok := bound[ref]; return b, ok }}}
	spec := &sessionspec.Spec{Egress: sessionspec.Egress{Allow: []string{"vault.corp.example"}}}
	lines := c.bindSecrets(spec, LaunchSpec{InfraTokens: []string{"INFRA_TOKEN_vault=/h/t", "INFRA_TOKEN=/h/p"}}, SessionRecord{})
	if strings.Join(lines, "\n") != "==> Secret INFRA_TOKEN_vault: brokered to vault.corp.example (bearer)\n==> Secret INFRA_TOKEN: withheld (no --infra-endpoint to bind it to)" {
		t.Errorf("%q", lines)
	}
	if len(spec.Bindings) != 1 || spec.Bindings[0].Ref != "infra.INFRA_TOKEN_vault" || spec.Bindings[0].EnvVar != "INFRA_TOKEN_vault" ||
		len(spec.Env) != 1 || spec.Env[0].Value != spec.Bindings[0].Placeholder {
		t.Errorf("%+v %+v", spec.Bindings, spec.Env)
	}
}

// TestBindOpencode: opencode gets v2's three variables, the key as a placeholder bound to the
// endpoint; without the host's binding or configuration the launch stops.
func TestBindOpencode(t *testing.T) {
	bound := map[string]brokerseal.Binding{OpencodeRef: {Hosts: []string{"vllm.corp.example"}, Inject: "bearer"}}
	env := Env{CredentialBinding: func(ref string) (brokerseal.Binding, bool) { b, ok := bound[ref]; return b, ok },
		Getenv: func(k string) string { return map[string]string{OpencodeConfigEnv: `{"provider":{}}`}[k] }}
	var out bytes.Buffer
	c := &cmdCtx{env: env, stdout: &out, stderr: io.Discard}
	spec := &sessionspec.Spec{Egress: sessionspec.Egress{Allow: []string{"vllm.corp.example"}}}
	c.bindOpencode(spec, LaunchSpec{Agent: "opencode", BaseURL: "https://VLLM.corp.example/v1"})
	if len(spec.Bindings) != 1 || spec.Bindings[0].Ref != OpencodeRef || spec.Bindings[0].EnvVar != "OPENAI_API_KEY" ||
		strings.Join(spec.Bindings[0].Hosts, ",") != "vllm.corp.example" {
		t.Fatalf("%+v", spec.Bindings)
	}
	var vars []string
	for _, e := range spec.Env {
		vars = append(vars, e.Name+"="+strings.Replace(e.Value, spec.Bindings[0].Placeholder, "PH", 1))
	}
	if strings.Join(vars, " ") != `OPENAI_API_KEY=PH OPENCODE_CONFIG_CONTENT={"provider":{}} OPENAI_BASE_URL=https://VLLM.corp.example/v1` {
		t.Errorf("%q", vars)
	}
	if !strings.Contains(out.String(), "==> opencode: API key brokered to vllm.corp.example (bearer)") {
		t.Errorf("%q", out.String())
	}
	for name, e := range map[string]Env{
		"no binding": {Getenv: env.Getenv},
		"another host": {CredentialBinding: func(string) (brokerseal.Binding, bool) {
			return brokerseal.Binding{Hosts: []string{"x.example"}, Inject: "bearer"}, true
		}, Getenv: env.Getenv},
		"no config": {CredentialBinding: env.CredentialBinding},
	} {
		c := &cmdCtx{env: e, stdout: io.Discard, stderr: io.Discard}
		if rc := runDie(func() {
			c.bindOpencode(&sessionspec.Spec{Egress: spec.Egress}, LaunchSpec{Agent: "opencode", BaseURL: "https://vllm.corp.example/v1"})
		}); rc != 1 {
			t.Errorf("%s: launched", name)
		}
	}
	// the pre-pass names the endpoint
	be := bindingsHome(t)
	be.OpencodeBaseURL, be.OpencodeAPIKey = "https://vllm.corp.example/v1", ""
	if p, ok, _ := RunPrepass([]string{"--agent", "opencode"}, be); !ok || p.OpencodeBaseURL != "https://vllm.corp.example/v1" {
		t.Errorf("prepass %+v %v", p, ok)
	}
	// in the VM, run needs the key the host pushed, not the VM's environment
	be.CredentialPresent = func(string) bool { return false }
	be.OpencodeAPIKey = "set-in-the-vm"
	var errb bytes.Buffer
	if rc := Run([]string{"run", "--agent", "opencode"}, be, io.Discard, &errb); rc != 1 || !strings.Contains(errb.String(), "OPENCODE_API_KEY must be set") {
		t.Errorf("%d %q", rc, errb.String())
	}
}

// TestSetUpAgent: claude's binding, re-staged configuration (the operator's copy first), and
// history per tier and repository set; an agent with no adapter or not onboarded stops the launch.
func TestSetUpAgent(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".sandbox", "agent-config", "claude"), 0o700)
	os.WriteFile(filepath.Join(home, ".sandbox", "agent-config", "claude", "CLAUDE.md"), []byte("be brief"), 0o600)
	os.WriteFile(filepath.Join(home, ".sandbox", "agent-config", "claude", ".credentials.json"), []byte("{}"), 0o600)
	onboarded := Env{Env: config.Env{Home: home},
		CredentialPresent: func(ref string) bool { return ref == "agent.claude" },
		CredentialBinding: func(ref string) (brokerseal.Binding, bool) {
			return brokerseal.Binding{Hosts: []string{"api.anthropic.com"}, Inject: "bearer"}, ref == "agent.claude"
		}}
	mk := func(tier int, copies ...string) *sessionspec.Spec {
		sp := &sessionspec.Spec{Agent: "claude", Tier: tier, Egress: sessionspec.Egress{Allow: []string{"api.anthropic.com"}}}
		for _, cp := range copies {
			sp.Mounts = append(sp.Mounts, sessionspec.Mount{Kind: sessionspec.Workspace, Source: sessionspec.WorkspaceStore + "/" + cp, Target: "/workspace/" + cp})
		}
		return sp
	}
	c := &cmdCtx{env: onboarded, stdout: io.Discard, stderr: io.Discard}
	sp := mk(2, "0123456789abcdef")
	f := c.setUpAgent(sp, LaunchSpec{Agent: "claude"}, SessionRecord{ID: "ses-20261126-213445-5114"})
	if f == nil || f.HistoryKey != "0123456789abcdef" || string(f.Config["CLAUDE.md"]) != "be brief" || f.Config[".credentials.json"] != nil || f.Config[".claude.json"] == nil {
		t.Fatalf("%+v", f)
	}
	last := sp.Mounts[len(sp.Mounts)-1]
	if last.Kind != sessionspec.History || last.Source != sessionspec.AgentHistoryStore+"/claude/tier2/0123456789abcdef" {
		t.Errorf("%+v", last)
	}
	// two repositories: one key for the set, whatever their order
	a := c.setUpAgent(mk(3, "0123456789abcdef", "fedcba9876543210"), LaunchSpec{Agent: "claude"}, SessionRecord{ID: "ses-20261126-213445-5114"})
	b := c.setUpAgent(mk(3, "fedcba9876543210", "0123456789abcdef"), LaunchSpec{Agent: "claude"}, SessionRecord{ID: "ses-20261126-213445-5114"})
	if a.HistoryKey != b.HistoryKey || len(a.HistoryKey) != 32 || a.HistoryKey == "0123456789abcdef" {
		t.Errorf("%q %q", a.HistoryKey, b.HistoryKey)
	}
	if f := c.setUpAgent(mk(1, "0123456789abcdef"), LaunchSpec{Agent: "claude"}, SessionRecord{ID: "ses-20261126-213445-5114"}); f.HistoryKey != "" {
		t.Errorf("tier 1 kept history: %q", f.HistoryKey)
	}
	var errb bytes.Buffer
	nc := &cmdCtx{env: Env{CredentialPresent: func(string) bool { return false }, CredentialBinding: onboarded.CredentialBinding}, stdout: io.Discard, stderr: &errb}
	if rc := runDie(func() { nc.setUpAgent(mk(2, "0123456789abcdef"), LaunchSpec{Agent: "claude"}, SessionRecord{}) }); rc != 1 || !strings.Contains(errb.String(), "claude is not onboarded") {
		t.Errorf("not onboarded: %d %q", rc, errb.String())
	}
	if f := c.setUpAgent(mk(2), LaunchSpec{Agent: "opencode"}, SessionRecord{}); f != nil {
		t.Error("opencode staged")
	}
	for name, cc := range map[string]struct {
		env   Env
		agent string
	}{
		"codex":         {onboarded, "codex"},
		"not onboarded": {Env{CredentialPresent: func(string) bool { return false }}, "claude"},
		"no broker":     {Env{}, "claude"},
		"bound elsewhere": {Env{CredentialPresent: onboarded.CredentialPresent, CredentialBinding: func(string) (brokerseal.Binding, bool) {
			return brokerseal.Binding{Hosts: []string{"evil.example.com"}, Inject: "bearer"}, true
		}}, "claude"},
	} {
		c := &cmdCtx{env: cc.env, stdout: io.Discard, stderr: io.Discard}
		if rc := runDie(func() { c.setUpAgent(mk(2, "0123456789abcdef"), LaunchSpec{Agent: cc.agent}, SessionRecord{}) }); rc != 1 {
			t.Errorf("%s: launched", name)
		}
	}
}
