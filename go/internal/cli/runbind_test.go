package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
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
