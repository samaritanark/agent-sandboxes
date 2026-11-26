package cli

import (
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
