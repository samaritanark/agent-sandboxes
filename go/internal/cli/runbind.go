package cli

// A launch's secrets as their bindings say (owner decision, 2026-11-26, ninth round): the host
// keeps each secret's binding beside it and seals it with the value; here the binding is read
// back from the broker store (unchecked: sandboxd's helper checks every use against the sealed
// binding) and turned into the spec. A bound secret is brokered: its variable holds a placeholder
// and the gateway injects the value toward the bound hosts. A readable one reaches the agent as a
// file and a variable. Any other is withheld, and run says which and why.

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// secretBinding is the binding the host sealed with a pushed secret; ok is false when the store
// has none for it (then it is withheld).
func (c *cmdCtx) secretBinding(name string) (brokerseal.Binding, bool) {
	if c.env.SecretBinding == nil {
		return brokerseal.Binding{}, false
	}
	return c.env.SecretBinding(name)
}

// placeholder is a new broker placeholder (sessionspec.PlaceholderPattern).
func placeholder() string {
	b := make([]byte, 32)
	rand.Read(b)
	return "sbxph_" + base64.RawURLEncoding.EncodeToString(b)
}

// bindSecrets adds the launch's secrets (the agent's, then each dependency's) to spec and returns
// one line per secret saying what became of it.
func (c *cmdCtx) bindSecrets(spec *sessionspec.Spec, s LaunchSpec, rec SessionRecord) []string {
	var lines []string
	add := func(name, what string) { lines = append(lines, fmt.Sprintf("==> Secret %s: %s", name, what)) }
	bindRef := func(name, ref string, b brokerseal.Binding, ok bool, egress sessionspec.Egress, readableOK bool) (*sessionspec.Binding, *sessionspec.Readable) {
		switch {
		case (!ok || (!b.Readable && len(b.Hosts) == 0)) && strings.HasPrefix(ref, "infra."):
			add(name, "withheld (no --infra-endpoint to bind it to)")
		case !ok || (!b.Readable && len(b.Hosts) == 0):
			add(name, fmt.Sprintf("withheld (no binding; see 'sandbox secret bind %s --bind HOST')", name))
		case b.Readable && !readableOK:
			add(name, "withheld (a dependency cannot read a secret; bind it to hosts instead)")
		case b.Readable:
			add(name, fmt.Sprintf("readable by the agent ($%s)", name))
			return nil, &sessionspec.Readable{Ref: ref, EnvVar: name}
		default:
			var hosts, off []string
			for _, h := range b.Hosts {
				if sessionspec.Reachable(h, egress) {
					hosts = append(hosts, h)
				} else {
					off = append(off, h)
				}
			}
			if len(hosts) == 0 {
				add(name, fmt.Sprintf("withheld (%s not on this session's allowlist)", strings.Join(off, ", ")))
				return nil, nil
			}
			what := fmt.Sprintf("brokered to %s (%s)", strings.Join(hosts, ", "), b.Inject)
			if len(off) > 0 {
				what += fmt.Sprintf("; not to %s (not on the allowlist)", strings.Join(off, ", "))
			}
			add(name, what)
			return &sessionspec.Binding{Ref: ref, Hosts: hosts, Inject: b.Inject, Placeholder: placeholder(), EnvVar: name}, nil
		}
		return nil, nil
	}
	bind := func(name string, egress sessionspec.Egress, readableOK bool) (*sessionspec.Binding, *sessionspec.Readable) {
		b, ok := c.secretBinding(name)
		return bindRef(name, brokerseal.SecretRef(name), b, ok, egress, readableOK)
	}
	for _, name := range s.Secrets {
		b, r := bind(name, spec.Egress, true)
		if b != nil {
			spec.Bindings = append(spec.Bindings, *b)
			spec.Env = append(spec.Env, sessionspec.EnvVar{Name: name, Value: b.Placeholder})
		}
		if r != nil {
			spec.Readable = append(spec.Readable, *r)
		}
	}
	// infra tokens (tier 3): bound by the host to the --infra-endpoint hosts
	for _, t := range s.InfraTokens {
		env := t[:strings.Index(t, "=")]
		var b brokerseal.Binding
		var ok bool
		if c.env.CredentialBinding != nil {
			b, ok = c.env.CredentialBinding(InfraRef(env))
		}
		if bb, _ := bindRef(env, InfraRef(env), b, ok, spec.Egress, false); bb != nil {
			spec.Bindings = append(spec.Bindings, *bb)
			spec.Env = append(spec.Env, sessionspec.EnvVar{Name: env, Value: bb.Placeholder})
		}
	}
	for i, d := range rec.Dependencies {
		if i >= len(spec.Dependencies) {
			break
		}
		dep := &spec.Dependencies[i]
		for _, name := range d.Secrets {
			if b, _ := bind(name, dep.Egress, false); b != nil {
				dep.Bindings = append(dep.Bindings, *b)
				dep.Env = append(dep.Env, sessionspec.EnvVar{Name: name, Value: b.Placeholder})
			}
		}
	}
	return lines
}

// bindOpencode gives opencode v2's environment (design 5.9.4): OPENAI_API_KEY holding a placeholder
// the broker replaces toward the endpoint, OPENAI_BASE_URL, and OPENCODE_CONFIG_CONTENT, the model
// list the host fetched with the key.
func (c *cmdCtx) bindOpencode(spec *sessionspec.Spec, s LaunchSpec) {
	var b brokerseal.Binding
	var ok bool
	if c.env.CredentialBinding != nil {
		b, ok = c.env.CredentialBinding(OpencodeRef)
	}
	host := strings.ToLower(urlHost(s.BaseURL))
	if !ok || b.Allows([]string{host}, "bearer", false) != nil || !sessionspec.Reachable(host, spec.Egress) {
		c.die("opencode's API key is not bound to %s for this launch; run it through the host's sandbox command, with OPENCODE_API_KEY set there.", host)
	}
	cfg := ""
	if c.env.Getenv != nil {
		cfg = c.env.Getenv(OpencodeConfigEnv)
	}
	if cfg == "" {
		c.die("opencode's configuration did not come from the host; run it through the host's sandbox command.")
	}
	ph := placeholder()
	spec.Bindings = append(spec.Bindings, sessionspec.Binding{Ref: OpencodeRef, Hosts: []string{host}, Inject: "bearer", Placeholder: ph, EnvVar: "OPENAI_API_KEY"})
	spec.Env = append(spec.Env, sessionspec.EnvVar{Name: "OPENAI_API_KEY", Value: ph},
		sessionspec.EnvVar{Name: "OPENCODE_CONFIG_CONTENT", Value: cfg}, sessionspec.EnvVar{Name: "OPENAI_BASE_URL", Value: s.BaseURL})
	c.out("==> opencode: API key brokered to %s (bearer)", host)
}
