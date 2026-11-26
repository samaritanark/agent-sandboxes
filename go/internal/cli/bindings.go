package cli

import (
	"io"
	"slices"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
)

// RunBindings is the in-VM half of the host's pre-pass (owner decision, eighth round): the names
// of the host-side secrets `sandbox run ARGS` would bind (the profile's secrets: and each
// profile dependency's), in the order run checks them, without duplicates, and the repositories
// it would mount (as run sees them, `~` expanded), which the host syncs and mirrors first. It decides as run
// does but prints nothing, prompts for nothing, writes nothing, and does not require the secrets
// to be present: the host checks and pushes them, and the run that follows checks again. ok is
// false when run would stop (or only print its usage) before binding anything; status is then
// the status run would end with.
func RunBindings(args []string, env Env) (names, repos []string, ok bool, status int) {
	p, ok, status := RunPrepass(args, env)
	return p.Secrets, p.Repos, ok, status
}

// InfraToken is one --infra-token of a launch: the variable it fills and the token file's path on
// the host, which the host reads, seals, and pushes (design 5.9.4: a placeholder bound to the
// --infra-endpoint hosts).
type InfraToken struct {
	Env  string `json:"env"`
	Path string `json:"path"`
}

// Prepass is everything the host needs before a launch: the secrets it binds, the repositories it
// mounts, its infra tokens, and the hosts of its --infra-endpoint URLs (the tokens' destinations).
type Prepass struct {
	Secrets     []string     `json:"secrets"`
	Repos       []string     `json:"repos"`
	InfraTokens []InfraToken `json:"infra_tokens,omitempty"`
	InfraHosts  []string     `json:"infra_hosts,omitempty"`
	// OpencodeBaseURL is an opencode launch's endpoint, which the host binds its API key to.
	OpencodeBaseURL string `json:"opencode_base_url,omitempty"`
}

// RunPrepass is RunBindings with the infra tokens and their hosts.
func RunPrepass(args []string, env Env) (p Prepass, ok bool, status int) {
	c := &cmdCtx{env: env, stdout: io.Discard, stderr: io.Discard, prepass: true}
	c.env.Stdin, c.env.StdinTTY = nil, false
	defer func() {
		if r := recover(); r != nil {
			e, isExit := r.(exit)
			if !isExit {
				panic(r)
			}
			p, ok, status = Prepass{}, false, int(e)
		}
	}()
	s := runDecide(c, args)
	seen := map[string]bool{}
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			p.Secrets = append(p.Secrets, n)
		}
	}
	for _, n := range s.Secrets {
		add(n)
	}
	deps, depsOK := c.resolveDependencies("prepass", s.Agent, s.MCPs, s.Services)
	if !depsOK {
		return Prepass{}, false, 1
	}
	for _, d := range deps {
		for _, n := range d.Secrets {
			add(n)
		}
	}
	p.Repos = s.Repos
	if s.Agent == "opencode" {
		p.OpencodeBaseURL = s.BaseURL
	}
	if s.Tier == "3" {
		for _, t := range s.InfraTokens {
			i := strings.Index(t, "=")
			p.InfraTokens = append(p.InfraTokens, InfraToken{Env: t[:i], Path: t[i+1:]})
		}
		p.InfraHosts = infraHosts(s.InfraEndpoints)
	}
	return p, true, 0
}

// infraHosts are the distinct hosts of the --infra-endpoint URLs, lower-cased.
func infraHosts(eps []string) []string {
	var out []string
	for _, ep := range eps {
		if h := strings.ToLower(urlHost(ep)); h != "" && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}

// InfraRef is the broker store reference of an infra token's variable.
func InfraRef(env string) string { return "infra." + env }

// infraTokenPresent is whether the host pushed the token for variable env: in the pre-pass every
// token counts; with no broker store to ask (the differential tests), the file is checked, as v2
// did.
func (c *cmdCtx) infraTokenPresent(env, path string) bool {
	switch {
	case c.prepass:
		return true
	case c.env.CredentialPresent != nil:
		return c.env.CredentialPresent(InfraRef(env))
	}
	return config.IsFile(path)
}

// secretPresent is whether the launch has a secret: in the pre-pass every name counts (the host
// has not pushed yet).
func (c *cmdCtx) secretPresent(name string) bool {
	switch {
	case c.prepass:
		return true
	case c.env.SecretPresent != nil:
		return c.env.SecretPresent(name)
	}
	return config.IsFile(c.env.SecretsDir + "/" + name)
}

// OpencodeRef is opencode's API key in the broker store (the host seals it from
// OPENCODE_API_KEY), and OpencodeConfigEnv the variable the host passes its configuration in.
const (
	OpencodeRef       = "opencode.OPENAI_API_KEY"
	OpencodeConfigEnv = "SANDBOX_OPENCODE_CONFIG"
)

// opencodeKeyPresent is whether opencode has its API key: in the pre-pass it counts (the host
// checks); with a broker store, the host must have pushed it; otherwise (the differential tests)
// the environment's, as v2.
func (c *cmdCtx) opencodeKeyPresent() bool {
	switch {
	case c.prepass:
		return true
	case c.env.CredentialPresent != nil:
		return c.env.CredentialPresent(OpencodeRef)
	}
	return c.env.OpencodeAPIKey != ""
}
