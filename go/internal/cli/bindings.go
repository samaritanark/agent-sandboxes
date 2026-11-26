package cli

import (
	"io"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
)

// RunBindings is the in-VM half of the host's pre-pass (owner decision, eighth round): the names
// of the host-side secrets `sandbox run ARGS` would bind (the profile's secrets: and each
// profile dependency's), in the order run checks them, without duplicates. It decides as run
// does but prints nothing, prompts for nothing, writes nothing, and does not require the secrets
// to be present: the host checks and pushes them, and the run that follows checks again. ok is
// false when run would stop (or only print its usage) before binding anything; status is then
// the status run would end with.
func RunBindings(args []string, env Env) (names []string, ok bool, status int) {
	c := &cmdCtx{env: env, stdout: io.Discard, stderr: io.Discard, prepass: true}
	c.env.Stdin, c.env.StdinTTY = nil, false
	defer func() {
		if r := recover(); r != nil {
			e, isExit := r.(exit)
			if !isExit {
				panic(r)
			}
			names, ok, status = nil, false, int(e)
		}
	}()
	s := runDecide(c, args)
	seen := map[string]bool{}
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	for _, n := range s.Secrets {
		add(n)
	}
	deps, depsOK := c.resolveDependencies("prepass", s.Agent, s.MCPs, s.Services)
	if !depsOK {
		return nil, false, 1
	}
	for _, d := range deps {
		for _, n := range d.Secrets {
			add(n)
		}
	}
	return names, true, 0
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
