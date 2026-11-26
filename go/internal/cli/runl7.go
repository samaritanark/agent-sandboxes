package cli

// The session's own L7 rules (design 5.8.5): the overlay's egress-rules.yaml, then the operator's
// ~/.sandbox/egress-rules.yaml, in the org baseline's format (one JSON rule per line under
// "rules:"). sandboxd puts the image's baseline before them; a destination with a rule is
// intercepted. Rules only add: deny rules refuse, and allow rules narrow a host to what they list.
// A rule for a host this session's allowlist does not reach is left out and named, as a binding's
// host is (a rule never widens the allowlist). A file that does not parse stops the run: a rule
// the operator wrote must not be dropped quietly.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/l7"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// EgressRulesFile is the rules file's name in the overlay and in ~/.sandbox.
const EgressRulesFile = "egress-rules.yaml"

// l7Rules adds the overlay's and the operator's rules to spec's egress and returns run's lines.
func (c *cmdCtx) l7Rules(spec *sessionspec.Spec) []string {
	var lines []string
	type source struct{ what, path string }
	var srcs []source
	if ov := config.ResolveOverlayPath(c.env.Env); ov != "" {
		srcs = append(srcs, source{"overlay", filepath.Join(ov, EgressRulesFile)})
	}
	srcs = append(srcs, source{"operator", filepath.Join(c.env.Home, ".sandbox", EgressRulesFile)})
	for _, src := range srcs {
		b, err := os.ReadFile(src.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			c.die("cannot read the %s's L7 rules %s: %v", src.what, src.path, err)
		}
		rules, err := l7.ParseRules(b, src.what+" rules", false)
		if err != nil {
			c.die("the %s's L7 rules in %s: %v", src.what, src.path, err)
		}
		var kept int
		var off []string
		for _, r := range rules {
			if r.Host != l7.AnyHost && !reachableL7(r.Host, spec.Egress) {
				off = append(off, r.Host)
				continue
			}
			spec.Egress.L7 = append(spec.Egress.L7, r)
			kept++
		}
		line := fmt.Sprintf("==> L7 rules (%s): %d", src.what, kept)
		if len(off) > 0 {
			line += fmt.Sprintf("; left out for hosts not on this session's allowlist: %s", strings.Join(dedupe(off), ", "))
		}
		lines = append(lines, line)
	}
	return lines
}

// reachableL7 is the spec's own check (an exact name or a "*." wildcard the allowlist allows).
func reachableL7(host string, e sessionspec.Egress) bool {
	return sessionspec.L7Reachable(host, e)
}

func dedupe(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// registryWord marks a host name that looks like a package or image registry's.
var registryWords = []string{"registry", "npm", "pypi", "artifactory", "nexus", "verdaccio", "packages",
	"rubygems", "crates", "maven", "nuget", "harbor", "quay", "ghcr"}

// registryWarnings names each intercepted host of the session (an L7 rule's or a binding's) that
// looks like a registry but has no rule of its own refusing writes (owner decision, seventh round:
// the baseline names the public registries, and a self-hosted one needs the overlay's deny). The
// baseline's protocol rules for every host do not count: they cover push protocols, not an
// npm-style PUT. Only the run knows a session's intercepted hosts, so the warning is here rather
// than in doctor.
func (c *cmdCtx) registryWarnings(spec *sessionspec.Spec) []string {
	var rules []sessionspec.L7Rule
	if b, err := os.ReadFile(filepath.Join(c.env.SandboxRoot, "config", "egress-baseline.yaml")); err == nil {
		if base, err := l7.ParseBaseline(b); err == nil {
			rules = base
		}
	}
	rules = append(rules, spec.Egress.L7...)
	var hosts []string
	for _, r := range spec.Egress.L7 {
		if r.Host != l7.AnyHost && !strings.HasPrefix(r.Host, "*.") {
			hosts = append(hosts, r.Host)
		}
	}
	for _, b := range spec.Bindings {
		hosts = append(hosts, b.Hosts...)
	}
	for _, d := range spec.Dependencies {
		for _, b := range d.Bindings {
			hosts = append(hosts, b.Hosts...)
		}
	}
	var out []string
	for _, h := range dedupe(hosts) {
		if !looksLikeRegistry(h) || writeDenied(rules, h) {
			continue
		}
		out = append(out, fmt.Sprintf("WARNING: %s looks like a package or image registry, but no rule refuses writes to it (a publish with a credential would pass).", h),
			fmt.Sprintf("         Add one to ~/.sandbox/%s or the overlay, e.g.: {\"host\": \"%s\", \"methods\": [\"PUT\", \"DELETE\", \"PATCH\"], \"action\": \"deny\"}", EgressRulesFile, h))
	}
	return out
}

func looksLikeRegistry(host string) bool {
	for _, label := range strings.FieldsFunc(host, func(r rune) bool { return r == '.' || r == '-' }) {
		for _, w := range registryWords {
			if label == w {
				return true
			}
		}
	}
	return false
}

// writeDenied: a deny rule of the host's own (not every host's) covers PUT on any path.
func writeDenied(rules []sessionspec.L7Rule, host string) bool {
	for _, r := range rules {
		if r.Action != l7.Deny || r.Host == l7.AnyHost || !l7.HostMatches(r.Host, host) {
			continue
		}
		if len(r.Methods) == 0 {
			return true
		}
		for _, m := range r.Methods {
			if m == "PUT" {
				return true
			}
		}
	}
	return false
}
