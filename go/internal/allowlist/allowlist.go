// Package allowlist is the domain-set half of build_cilium_policy (lib/policy.sh:42-97): the
// session's egress allowlist as v2 rendered it into the CiliumNetworkPolicy. In v3 it is the
// allowlist the session spec carries to the gateway (design 5.4.1, 5.4.2); the CNP rendering is not
// ported.
package allowlist

import (
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/checks"
)

// Build returns the session's allowlist: the agent's and the tier's built-in domains, then the
// extras, then for each "*.X" entry the apex X when X is a registrable domain the block lists do
// not block (a Cilium matchPattern does not reach the apex; the bash re-checks the synthesized
// apex because it never passed the input gate). The list is deduplicated keeping first
// occurrences, blank entries dropped, as `printf '%s\n' ... | awk 'NF && !seen[$0]++'` does:
// that pipeline works on lines, so an entry holding a newline becomes several entries.
func Build(c checks.Ctx, agentDomains, tierDomains, extras []string) []string {
	all := append(append(append([]string(nil), agentDomains...), tierDomains...), extras...)
	n := len(all) // the bash loop iterates the array as it was when the loop began
	for _, d := range all[:n] {
		if !strings.HasPrefix(d, "*.") {
			continue
		}
		apex := checks.NormalizeDomain(d[2:])
		if checks.ApexIsRegistrableDomain(apex) && !c.DomainIsBlocked(apex) {
			all = append(all, apex)
		}
	}
	var lines []string
	for _, d := range all {
		lines = append(lines, strings.Split(d, "\n")...)
	}
	seen := map[string]bool{}
	var out []string
	for _, l := range lines {
		if strings.Trim(l, " \t") == "" || seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out
}
