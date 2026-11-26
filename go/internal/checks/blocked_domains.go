package checks

import (
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
)

// BlockedDomains is the org, overlay, and user blocked_domains patterns, first occurrence of each
// kept: what the gateway enforces at connection time (design 5.8), as BlockedCIDRs is for
// addresses.
func (c Ctx) BlockedDomains() []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range c.blockFiles() {
		for _, x := range config.ExtractYAMLList(f[0], "blocked_domains") {
			if strings.TrimSpace(x) != "" && !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	return out
}
