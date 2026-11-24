// Package tier is lib/tier.sh: the tier names, the extra egress domains of each tier, and the
// audit-log retention each tier records.
package tier

import "fmt"

// Validate is validate_tier: nil for 1, 2 or 3; otherwise the refusal the bash prints before
// exiting (its second line is a single space).
func Validate(tier string) error {
	switch tier {
	case "1", "2", "3":
		return nil
	}
	return fmt.Errorf("ERROR: Invalid tier '%s'. Valid tiers: 1, 2, 3.\n ", tier)
}

// projectDomains is the tier 2 and 3 list. lib/tier.sh is authoritative; config/tiers/tier2.yaml
// repeats it as documentation and has drifted (it lacks raw.githubusercontent.com).
var projectDomains = []string{
	"github.com",
	"api.github.com",
	"codeload.github.com",
	"objects.githubusercontent.com",
	"release-assets.githubusercontent.com",
	"raw.githubusercontent.com",
	"pypi.org",
	"files.pythonhosted.org",
	"registry.npmjs.org",
	"registry.terraform.io",
	"go.dev",
	"dl.google.com",
	"proxy.golang.org",
	"sum.golang.org",
}

// Domains is get_tier_domains: the extra egress domains for a tier (none for tier 1 or an unknown
// tier).
func Domains(tier string) []string {
	if tier == "2" || tier == "3" {
		return append([]string(nil), projectDomains...)
	}
	return nil
}

// RetentionDays is get_tier_retention_days: 180 for tier 3, otherwise 90.
func RetentionDays(tier string) int {
	if tier == "3" {
		return 180
	}
	return 90
}

// Description is get_tier_description.
func Description(tier string) string {
	switch tier {
	case "1":
		return "Ephemeral"
	case "2":
		return "Project"
	case "3":
		return "Infra"
	}
	return "Unknown"
}
