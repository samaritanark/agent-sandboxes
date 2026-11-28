package config

import (
	"fmt"
	"strconv"
)

// Log retention (OQ-08, owner decision 2026-11-27): nothing expires by default, and v2's per-tier
// retention_days (90, 90, 180), which nothing enforced, is no longer claimed. A team overlay may
// set a minimum per tier (log_retention_min_days_tier1, _tier2, _tier3: whole days), which
// `sandbox cleanup` never deletes below.

// RetentionMinDays is the overlay's minimum retention for each tier ("1", "2", "3"), in days; a
// tier the overlay does not set is absent. A value that is not a whole number of days is an
// error, so cleanup refuses rather than deletes.
func RetentionMinDays(e Env) (map[string]int, error) {
	out := map[string]int{}
	ov := ResolveOverlayPath(e)
	if ov == "" {
		return out, nil
	}
	for _, t := range []string{"1", "2", "3"} {
		key := "log_retention_min_days_tier" + t
		v := ExtractYAMLScalar(ov+"/config.yaml", key)
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || strconv.Itoa(n) != v {
			return nil, fmt.Errorf("the overlay's %s must be a whole number of days, got '%s'", key, v)
		}
		out[t] = n
	}
	return out, nil
}
