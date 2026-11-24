package config

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

// This file is lib/profile.sh (resolve_overlay_path is in config.go) and version_ge from
// lib/platform.sh, which overlay_min_version_unmet uses.

// IsNumericProfile is is_numeric_profile: the tier aliases 1, 2 and 3.
func IsNumericProfile(name string) bool { return name == "1" || name == "2" || name == "3" }

// UserProfilesDir is user_profiles_dir.
func UserProfilesDir(e Env) string { return e.Home + "/.sandbox/profiles" }

var profileNameChars = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// IsValidProfileName is is_valid_profile_name. The bash's [A-Za-z] follows the locale (under
// en_US.UTF-8 on Linux it accepts "café"); the port is ASCII-only in every locale, which is what
// the bash does under C and on macOS.
func IsValidProfileName(name string) bool {
	return name != "" && !IsNumericProfile(name) && !strings.Contains(name, "/") &&
		!strings.Contains(name, "..") && !strings.HasPrefix(name, ".") && profileNameChars.MatchString(name)
}

// FindProfilePath is find_profile_path: ~/.sandbox/profiles/<name>.yaml, then
// <overlay>/profiles/<name>.yaml; ok is false when neither is a file.
//
// With ProfileLookupStaysInDir, a name that is absolute or has a ".." component is not looked up
// (the bash joined it as given, so --profile ../../x read a file outside both directories).
func FindProfilePath(e Env, name string) (string, bool) {
	if deviation.Fixed(deviation.ProfileLookupStaysInDir) {
		if strings.HasPrefix(name, "/") {
			return "", false
		}
		for _, c := range strings.Split(name, "/") {
			if c == ".." {
				return "", false
			}
		}
	}
	if p := UserProfilesDir(e) + "/" + name + ".yaml"; IsFile(p) {
		return p, true
	}
	if ov := ResolveOverlayPath(e); ov != "" {
		if p := ov + "/profiles/" + name + ".yaml"; IsFile(p) {
			return p, true
		}
	}
	return "", false
}

// OverlayBlockedDestinationsFile is overlay_blocked_destinations_file: the overlay's
// blocked-destinations.yaml if it is a file, else "".
func OverlayBlockedDestinationsFile(e Env) string {
	ov := ResolveOverlayPath(e)
	if ov == "" {
		return ""
	}
	if p := ov + "/blocked-destinations.yaml"; IsFile(p) {
		return p
	}
	return ""
}

// OverlayMinSandboxVersion is overlay_min_sandbox_version.
func OverlayMinSandboxVersion(overlay string) string {
	return ExtractYAMLScalar(overlay+"/config.yaml", "min_sandbox_version")
}

var minVersionForm = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+)*$`)

// OverlayMinVersionUnmet is overlay_min_version_unmet: the overlay's min_sandbox_version when the
// running CLI (version; "" means "dev") does not satisfy it, else "". warnings are the WARN
// messages the bash prints (without the "WARN: " prefix).
func OverlayMinVersionUnmet(overlay, version string) (unmet string, warnings []string) {
	min := OverlayMinSandboxVersion(overlay)
	if min == "" {
		return "", nil
	}
	if !minVersionForm.MatchString(min) {
		return "", []string{fmt.Sprintf("overlay config.yaml sets an unparseable min_sandbox_version '%s' — ignoring it.", min)}
	}
	if version == "" || version == "dev" {
		return "", []string{fmt.Sprintf("overlay requires agent-sandboxes >= %s, but this is an unversioned dev checkout — cannot compare, continuing.", min)}
	}
	if VersionGE(version, min) {
		return "", nil
	}
	return min, nil
}

// VersionGE is version_ge in lib/platform.sh: dotted versions compared field by field, a leading
// v stripped, a missing field read as 0, each field cut to its leading digits.
//
// In legacy mode a field is bash arithmetic (10#...), so one past the 64-bit range wraps; with
// DecimalNumbers a field compares as an unbounded decimal number.
func VersionGE(a, b string) bool {
	fa, fb := versionFields(strings.TrimPrefix(a, "v")), versionFields(strings.TrimPrefix(b, "v"))
	n := len(fa)
	if len(fb) > n {
		n = len(fb)
	}
	for i := 0; i < n; i++ {
		xa, xb := "0", "0"
		if i < len(fa) {
			xa = fa[i]
		}
		if i < len(fb) {
			xb = fb[i]
		}
		xa, xb = leadingDigits(xa), leadingDigits(xb)
		if c := compareFields(xa, xb); c != 0 {
			return c > 0
		}
	}
	return true
}

// versionFields is `read_into_array f < <(printf '%s\n' ${v})` with IFS='.': word splitting on
// '.', where an empty field between two dots is kept and a trailing '.' adds none. (The bash
// also glob-expands each field; a version never contains *, ? or [.)
func versionFields(v string) []string {
	if v == "" {
		return nil
	}
	f := strings.Split(v, ".")
	if strings.HasSuffix(v, ".") {
		f = f[:len(f)-1]
	}
	return f
}

// leadingDigits is ${x%%[!0-9]*}, then ${x:-0}.
func leadingDigits(x string) string {
	i := 0
	for i < len(x) && x[i] >= '0' && x[i] <= '9' {
		i++
	}
	if i == 0 {
		return "0"
	}
	return x[:i]
}

func compareFields(a, b string) int {
	if deviation.Fixed(deviation.DecimalNumbers) {
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		if len(a) != len(b) {
			if len(a) > len(b) {
				return 1
			}
			return -1
		}
		return strings.Compare(a, b)
	}
	ia, ib := bashArith(a), bashArith(b)
	switch {
	case ia > ib:
		return 1
	case ia < ib:
		return -1
	}
	return 0
}

// bashArith is the value of 10#digits in bash arithmetic: 64-bit, wrapping on overflow.
func bashArith(d string) int64 {
	var v uint64
	for i := 0; i < len(d); i++ {
		v = v*10 + uint64(d[i]-'0')
	}
	return int64(v)
}

// RenderProfileYAML is render_profile_yaml: the profile file `sandbox profile save` writes. agent
// and defaultRepo are omitted when empty; empty domains are skipped.
//
// With WritesReadBack, a value the profile readers would not read back unchanged (a line break,
// a quote, " #", or surrounding whitespace in a scalar; the same in a domain, or a leading '#',
// or an echo option) is refused.
func RenderProfileYAML(name, tier, agent, defaultRepo string, domains []string) (string, error) {
	if deviation.Fixed(deviation.WritesReadBack) {
		for _, kv := range [][2]string{{"profile", name}, {"tier", tier}, {"agent", agent}, {"default_repo", defaultRepo}} {
			if kv[1] != "" && !scalarReadsBack(kv[1]) {
				return "", fmt.Errorf("profile %s %q cannot be saved: the profile reader would not read it back as written", kv[0], kv[1])
			}
		}
		for _, d := range domains {
			if d == "" {
				continue
			}
			if got, ok := listItem("  - " + d); strings.ContainsAny(d, "\n\r") || !ok || got != d {
				return "", fmt.Errorf("profile domain %q cannot be saved: the profile reader would not read it back as written", d)
			}
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — generated by `sandbox profile save`\n", name)
	b.WriteString("# Edit by hand, or re-run save with --force to regenerate.\n")
	fmt.Fprintf(&b, "profile: %s\ntier: %s\n", name, tier)
	if agent != "" {
		fmt.Fprintf(&b, "agent: %s\n", agent)
	}
	if defaultRepo != "" {
		fmt.Fprintf(&b, "default_repo: %s\n", defaultRepo)
	}
	var ds []string
	for _, d := range domains {
		if d != "" {
			ds = append(ds, d)
		}
	}
	if len(ds) > 0 {
		b.WriteString("extra_allowed_domains:\n")
		for _, d := range ds {
			fmt.Fprintf(&b, "  - %s\n", d)
		}
	}
	return b.String(), nil
}

// scalarReadsBack reports whether "key: v" reads back as v through ExtractYAMLScalar's cleanup.
func scalarReadsBack(v string) bool {
	if strings.ContainsAny(v, "\n\r\"'") {
		return false
	}
	got := v
	if loc := reTrailComment.FindStringIndex(got); loc != nil {
		got = got[:loc[0]]
	}
	got = reLeadSpace.ReplaceAllString(got, "")
	got = reTrailSpace.ReplaceAllString(got, "")
	return got == v
}
