// Package egressmatch holds the domain-matching rules shared by the policy layer (which builds
// the allowlist and the block lists) and the gateway and resolver (which enforce them), so both
// sides read a name the same way (design 5.4.1: one source of truth for blocked-destination
// rules). Data and pure functions only.
package egressmatch

import "strings"

// Normalize is a domain as both sides compare it: lower case (ASCII), without trailing dots or
// newlines. It is v2's normalize_domain.
func Normalize(d string) string {
	d = strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, d)
	d = strings.TrimRight(d, "\n")
	d = strings.TrimRight(d, ".")
	return strings.TrimRight(d, "\n")
}

// Blocked is v2's _domain_matches_block_pattern for an already normalized domain: "*.x" blocks x
// and every name under it, "*suffix" blocks names ending in suffix, "prefix.*" blocks prefix and
// every name starting "prefix.", and anything else blocks exactly that name.
func Blocked(domain, pattern string) bool {
	p := Normalize(pattern)
	switch {
	case strings.HasPrefix(p, "*."):
		apex := p[2:]
		return domain == apex || strings.HasSuffix(domain, "."+apex)
	case strings.HasPrefix(p, "*"):
		return strings.HasSuffix(domain, p[1:])
	case strings.HasSuffix(p, ".*"):
		prefix := p[:len(p)-2]
		return domain == prefix || strings.HasPrefix(domain, prefix+".")
	}
	return domain == p
}

// Allowed reports whether a normalized domain matches one allowlist entry: an exact name, or
// "*.x", which (as a Cilium matchPattern in v2) matches exactly one label under x and not x itself;
// the policy layer adds the apex as its own entry when it should be allowed.
func Allowed(domain, entry string) bool {
	e := Normalize(entry)
	if rest, ok := strings.CutPrefix(e, "*."); ok {
		label, parent, found := strings.Cut(domain, ".")
		return found && label != "" && parent == rest
	}
	return domain == e
}

// Decide is the gateway's and resolver's question: may the session reach domain? Deny wins: a
// name that matches any block pattern is refused even when the allowlist names it.
func Decide(domain string, allow, block []string) bool {
	d := Normalize(domain)
	if d == "" {
		return false
	}
	for _, b := range block {
		if b != "" && Blocked(d, b) {
			return false
		}
	}
	for _, a := range allow {
		if Allowed(d, a) {
			return true
		}
	}
	return false
}
