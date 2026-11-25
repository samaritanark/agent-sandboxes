// Package checks is the egress side of lib/checks.sh: the blocked-destinations lists (org,
// overlay, user), domain and CIDR matching, the over-broad wildcard refusal, the eTLD+1 apex rule,
// and the trusted inference endpoints.
//
// Not ported: check_no_privileged_flags and check_dependency_no_host_mounts grep rendered pod
// manifests, which v3 does not have (sandboxd validates a structured spec instead, design
// section 5.4.2); check_prerequisites checks v2's host tools and belongs with the CLI.
package checks

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/egressmatch"
)

// Ctx is what the checks read: the environment and the org block list
// ($BLOCKED_DESTINATIONS_CONFIG, default $SANDBOX_ROOT/config/blocked-destinations.yaml).
type Ctx struct {
	config.Env
	OrgFile string
}

// Error is a refusal: the lines the bash prints to stderr before `exit 1`.
type Error struct{ Lines []string }

func (e *Error) Error() string { return strings.Join(e.Lines, "\n") }

func refuse(lines ...string) error { return &Error{Lines: lines} }

// NormalizeDomain is _normalize_domain: ASCII lowercase, trailing root dots removed. (The two
// command substitutions around it also drop trailing newlines, before and after the dots.)
func NormalizeDomain(d string) string { return egressmatch.Normalize(d) }

// DomainMatchesBlockPattern is _domain_matches_block_pattern; domain is already normalized.
func DomainMatchesBlockPattern(domain, pattern string) bool {
	return egressmatch.Blocked(domain, pattern)
}

// blockFiles lists the block-list sources that exist, labelled as the bash labels them.
func (c Ctx) blockFiles() [][2]string {
	var f [][2]string
	if config.IsFile(c.OrgFile) {
		f = append(f, [2]string{c.OrgFile, "org"})
	}
	if ov := config.OverlayBlockedDestinationsFile(c.Env); ov != "" {
		f = append(f, [2]string{ov, "overlay"})
	}
	if config.IsFile(c.UserConfig) {
		f = append(f, [2]string{c.UserConfig, "user"})
	}
	return f
}

// CheckDomainNotBlocked is check_domain_not_blocked: an error naming the first matching rule
// (org, then overlay, then user). warnings are the WARN lines it prints.
//
// In legacy mode a missing org list skips every list, overlay and user included, with a warning;
// with MissingOrgBlockListFailsClosed it is a refusal (design Appendix B, item 1).
func (c Ctx) CheckDomainNotBlocked(target string) (warnings []string, err error) {
	domain := NormalizeDomain(target)
	if !config.IsFile(c.OrgFile) {
		if deviation.Fixed(deviation.MissingOrgBlockListFailsClosed) {
			return nil, refuse(
				fmt.Sprintf("ERROR: the org blocked-destinations list is missing (%s);", c.OrgFile),
				"       refusing egress to '"+domain+"' rather than skipping the block check.")
		}
		return []string{"WARN: blocked-destinations.yaml not found; skipping block check."}, nil
	}
	for _, f := range c.blockFiles() {
		for _, p := range config.ExtractYAMLList(f[0], "blocked_domains") {
			if p != "" && DomainMatchesBlockPattern(domain, p) {
				return nil, refuse(
					fmt.Sprintf("ERROR: Domain '%s' matches the %s blocked-destinations rule '%s'.", domain, f[1], p),
					fmt.Sprintf("       (%s)", f[0]))
			}
		}
	}
	return nil, nil
}

// DomainIsBlocked is domain_is_blocked: the quiet predicate over the same three lists. With
// MissingOrgBlockListFailsClosed a missing org list counts as blocked.
func (c Ctx) DomainIsBlocked(d string) bool {
	if !config.IsFile(c.OrgFile) && deviation.Fixed(deviation.MissingOrgBlockListFailsClosed) {
		return true
	}
	domain := NormalizeDomain(d)
	for _, f := range c.blockFiles() {
		for _, p := range config.ExtractYAMLList(f[0], "blocked_domains") {
			if p != "" && DomainMatchesBlockPattern(domain, p) {
				return true
			}
		}
	}
	return false
}

// BlockedCIDRs is get_blocked_cidrs: the org, overlay and user blocked_cidrs, first occurrence of
// each kept.
func (c Ctx) BlockedCIDRs() []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range c.blockFiles() {
		for _, x := range config.ExtractYAMLList(f[0], "blocked_cidrs") {
			if strings.TrimSpace(x) != "" && !seen[x] { // awk 'NF && !seen[$0]++'
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	return out
}

var (
	legacyIPv4CIDR = regexp.MustCompile(`^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$`)
	legacyIPv6CIDR = regexp.MustCompile(`^[0-9A-Fa-f:]+/[0-9]{1,3}$`)
	ipv4Shape      = regexp.MustCompile(`^([0-9]{1,3}\.){3}[0-9]{1,3}$`)
)

// ValidateCIDR is validate_cidr. In legacy mode it is a shape check that accepts /33, octets over
// 255, and any run of hex digits and colons; with StrictCIDRs the CIDR must parse (IPv4 or IPv6,
// a prefix length within the address size, no leading zeros).
func ValidateCIDR(cidr string) bool {
	if deviation.Fixed(deviation.StrictCIDRs) {
		_, err := netip.ParsePrefix(cidr)
		return err == nil
	}
	return legacyIPv4CIDR.MatchString(cidr) || (strings.Contains(cidr, ":") && legacyIPv6CIDR.MatchString(cidr))
}

// CheckBlockedCIDRsValid is check_blocked_cidrs_valid: an error for the first malformed entry.
func (c Ctx) CheckBlockedCIDRsValid() error {
	for _, x := range c.BlockedCIDRs() {
		if !ValidateCIDR(x) {
			return refuse(
				fmt.Sprintf("ERROR: blocked_cidrs entry '%s' is not a valid CIDR.", x),
				fmt.Sprintf("       Fix it in %s (or the overlay's blocked-destinations.yaml).", c.OrgFile),
				"       Expected forms: 10.0.0.0/8, 169.254.0.0/16, fd00::/8.")
		}
	}
	return nil
}

// IsIPv4Literal is _is_ipv4_literal: dotted-quad shape, octets not range-checked.
func IsIPv4Literal(s string) bool { return ipv4Shape.MatchString(s) }

// IPv4ToInt is _ipv4_to_int: four '.'-separated decimal fields of 0-255. In legacy mode a field
// is bash arithmetic and wraps past 64 bits; with DecimalNumbers it does not.
func IPv4ToInt(ip string) (uint32, bool) {
	f := strings.Split(ip, ".") // IFS='.' word splitting: a trailing '.' adds no field
	if ip == "" {
		f = nil
	} else if strings.HasSuffix(ip, ".") {
		f = f[:len(f)-1]
	}
	if len(f) != 4 {
		return 0, false
	}
	var n uint32
	for _, o := range f {
		if o == "" || strings.Trim(o, "0123456789") != "" {
			return 0, false
		}
		v, ok := decimal(o)
		if !ok || v < 0 || v > 255 {
			return 0, false
		}
		n = n<<8 + uint32(v)
	}
	return n, true
}

// decimal is 10#digits: legacy wraps at 64 bits; DecimalNumbers saturates (so it stays out of
// any small range).
func decimal(d string) (int64, bool) {
	var v uint64
	for i := 0; i < len(d); i++ {
		next := v*10 + uint64(d[i]-'0')
		if deviation.Fixed(deviation.DecimalNumbers) && (next < v || v > (1<<63)/10) {
			return 1<<63 - 1, true
		}
		v = next
	}
	return int64(v), true
}

// bashInt is the value of a digit string as a bash arithmetic constant: a leading 0 means octal,
// and an 8 or 9 in an octal constant is an error (ok false).
func bashInt(d string) (int64, bool) {
	if len(d) > 1 && d[0] == '0' {
		var v uint64
		for i := 1; i < len(d); i++ {
			if d[i] > '7' {
				return 0, false
			}
			v = v*8 + uint64(d[i]-'0')
		}
		return int64(v), true
	}
	return decimal(d)
}

// IPInCIDR is ip_in_cidr: IPv4 only. In legacy mode the prefix length is bash arithmetic, so a
// leading zero makes it octal (/010 is /8) or an error (/08, which reports "not inside"); with
// DecimalNumbers it is decimal.
func IPInCIDR(ip, cidr string) bool {
	if strings.Contains(ip+cidr, ":") || !strings.Contains(cidr, "/") || !IsIPv4Literal(ip) {
		return false
	}
	netPart := cidr[:strings.LastIndex(cidr, "/")]
	prefixStr := cidr[strings.Index(cidr, "/")+1:]
	if !IsIPv4Literal(netPart) || prefixStr == "" || strings.Trim(prefixStr, "0123456789") != "" {
		return false
	}
	var prefix int64
	var ok bool
	if deviation.Fixed(deviation.DecimalNumbers) {
		prefix, ok = decimal(prefixStr)
	} else {
		prefix, ok = bashInt(prefixStr)
	}
	if !ok || prefix < 0 || prefix > 32 {
		return false
	}
	ipInt, ok1 := IPv4ToInt(ip)
	netInt, ok2 := IPv4ToInt(netPart)
	if !ok1 || !ok2 {
		return false
	}
	var mask uint32
	if prefix != 0 {
		mask = uint32(0xFFFFFFFF << (32 - prefix))
	}
	return ipInt&mask == netInt&mask
}

// CheckIPNotInBlockedCIDRs is check_ip_not_in_blocked_cidrs: an IPv6 literal is skipped with a
// warning (Cilium enforces it at runtime), a non-literal is not checked.
func (c Ctx) CheckIPNotInBlockedCIDRs(ip string) (warnings []string, err error) {
	if strings.Contains(ip, ":") {
		return []string{
			fmt.Sprintf("WARN: %s is an IPv6 literal; create-time blocked-CIDR check skipped", ip),
			"      (Cilium still enforces egressDeny at runtime).",
		}, nil
	}
	if !IsIPv4Literal(ip) {
		return nil, nil
	}
	for _, x := range c.BlockedCIDRs() {
		if strings.Contains(x, ":") {
			continue
		}
		if IPInCIDR(ip, x) {
			return nil, refuse(
				fmt.Sprintf("ERROR: %s falls inside blocked CIDR '%s'.", ip, x),
				fmt.Sprintf("       (%s, the overlay's blocked-destinations.yaml, or %s)", c.OrgFile, c.UserConfig))
		}
	}
	return nil, nil
}

var multilabelPublicSuffixes = map[string]bool{}

func init() {
	for _, s := range strings.Fields(`
		co.uk org.uk me.uk gov.uk ac.uk net.uk ltd.uk plc.uk sch.uk nhs.uk
		com.au net.au org.au edu.au gov.au id.au
		co.nz net.nz org.nz govt.nz
		co.jp or.jp ne.jp ac.jp go.jp
		com.cn net.cn org.cn gov.cn ac.cn
		co.in net.in org.in gov.in com.br net.br org.br gov.br
		co.za org.za com.mx com.sg com.hk com.tr co.kr or.kr
		com.ua co.il com.ar com.tw co.th com.my
		github.io githubusercontent.com gitlab.io pages.dev workers.dev
		web.app firebaseapp.com netlify.app vercel.app herokuapp.com
		blogspot.com wordpress.com amplifyapp.com appspot.com r2.dev
		s3.amazonaws.com cloudfront.net blob.core.windows.net azurewebsites.net`) {
		multilabelPublicSuffixes[s] = true
	}
}

// IsMultilabelPublicSuffix is _is_multilabel_public_suffix: the curated list, exact match.
func IsMultilabelPublicSuffix(name string) bool { return multilabelPublicSuffixes[name] }

// ApexIsRegistrableDomain is _apex_is_registrable_domain: name is exactly one label above a
// public suffix (eTLD+1).
func ApexIsRegistrableDomain(name string) bool {
	if !strings.Contains(name, ".") || IsMultilabelPublicSuffix(name) {
		return false
	}
	rest := name[strings.Index(name, ".")+1:]
	if strings.Contains(rest, ".") {
		return IsMultilabelPublicSuffix(rest)
	}
	return true
}

// EgressWildcardTooBroad is _egress_wildcard_too_broad on a normalized entry: any '*' other than
// one leading "*." over a registrable domain is too broad.
func EgressWildcardTooBroad(d string) bool {
	if !strings.Contains(d, "*") {
		return false
	}
	if !strings.HasPrefix(d, "*.") {
		return true
	}
	rest := d[2:]
	switch {
	case strings.Contains(rest, "*"),
		strings.HasPrefix(rest, "."), strings.HasSuffix(rest, "."), strings.Contains(rest, ".."),
		!strings.Contains(rest, "."):
		return true
	}
	return IsMultilabelPublicSuffix(rest)
}

var hostLabel = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`) // no leading or trailing '-'

// egressSyntaxOK is the StrictEgressSyntax rule on a normalized target: an IPv6 address, a strict
// dotted-quad IPv4 address, or dot-separated labels of [a-z0-9_-] not starting or ending in '-'
// (optionally after a leading
// "*.") whose last label is not all digits (a numeric name like 1.2.3 or 010.0.0.1 is an IPv4
// address to inet_aton, read differently from how the block check reads it).
func egressSyntaxOK(n string) bool {
	if strings.Contains(n, ":") {
		a, err := netip.ParseAddr(n)
		return err == nil && a.Is6() && a.Zone() == ""
	}
	if a, err := netip.ParseAddr(n); err == nil {
		return a.Is4()
	}
	if len(n) > 253 {
		return false
	}
	labels := strings.Split(strings.TrimPrefix(n, "*."), ".")
	for _, l := range labels {
		if !hostLabel.MatchString(l) {
			return false
		}
	}
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

// CheckEgressTargetNotBlocked is check_egress_target_not_blocked: refuse an over-broad wildcard,
// then the domain block check, then (for an IPv4 literal) the blocked-CIDR check.
//
// With StrictEgressSyntax a target that is not a host name or IP address is refused first. The
// bash compared the target as a literal string, but the policy renders it inside a YAML
// double-quoted scalar, which interprets backslash escapes, so an escaped form of a blocked name
// passed the block check and reached the policy as the blocked name. The CIDR check then runs on
// the normalized target, so a trailing dot no longer skips it.
func (c Ctx) CheckEgressTargetNotBlocked(target string) (warnings []string, err error) {
	n := NormalizeDomain(target)
	if deviation.Fixed(deviation.StrictEgressSyntax) && !egressSyntaxOK(n) {
		return nil, refuse(
			fmt.Sprintf("ERROR: egress allow entry '%s' is not a host name or IP address.", target),
			"       Use dot-separated labels of letters, digits, '-' and '_' (optionally starting",
			"       '*.'), an IPv4 address such as 192.0.2.10, or an IPv6 address.")
	}
	if EgressWildcardTooBroad(n) {
		return nil, refuse(
			fmt.Sprintf("ERROR: egress allow entry '%s' is too broad to be allowed.", target),
			"       It would render to a Cilium DNS/toFQDNs matchPattern the block list",
			"       cannot constrain, opening egress (and DNS) to arbitrary hosts — a",
			"       containment bypass. Allow specific hosts, or a bounded wildcard of the",
			"       form '*.<domain>.<tld>' (e.g. '*.internal.example.com').")
	}
	w, err := c.CheckDomainNotBlocked(target)
	if err != nil {
		return w, err
	}
	ipTarget := target
	if deviation.Fixed(deviation.StrictEgressSyntax) {
		ipTarget = n
	}
	if IsIPv4Literal(ipTarget) {
		w2, err := c.CheckIPNotInBlockedCIDRs(ipTarget)
		return append(w, w2...), err
	}
	return w, nil
}

// InferenceEndpointIsTrusted is inference_endpoint_is_trusted: host is exactly an entry of the
// overlay config's trusted_inference_endpoints: list.
func (c Ctx) InferenceEndpointIsTrusted(host string) bool {
	if host == "" {
		return false
	}
	ov := config.ResolveOverlayPath(c.Env)
	if ov == "" || !config.IsFile(ov+"/config.yaml") {
		return false
	}
	for _, e := range config.ExtractYAMLList(ov+"/config.yaml", "trusted_inference_endpoints") {
		if e == host {
			return true
		}
	}
	return false
}
