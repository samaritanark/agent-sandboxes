// Package l7 holds the L7 rules of an intercepted destination (design 5.8.5): their shape, the
// path pattern language, and the reference decision. The gateway controller compiles the same
// patterns to Envoy RE2 (Compile), and the tests hold the compiled form to a direct glob matcher,
// so what Envoy enforces and what the policy layer reasons about cannot drift apart. Data and pure
// functions only.
//
// A path pattern is a glob over the request path, optionally followed by "?" and query
// conditions:
//
//   - "*" matches any characters within one path segment (not "/");
//   - "**", which must be a whole segment, matches any number of segments, none included:
//     "/a/**/b" matches "/a/b" and "/a/x/y/b", and "/a/**" matches "/a" and everything below it;
//   - every other character matches itself (case-sensitive);
//   - a query part is "&"-separated conditions, each "name" (the parameter is present) or
//     "name=value" where value is a glob in which "*" matches any characters. All conditions must
//     hold, each by any occurrence of its parameter, names and values compared percent-decoded
//     (so "git%2Dreceive-pack" is "git-receive-pack"). A pattern without a query part ignores the
//     query. Only deny rules may have a query part: an allow rule that one occurrence satisfies
//     would pass a request whose server reads another.
package l7

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/egressmatch"
)

// Actions.
const (
	Allow = "allow"
	Deny  = "deny"
)

// AnyHost is a rule's Host when it applies to every intercepted destination (the org baseline's
// protocol rules, D-33). Only deny rules may use it.
const AnyHost = "*"

// Rule limits the requests to one destination. Methods and PathPatterns empty mean any.
type Rule struct {
	Host         string   `json:"host"`
	Methods      []string `json:"methods,omitempty"`
	PathPatterns []string `json:"path_patterns,omitempty"`
	Action       string   `json:"action"`
}

var (
	methodRE   = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{0,31}$`)
	pathCharRE = regexp.MustCompile(`^[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$`)
	nameRE     = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	valueRE    = regexp.MustCompile(`^[A-Za-z0-9._~!$'()*,;:@/-]*$`) // no "+", which decodes to a space
)

// Validate checks a rule's shape (the host itself is the caller's to check).
func (r Rule) Validate() error {
	switch r.Action {
	case Allow, Deny:
	default:
		return fmt.Errorf("l7: action %q is not allow or deny", r.Action)
	}
	if r.Host == "" {
		return errors.New("l7: a rule needs a host")
	}
	if r.Host == AnyHost && r.Action != Deny {
		return errors.New("l7: only a deny rule may apply to every host")
	}
	for _, m := range r.Methods {
		if !methodRE.MatchString(m) {
			return fmt.Errorf("l7: invalid method %q", m)
		}
	}
	for _, p := range r.PathPatterns {
		c, err := Compile(p)
		if err != nil {
			return err
		}
		if len(c.Query) > 0 && r.Action != Deny {
			return fmt.Errorf("l7: %q: only a deny rule may have a query part", p)
		}
	}
	return nil
}

// Pattern is a compiled path pattern: an RE2 expression for the path (Envoy matches it against the
// path without the query string) and the query conditions.
type Pattern struct {
	Glob      string
	PathRegex string
	Query     []QueryCond
}

// QueryCond is one query condition, compiled to RawRegex, an RE2 expression over the raw query
// string (Envoy matches it against the ":path" header, QueryPathRegex).
type QueryCond struct {
	Name     string
	RawRegex string
}

// encoded is an RE2 expression for a literal that may arrive with any of its characters
// percent-encoded, in either case of hex digit.
func encoded(lit string) string {
	var b strings.Builder
	for i := 0; i < len(lit); i++ {
		b.WriteString("(?:")
		b.WriteString(regexp.QuoteMeta(lit[i : i+1]))
		b.WriteString("|%")
		for _, h := range fmt.Sprintf("%02X", lit[i]) {
			if h >= 'A' {
				b.WriteString("[" + string(h) + string(h+'a'-'A') + "]")
			} else {
				b.WriteRune(h)
			}
		}
		b.WriteString(")")
	}
	return b.String()
}

// QueryPathRegex is the condition as an RE2 expression over a request's ":path" header.
func (q QueryCond) QueryPathRegex() string {
	return `^[^?]*\?` + strings.TrimPrefix(q.RawRegex, "^")
}

// MaxPatternLen bounds a path pattern, and so the size of its compiled expressions.
const MaxPatternLen = 200

// Compile parses and compiles a path pattern.
func Compile(glob string) (Pattern, error) {
	if len(glob) > MaxPatternLen {
		return Pattern{}, fmt.Errorf("l7: path pattern %q is longer than %d characters", glob, MaxPatternLen)
	}
	path, query, hasQuery := strings.Cut(glob, "?")
	if !strings.HasPrefix(path, "/") || !pathCharRE.MatchString(path) || strings.Contains(path, "//") {
		return Pattern{}, fmt.Errorf("l7: path pattern %q must start with / and hold only URL path characters", glob)
	}
	p := Pattern{Glob: glob}
	var re strings.Builder
	re.WriteString("^")
	segs := strings.Split(path, "/")[1:]
	for _, s := range segs {
		if s == "**" {
			// "/**" followed by "/b" or by nothing: zero or more segments
			re.WriteString("(?:/.*)?")
			continue
		}
		if strings.Contains(s, "**") {
			return Pattern{}, fmt.Errorf("l7: in %q, ** must be a whole path segment", glob)
		}
		re.WriteString("/")
		for j, part := range strings.Split(s, "*") {
			if j > 0 {
				re.WriteString("[^/]*")
			}
			re.WriteString(regexp.QuoteMeta(part))
		}
	}
	re.WriteString("$")
	p.PathRegex = re.String()
	if hasQuery {
		if query == "" {
			return Pattern{}, fmt.Errorf("l7: %q has an empty query part", glob)
		}
		seen := map[string]bool{}
		for _, c := range strings.Split(query, "&") {
			name, value, hasValue := strings.Cut(c, "=")
			if !nameRE.MatchString(name) || seen[name] || (hasValue && !valueRE.MatchString(value)) {
				return Pattern{}, fmt.Errorf("l7: invalid query condition %q in %q", c, glob)
			}
			seen[name] = true
			cond := encoded(name) + `(?:=[^&]*)?`
			if hasValue {
				var v strings.Builder
				for j, part := range strings.Split(value, "*") {
					if j > 0 {
						v.WriteString("[^&]*")
					}
					v.WriteString(encoded(part))
				}
				cond = encoded(name) + "=" + v.String()
				if strings.Trim(value, "*") == "" {
					// a parameter with no "=" has the empty value
					cond = encoded(name) + "(?:=" + v.String() + ")?"
				}
			}
			q := QueryCond{Name: name, RawRegex: `^(?:.*&)?` + cond + `(?:&.*)?$`}
			p.Query = append(p.Query, q)
		}
	}
	return p, nil
}

// Matches reports whether a request's path (without the query) and raw query match the pattern,
// using its compiled regular expressions.
func (p Pattern) Matches(path, rawQuery string) bool {
	if !regexp.MustCompile(p.PathRegex).MatchString(path) {
		return false
	}
	for _, q := range p.Query {
		if !regexp.MustCompile(q.RawRegex).MatchString(rawQuery) {
			return false
		}
	}
	return true
}

// HostMatches reports whether a rule's host covers a destination: the rule's host exactly, a
// wildcard entry as egressmatch reads one, or AnyHost.
func HostMatches(ruleHost, host string) bool {
	if ruleHost == AnyHost {
		return true
	}
	h := egressmatch.Normalize(host)
	return h != "" && egressmatch.Allowed(h, ruleHost)
}

func (r Rule) matches(method, path, rawQuery string) bool {
	if len(r.Methods) > 0 {
		ok := false
		for _, m := range r.Methods {
			ok = ok || m == method
		}
		if !ok {
			return false
		}
	}
	if len(r.PathPatterns) == 0 {
		return true
	}
	for _, g := range r.PathPatterns {
		if p, err := Compile(g); err == nil && p.Matches(path, rawQuery) {
			return true
		}
	}
	return false
}

// Decide is the reference decision for one request to host, deny first: any deny rule that
// matches refuses it; otherwise, if the host has allow rules, one of them must match; a host with
// none allows what no deny rule refuses. It returns the deciding rule's index, or -1.
func Decide(rules []Rule, host, method, path, rawQuery string) (bool, int) {
	hasAllow := false
	for i, r := range rules {
		if r.Action == Deny && HostMatches(r.Host, host) && r.matches(method, path, rawQuery) {
			return false, i
		}
	}
	for i, r := range rules {
		if r.Action != Allow || !HostMatches(r.Host, host) {
			continue
		}
		hasAllow = true
		if r.matches(method, path, rawQuery) {
			return true, i
		}
	}
	return !hasAllow, -1
}

// ParseBaseline reads the org baseline (config/egress-baseline.yaml): a "rules:" key whose list
// items are one-line JSON objects, comments and blank lines aside. Anything else, an unknown key,
// or a rule that is not a valid deny rule is an error: the baseline fails closed.
func ParseBaseline(data []byte) ([]Rule, error) {
	rules, err := ParseRules(data, "baseline", true)
	if err == nil && len(rules) == 0 {
		err = errors.New("l7: the baseline has no rules")
	}
	return rules, err
}

// ParseRules reads a rules file in the baseline's format (the overlay's and the operator's
// egress-rules.yaml); what names it in errors. denyOnly refuses allow rules. A file with no rules is
// valid.
func ParseRules(data []byte, what string, denyOnly bool) ([]Rule, error) {
	var rules []Rule
	inRules := false
	for n, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == "" || strings.HasPrefix(t, "#"):
			continue
		case t == "rules:" && line == t && !inRules:
			inRules = true
			continue
		case inRules && strings.HasPrefix(line, "  - {"):
			dec := json.NewDecoder(strings.NewReader(strings.TrimPrefix(line, "  - ")))
			dec.DisallowUnknownFields()
			var r Rule
			if err := dec.Decode(&r); err != nil || dec.More() {
				return nil, fmt.Errorf("l7: %s line %d: not one rule: %v", what, n+1, err)
			}
			if err := r.Validate(); err != nil {
				return nil, fmt.Errorf("l7: %s line %d: %w", what, n+1, err)
			}
			if denyOnly && r.Action != Deny {
				return nil, fmt.Errorf("l7: %s line %d: the %s holds deny rules only", what, n+1, what)
			}
			rules = append(rules, r)
			continue
		}
		return nil, fmt.Errorf("l7: %s line %d: unexpected %q", what, n+1, t)
	}
	return rules, nil
}
