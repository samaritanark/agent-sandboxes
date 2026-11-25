package l7

import (
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
)

// globSeg matches one segment glob ("*" within the segment) directly, without regular expressions.
func globSeg(p, s string) bool {
	if p == "" {
		return s == ""
	}
	if p[0] == '*' {
		for i := 0; i <= len(s); i++ {
			if globSeg(p[1:], s[i:]) {
				return true
			}
		}
		return false
	}
	return s != "" && p[0] == s[0] && globSeg(p[1:], s[1:])
}

// globPath is the reference matcher for a pattern's path part over "/"-split segments.
func globPath(ps, ss []string) bool {
	if len(ps) == 0 {
		return len(ss) == 0
	}
	if ps[0] == "**" {
		for i := 0; i <= len(ss); i++ {
			if globPath(ps[1:], ss[i:]) {
				return true
			}
		}
		return false
	}
	return len(ss) > 0 && globSeg(ps[0], ss[0]) && globPath(ps[1:], ss[1:])
}

func reference(glob, path string) bool {
	gp, _, _ := strings.Cut(glob, "?")
	return strings.HasPrefix(path, "/") && globPath(strings.Split(gp, "/")[1:], strings.Split(path, "/")[1:])
}

var globs = []string{
	"/", "/a", "/a/", "/a/*", "/a/*/b", "/a/**", "/a/**/b", "/**", "/**/git-receive-pack", "/*.git/info/refs",
	"/v1/models/*:generate", "/a/x*y/**/c*", "/-/user/**", "/a.b+c(d)/$x", "/**/**/z",
}

var paths = []string{
	"/", "/a", "/a/", "/a/b", "/a/b/", "/a/x/b", "/a/x/y/b", "/a/xb", "/ab", "/b", "/a/b/c", "/repo.git/git-receive-pack",
	"/o/r.git/git-receive-pack", "/git-receive-pack", "/git-receive-packs", "/r.git/info/refs", "/x/r.git/info/refs",
	"/v1/models/gemini:generate", "/v1/models/a/b:generate", "/a/xy/c", "/a/xzy/q/r/cat", "/a/xy/c/", "/-/user/org.couchdb.user:x",
	"/a.b+c(d)/$x", "/aXb+c(d)/$x", "/z", "/q/z", "/q/r/z", "/a//b", "*", // Envoy paths start with "/", or are "*" (OPTIONS)
}

func TestCompiledMatchesReference(t *testing.T) {
	for _, g := range globs {
		p, err := Compile(g)
		if err != nil {
			t.Fatalf("%q: %v", g, err)
		}
		for _, path := range paths {
			if got, want := p.Matches(path, ""), reference(g, path); got != want {
				t.Errorf("%q on %q: compiled %v (%s), reference %v", g, path, got, p.PathRegex, want)
			}
		}
	}
}

func TestCompileRefuses(t *testing.T) {
	for _, g := range []string{"", "a", "/a b", "/a**", "/a/**b", "/***", "/a//b", "/a?", "/a?=x", "/a?x&x", "/a?x=a b",
		"/a#frag", "/a\x00", "/é", "/a?x=%", "/a?x=y=z", "/a?x=a+b", "/" + strings.Repeat("a", MaxPatternLen)} {
		if p, err := Compile(g); err == nil {
			t.Errorf("%q compiled: %+v", g, p)
		}
	}
}

// queryRef is the reference for a pattern's query part: each condition holds when some parameter's
// percent-decoded name is the condition's and, with a value, its decoded value matches the glob.
func queryRef(glob, rawQuery string) bool {
	_, query, ok := strings.Cut(glob, "?")
	if !ok {
		return true
	}
	for _, c := range strings.Split(query, "&") {
		name, value, hasValue := strings.Cut(c, "=")
		held := false
		for _, kv := range strings.Split(rawQuery, "&") {
			k, v, _ := strings.Cut(kv, "=")
			dk, err := url.QueryUnescape(k)
			if err != nil || dk != name {
				continue
			}
			dv, err := url.QueryUnescape(v)
			if err != nil {
				dv = v
			}
			held = held || !hasValue || globSeg(value, dv)
		}
		if !held {
			return false
		}
	}
	return true
}

func TestQuery(t *testing.T) {
	queryGlobs := []string{"/r?service=git-receive-pack", "/r?q&page=1*", "/r?a=*x*", "/r?a=", "/r?a.b~c=d/e:f"}
	queries := []string{"", "service=git-receive-pack", "x=1&service=git-receive-pack", "service=git%2Dreceive-pack",
		"service=git%2dreceive-pack", "servic%65=git-receive-pack", "service=git-upload-pack", "service=git-receive-pack2",
		"service=git-upload-pack&service=git-receive-pack", "service=git-receive-pack&service=git-upload-pack", "xservice=git-receive-pack",
		"service=git-receive-pac%6B&z", "service=git%zzreceive-pack", "q=&page=10", "q&page=1", "page=1", "q=x&page=2", "a=x", "a=yxz",
		"a=", "a", "a=%78", "a=b&a=", "a.b~c=d/e:f", "a.b~c=d%2Fe%3Af", "a%2Eb~c=d/e:f", "a+b=x", "a=x+", "service=git-receive-pack#x", "a=y&b=x", "a=&x"}
	for _, g := range queryGlobs {
		p, err := Compile(g)
		if err != nil {
			t.Fatalf("%q: %v", g, err)
		}
		for _, q := range queries {
			if got, want := p.Matches("/r", q), queryRef(g, q); got != want {
				t.Errorf("%q on %q: compiled %v, reference %v", g, q, got, want)
			}
			for _, c := range p.Query {
				raw := regexp.MustCompile(c.RawRegex).MatchString(q)
				if full := regexp.MustCompile(c.QueryPathRegex()).MatchString("/r/x?" + q); full != raw {
					t.Errorf("%q on %q: the :path form says %v", g, q, full)
				}
			}
		}
	}
	if err := (Rule{Host: "x.com", Action: Allow, PathPatterns: []string{"/a?b=c"}}).Validate(); err == nil {
		t.Error("an allow rule with a query part")
	}
}

func TestValidate(t *testing.T) {
	good := []Rule{
		{Host: "api.github.com", Methods: []string{"GET", "HEAD"}, PathPatterns: []string{"/repos/**"}, Action: Allow},
		{Host: AnyHost, Methods: []string{"TRACE"}, Action: Deny},
		{Host: "*.npmjs.org", Action: Deny, Methods: []string{"PUT", "DELETE"}},
	}
	for _, r := range good {
		if err := r.Validate(); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	for _, r := range []Rule{
		{Host: "x.com", Action: "permit"}, {Host: "", Action: Deny}, {Host: AnyHost, Action: Allow},
		{Host: "x.com", Action: Deny, Methods: []string{"get"}}, {Host: "x.com", Action: Deny, Methods: []string{""}},
		{Host: "x.com", Action: Deny, PathPatterns: []string{"repos"}},
	} {
		if err := r.Validate(); err == nil {
			t.Errorf("%+v accepted", r)
		}
	}
}

func TestDecide(t *testing.T) {
	rules := []Rule{
		{Host: AnyHost, Methods: []string{"POST"}, PathPatterns: []string{"/**/git-receive-pack"}, Action: Deny},
		{Host: AnyHost, Methods: []string{"GET"}, PathPatterns: []string{"/**/info/refs?service=git-receive-pack"}, Action: Deny},
		{Host: AnyHost, Methods: []string{"TRACE", "TRACK"}, Action: Deny},
		{Host: "api.github.com", Methods: []string{"GET"}, PathPatterns: []string{"/repos/**", "/user"}, Action: Allow},
		{Host: "api.github.com", Methods: []string{"POST"}, PathPatterns: []string{"/repos/*/*/issues"}, Action: Allow},
		{Host: "*.example.com", Methods: []string{"DELETE"}, Action: Deny},
	}
	for _, c := range []struct {
		host, method, path, query string
		want                      bool
		rule                      int
	}{
		{"github.com", "POST", "/o/r.git/git-receive-pack", "", false, 0},
		{"github.com", "POST", "/o/r.git/git-upload-pack", "", true, -1},
		{"github.com", "GET", "/o/r.git/info/refs", "service=git-receive-pack", false, 1},
		{"github.com", "GET", "/o/r.git/info/refs", "service=git-upload-pack", true, -1},
		{"anything.org", "TRACE", "/", "", false, 2},
		{"api.github.com", "GET", "/repos/o/r/pulls", "", true, 3},
		{"API.GitHub.com.", "GET", "/user", "", true, 3},
		{"api.github.com", "GET", "/users/x", "", false, -1},
		{"api.github.com", "POST", "/repos/o/r/issues", "", true, 4},
		{"api.github.com", "POST", "/repos/o/r/git-receive-pack", "", false, 0},
		{"api.github.com", "DELETE", "/repos/o/r", "", false, -1},
		{"a.example.com", "DELETE", "/x", "", false, 5},
		{"a.example.com", "PUT", "/x", "", true, -1},
		{"example.com", "DELETE", "/x", "", true, -1},
	} {
		got, rule := Decide(rules, c.host, c.method, c.path, c.query)
		if got != c.want || rule != c.rule {
			t.Errorf("%s %s %s?%s: %v by %d, want %v by %d", c.host, c.method, c.path, c.query, got, rule, c.want, c.rule)
		}
	}
}

func TestShippedBaseline(t *testing.T) {
	data, err := os.ReadFile("../../../config/egress-baseline.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := ParseBaseline(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		host, method, target string
		want                 bool
	}{
		{"github.com", "POST", "/o/r.git/git-receive-pack", false},
		{"github.com", "POST", "/o/r/git-receive-pack", false},
		{"gitlab.example.com", "GET", "/g/sub/r.git/info/refs?service=git-receive-pack", false},
		{"github.com", "GET", "/o/r.git/info/refs?service=git-upload-pack", true},
		{"github.com", "POST", "/o/r.git/git-upload-pack", true},
		{"api.anthropic.com", "TRACE", "/", false},
		{"api.anthropic.com", "POST", "/v1/messages", true},
		{"ghcr.io", "POST", "/v2/o/img/blobs/uploads/", false},
		{"ghcr.io", "PUT", "/v2/o/img/manifests/latest", false},
		{"ghcr.io", "PATCH", "/v2/o/img/blobs/uploads/abc", false},
		{"ghcr.io", "GET", "/v2/o/img/manifests/latest", true},
		{"registry.npmjs.org", "PUT", "/left-pad", false},
		{"registry.npmjs.org", "DELETE", "/left-pad/-rev/3-abc", false},
		{"registry.npmjs.org", "GET", "/left-pad", true},
		{"upload.pypi.org", "POST", "/legacy/", false},
		{"pypi.internal.example", "POST", "/legacy/", false},
		{"pypi.org", "GET", "/simple/requests/", true},
		{"crates.io", "PUT", "/api/v1/crates/new", false},
		{"rubygems.org", "POST", "/api/v1/gems", false},
		{"api.github.com", "GET", "/repos/o/r", true},
	} {
		path, q, _ := strings.Cut(c.target, "?")
		if got, i := Decide(rules, c.host, c.method, path, q); got != c.want {
			t.Errorf("%s %s %s: %v (rule %d)", c.method, c.host, c.target, got, i)
		}
	}
}

func TestParseBaselineRefuses(t *testing.T) {
	for _, b := range []string{
		"", "# only a comment\n", "rules:\n", "other:\n  - x\n",
		"rules:\n  - {\"host\": \"*\", \"action\": \"allow\"}\n",
		"rules:\n  - {\"host\": \"x.com\", \"action\": \"allow\"}\n",
		"rules:\n  - {\"host\": \"*\", \"action\": \"deny\", \"extra\": 1}\n",
		"rules:\n  - {\"host\": \"*\", \"action\": \"deny\"} {\"host\": \"*\", \"action\": \"deny\"}\n",
		"rules:\n  - {\"host\": \"*\", \"action\": \"deny\"}\nmore: 1\n",
		"rules:\n  - {\"host\": \"*\", \"action\": \"deny\", \"path_patterns\": [\"x\"]}\n",
		"rules:\n  - host: \"*\"\n",
	} {
		if r, err := ParseBaseline([]byte(b)); err == nil {
			t.Errorf("%q parsed: %+v", b, r)
		}
	}
}
