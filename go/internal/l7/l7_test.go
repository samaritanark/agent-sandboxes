package l7

import (
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
		"/a#frag", "/a\x00", "/é", "/a?x=%", "/a?x=y=z"} {
		if p, err := Compile(g); err == nil {
			t.Errorf("%q compiled: %+v", g, p)
		}
	}
}

func TestQuery(t *testing.T) {
	p, err := Compile("/**/info/refs?service=git-receive-pack")
	if err != nil {
		t.Fatal(err)
	}
	for q, want := range map[string]bool{
		"service=git-receive-pack": true, "x=1&service=git-receive-pack": true, "service=git%2Dreceive-pack": true,
		"service=git-upload-pack": false, "": false, "service=git-upload-pack&service=git-receive-pack": false,
		"servic%65=git-receive-pack": true, "service=git-receive-pack2": false,
	} {
		if got := p.Matches("/o/r.git/info/refs", q); got != want {
			t.Errorf("query %q: %v", q, got)
		}
	}
	p, _ = Compile("/s?q&page=1*")
	for q, want := range map[string]bool{"q=&page=10": true, "q&page=1": true, "page=1": false, "q=x&page=2": false} {
		if got := p.Matches("/s", q); got != want {
			t.Errorf("query %q: %v", q, got)
		}
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
