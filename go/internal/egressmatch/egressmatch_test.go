package egressmatch

import "testing"

func TestBlocked(t *testing.T) {
	for _, c := range []struct {
		d, p string
		want bool
	}{
		{"evil.com", "*.evil.com", true}, {"a.b.evil.com", "*.evil.com", true}, {"notevil.com", "*.evil.com", false},
		{"x.pastebin.com", "*pastebin.com", true}, {"mypastebin.com", "*pastebin.com", true},
		{"ngrok", "ngrok.*", true}, {"ngrok.io", "ngrok.*", true}, {"ngrokx.io", "ngrok.*", false},
		{"exact.org", "exact.org", true}, {"sub.exact.org", "exact.org", false}, {"exact.org", "EXACT.ORG.", true},
	} {
		if Blocked(c.d, c.p) != c.want {
			t.Errorf("Blocked(%q, %q) = %v", c.d, c.p, !c.want)
		}
	}
}

func TestAllowed(t *testing.T) {
	for _, c := range []struct {
		d, e string
		want bool
	}{
		{"api.github.com", "*.github.com", true}, {"github.com", "*.github.com", false},
		{"a.b.github.com", "*.github.com", false}, {"github.com", "github.com", true},
		{"api.github.com", "github.com", false}, {"api.github.com", "*.GitHub.com.", true},
		{"xgithub.com", "*.github.com", false},
	} {
		if Allowed(c.d, c.e) != c.want {
			t.Errorf("Allowed(%q, %q) = %v", c.d, c.e, !c.want)
		}
	}
}

func TestDecide(t *testing.T) {
	allow := []string{"*.github.com", "github.com", "api.anthropic.com"}
	block := []string{"*.gist.github.com", "raw.github.com"}
	for d, want := range map[string]bool{
		"api.github.com": true, "GITHUB.COM.": true, "api.anthropic.com": true,
		"raw.github.com": false, "x.gist.github.com": false, "gist.github.com": false,
		"anthropic.com": false, "": false, "evil.com": false,
	} {
		if Decide(d, allow, block) != want {
			t.Errorf("Decide(%q) = %v", d, !want)
		}
	}
}
