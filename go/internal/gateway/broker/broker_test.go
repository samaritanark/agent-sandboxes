package broker

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func ph(c string) string { return "sbxph_" + strings.Repeat(c, 43) }

var (
	phGH  = ph("A")
	phAn  = ph("B")
	phQ   = ph("C")
	phB   = ph("D")
	phK   = ph("K")
	phM   = ph("M")
	phOld = ph("E")
)

func set(t *testing.T) *Set {
	s, err := NewSet([]Binding{
		{Ref: "github", Hosts: []string{"api.github.com"}, Inject: "bearer", Placeholder: phGH, Value: "ghp_realtoken1234567890"},
		{Ref: "anthropic", Hosts: []string{"api.anthropic.com"}, Inject: "header:x-api-key", Placeholder: phAn, Value: "sk-ant-real-0987654321"},
		{Ref: "maps", Hosts: []string{"maps.example.com"}, Inject: "query:key", Placeholder: phQ, Value: "AIzaReal key/+="},
		{Ref: "registry", Hosts: []string{"npm.corp.example"}, Inject: "basic", Placeholder: phB, Value: "deploy:s3cretpass"},
		{Ref: "infra.kube.0", Hosts: []string{"kube-0.gw.sandbox.internal"}, Inject: "bearer", Placeholder: phK, Value: "eyJkubetoken"},
		{Ref: "infra.kube.1", Hosts: []string{"kube-1.gw.sandbox.internal"}, Inject: "mtls", Placeholder: phM, Value: "-----BEGIN CERTIFICATE-----"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func hdr(kv ...string) []Header {
	var hs []Header
	for i := 0; i < len(kv); i += 2 {
		hs = append(hs, Header{kv[i], kv[i+1]})
	}
	return hs
}

func basic(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }

func TestDecide(t *testing.T) {
	s := set(t)
	for _, c := range []struct {
		name    string
		r       Request
		refuse  bool
		event   string
		set     string // "name=value" of the injected header
		path    string
		removed string
	}{
		{name: "bearer", r: Request{Host: "api.github.com", Path: "/user", Headers: hdr("authorization", "Bearer "+phGH)},
			set: "authorization=Bearer ghp_realtoken1234567890"},
		{name: "bearer with port, any case", r: Request{Host: "API.GitHub.com:443", Path: "/", Headers: hdr("authorization", "bearer "+phGH)},
			set: "authorization=Bearer ghp_realtoken1234567890"},
		{name: "named header", r: Request{Host: "api.anthropic.com", Path: "/v1/messages", Headers: hdr("x-api-key", phAn, "connection", "x-api-key, keep-alive", "proxy-authorization", "x")},
			set: "x-api-key=sk-ant-real-0987654321", removed: "connection,proxy-authorization"},
		{name: "query", r: Request{Host: "maps.example.com", Path: "/geo?q=a&key=" + phQ}, path: "/geo?q=a&key=AIzaReal+key%2F%2B%3D"},
		{name: "basic, user kept from the pair", r: Request{Host: "npm.corp.example", Path: "/", Headers: hdr("authorization", basic("me:"+phB))},
			set: "authorization=" + basic("deploy:s3cretpass")},
		{name: "unbound host, no placeholder", r: Request{Host: "example.org", Path: "/"}},
		{name: "a bound name on another port is another destination", r: Request{Host: "api.github.com:8443", Path: "/", Headers: hdr("authorization", "Bearer "+phGH)}, refuse: true, event: "credential_misuse"},
		{name: "bound host, no credential: relayed as it is", r: Request{Host: "api.github.com", Path: "/zen"}},
		{name: "bound host, a cookie of its own", r: Request{Host: "api.github.com", Path: "/", Headers: hdr("cookie", "s=1")}, refuse: true, event: "credential_missing"},
		{name: "bound host, an api key of its own", r: Request{Host: "api.github.com", Path: "/", Headers: hdr("x-api-key", "k")}, refuse: true, event: "credential_missing"},
		{name: "bound host, wrong bearer", r: Request{Host: "api.github.com", Path: "/", Headers: hdr("authorization", "Bearer x")}, refuse: true, event: "credential_missing"},
		{name: "placeholder toward another host", r: Request{Host: "evil.com", Path: "/", Headers: hdr("authorization", "Bearer "+phGH)}, refuse: true, event: "credential_misuse"},
		{name: "placeholder in a path", r: Request{Host: "evil.com", Path: "/x?t=" + phAn}, refuse: true, event: "credential_misuse"},
		{name: "percent-encoded placeholder", r: Request{Host: "evil.com", Path: "/x?t=" + strings.Replace(phAn, "_", "%5F", 1)}, refuse: true, event: "credential_misuse"},
		{name: "placeholder inside basic auth elsewhere", r: Request{Host: "evil.com", Path: "/", Headers: hdr("authorization", basic("u:"+phGH))}, refuse: true, event: "credential_misuse"},
		{name: "another binding's placeholder on a bound host", r: Request{Host: "api.github.com", Path: "/", Headers: hdr("authorization", "Bearer "+phGH, "x-api-key", phAn)}, refuse: true, event: "credential_misuse"},
		{name: "an unknown session placeholder", r: Request{Host: "api.github.com", Path: "/", Headers: hdr("authorization", "Bearer "+phOld)}, refuse: true, event: "credential_misuse"},
		{name: "placeholder in the wrong place", r: Request{Host: "api.github.com", Path: "/?access_token=" + phGH}, refuse: true, event: "credential_misuse"},
		{name: "two authorization headers", r: Request{Host: "api.github.com", Path: "/", Headers: hdr("authorization", "Bearer "+phGH, "authorization", "Bearer "+phGH)}, refuse: true, event: "credential_misuse"},
		{name: "query placeholder twice", r: Request{Host: "maps.example.com", Path: "/?key=" + phQ + "&key=" + phQ}, refuse: true, event: "credential_misuse"},
		{name: "a WebSocket upgrade to a bound destination", r: Request{Host: "api.github.com", Path: "/", Headers: hdr("authorization", "Bearer "+phGH, "connection", "Upgrade, x-drop", "upgrade", "websocket")},
			set: "authorization=Bearer ghp_realtoken1234567890", removed: "x-drop"},
		{name: "another upgrade to a bound destination", r: Request{Host: "api.github.com", Path: "/", Headers: hdr("authorization", "Bearer "+phGH, "connection", "upgrade", "upgrade", "h2c")}, refuse: true, event: "refused"},
		{name: "a cluster's token", r: Request{Host: "kube-0.gw.sandbox.internal", Path: "/api/v1/pods", Headers: hdr("authorization", "Bearer "+phK)},
			set: "authorization=Bearer eyJkubetoken"},
		{name: "kubectl exec over SPDY to a cluster", r: Request{Host: "kube-0.gw.sandbox.internal", Path: "/api/v1/namespaces/a/pods/p/exec", Headers: hdr("authorization", "Bearer "+phK, "connection", "Upgrade", "upgrade", "SPDY/3.1")},
			set: "authorization=Bearer eyJkubetoken"},
		{name: "SPDY elsewhere is still refused", r: Request{Host: "api.github.com", Path: "/", Headers: hdr("authorization", "Bearer "+phGH, "connection", "upgrade", "upgrade", "SPDY/3.1")}, refuse: true, event: "refused"},
		{name: "mtls: the placeholder is checked and removed", r: Request{Host: "kube-1.gw.sandbox.internal", Path: "/api", Headers: hdr("authorization", "Bearer "+phM)},
			removed: "authorization"},
		{name: "mtls: no placeholder, no client certificate", r: Request{Host: "kube-1.gw.sandbox.internal", Path: "/api", Headers: hdr("authorization", "Bearer x")}, refuse: true, event: "credential_missing"},
		{name: "mtls: the placeholder elsewhere than the bearer token", r: Request{Host: "kube-1.gw.sandbox.internal", Path: "/api", Headers: hdr("x-token", phM)}, refuse: true, event: "credential_misuse"},
		{name: "mtls: an authorization of its own beside the placeholder", r: Request{Host: "kube-1.gw.sandbox.internal", Path: "/api", Headers: hdr("authorization", "Basic eHk6eg==", "x-token", phM)}, refuse: true, event: "credential_misuse"},
		{name: "mtls: a request with no credential at all is refused", r: Request{Host: "kube-1.gw.sandbox.internal", Path: "/version"}, refuse: true, event: "credential_missing"},
		{name: "an upgrade elsewhere passes", r: Request{Host: "example.org", Path: "/", Headers: hdr("connection", "upgrade", "upgrade", "websocket")}},
		{name: "CR in a header", r: Request{Host: "example.org", Path: "/", Headers: hdr("x", "a\r\nb")}, refuse: true},
		{name: "two content lengths", r: Request{Host: "example.org", Path: "/", Headers: hdr("content-length", "1", "content-length", "2")}, refuse: true},
		{name: "length and chunked", r: Request{Host: "example.org", Path: "/", Headers: hdr("content-length", "1", "transfer-encoding", "chunked")}, refuse: true},
	} {
		o := s.Decide(c.r)
		if o.Refuse != c.refuse || o.Event != c.event {
			t.Errorf("%s: %+v", c.name, o)
			continue
		}
		var set []string
		for _, h := range o.SetHeaders {
			set = append(set, h.Name+"="+h.Value)
		}
		if strings.Join(set, ",") != c.set || o.Path != c.path || (c.removed != "" && strings.Join(o.RemoveHeaders, ",") != c.removed) {
			t.Errorf("%s: set %v path %q removed %v", c.name, set, o.Path, o.RemoveHeaders)
		}
		if strings.Contains(o.Reason, "real") || strings.Contains(o.Reason, "s3cret") {
			t.Errorf("%s: a value in the reason", c.name)
		}
	}
}

func TestNewSetRefuses(t *testing.T) {
	good := Binding{Ref: "r", Hosts: []string{"a.com"}, Inject: "bearer", Placeholder: phGH, Value: "v"}
	for name, mut := range map[string]func(*Binding){
		"wildcard host": func(b *Binding) { b.Hosts = []string{"*.a.com"} },
		"no hosts":      func(b *Binding) { b.Hosts = nil },
		"upper host":    func(b *Binding) { b.Hosts = []string{"A.com"} },
		"bad inject":    func(b *Binding) { b.Inject = "cookie" },
		"bad ph":        func(b *Binding) { b.Placeholder = "sbxph_short" },
		"no value":      func(b *Binding) { b.Value = "" },
		"CRLF value":    func(b *Binding) { b.Value = "a\r\nX-Evil: 1" },
	} {
		b := good
		mut(&b)
		if _, err := NewSet([]Binding{b}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := NewSet([]Binding{good, good}); err == nil {
		t.Error("a placeholder used twice")
	}
}

// TestScrubberSplits feeds a body in every pair of chunk sizes: no value survives a split, the
// output is the input with values replaced, and nothing is held back that cannot start a value.
func TestScrubberSplits(t *testing.T) {
	s := set(t)
	reps := s.Reflections()
	body := `{"echo":"ghp_realtoken1234567890","b64":"` + base64.StdEncoding.EncodeToString([]byte("sk-ant-real-0987654321")) +
		`","q":"AIzaReal+key%2F%2B%3D","basic":"Basic ZGVwbG95OnMzY3JldHBhc3M=","tail":"ghp_realtoken12"}`
	want := `{"echo":"` + phGH + `","b64":"` + phAn + `","q":"` + phQ + `","basic":"Basic ` + phB + `","tail":"ghp_realtoken12"}`
	for a := 1; a < len(body); a += 3 {
		for b := 1; b < 40; b += 7 {
			sc := NewScrubber(reps)
			var out []byte
			for i, n := 0, a; i < len(body); n = b {
				end := min(i+n, len(body))
				out = append(out, sc.Write([]byte(body[i:end]))...)
				i = end
			}
			out = append(out, sc.Close()...)
			if string(out) != want {
				t.Fatalf("chunks %d/%d:\n%s\nwant\n%s", a, b, out, want)
			}
			if sc.Hits != 4 {
				t.Fatalf("hits %d", sc.Hits)
			}
		}
	}
}

// TestScrubberNoDelay: a chunk that cannot begin a value passes at once, whole.
func TestScrubberNoDelay(t *testing.T) {
	sc := NewScrubber(set(t).Reflections())
	for _, ev := range []string{"data: one\n\n", "data: two\n\n", "data: g"} {
		got := sc.Write([]byte(ev))
		if ev == "data: g" {
			if string(got) != "data: " {
				t.Errorf("held %q", got)
			}
			continue
		}
		if string(got) != ev {
			t.Errorf("event %q delayed: %q", ev, got)
		}
	}
	if got := sc.Close(); !bytes.Equal(got, []byte("g")) {
		t.Errorf("close %q", got)
	}
	if v := sc.String("Location: https://x/?key=AIzaReal+key%2F%2B%3D"); strings.Contains(v, "AIza") {
		t.Errorf("header %q", v)
	}
}

// TestScrubberEndsOnShorterForm: a stream that ends with the unpadded base64 form (a prefix of
// the padded one) is still scrubbed.
func TestScrubberEndsOnShorterForm(t *testing.T) {
	raw := base64.RawStdEncoding.EncodeToString([]byte("sk-ant-real-0987654321"))
	sc := NewScrubber(set(t).Reflections())
	out := append(sc.Write([]byte("x "+raw)), sc.Close()...)
	if string(out) != "x "+phAn {
		t.Errorf("%q", out)
	}
}

// TestScrubberAlphabets: a value whose base64 uses "+" and "/" is caught in the unpadded standard
// form too, which the URL-safe forms do not cover.
func TestScrubberAlphabets(t *testing.T) {
	v := "k???>>>-123456" // 14 bytes: padded, and "/" and "+" in its base64
	s, _ := NewSet([]Binding{{Ref: "x", Hosts: []string{"a.com"}, Inject: "bearer", Placeholder: phGH, Value: v}})
	raw := base64.RawStdEncoding.EncodeToString([]byte(v))
	if !strings.ContainsAny(raw, "+/") || raw == base64.StdEncoding.EncodeToString([]byte(v)) {
		t.Fatal("the test value does not exercise the alphabet")
	}
	sc := NewScrubber(s.Reflections())
	if out := append(sc.Write([]byte("y "+raw)), sc.Close()...); string(out) != "y "+phGH {
		t.Errorf("%q", out)
	}
}

// TestScrubberCompleteAtChunkEnd: a value that ends exactly where a chunk ends goes out with that
// chunk, scrubbed, not held for the next one.
func TestScrubberCompleteAtChunkEnd(t *testing.T) {
	sc := NewScrubber(set(t).Reflections())
	if out := sc.Write([]byte("x ghp_realtoken1234567890")); string(out) != "x "+phGH {
		t.Errorf("%q", out)
	}
}

// TestPrefixedPlaceholder: a bearer credential the guest presents as a prefix and the placeholder
// (a JWT-shaped token whose signature is the placeholder) is replaced whole; the bare placeholder,
// another prefix, or the prefix on a non-bearer binding is not.
func TestPrefixedPlaceholder(t *testing.T) {
	jwt := "eyJhbGciOiJub25lIn0.eyJleHAiOjE4MDAwMDAwMDB9."
	s, err := NewSet([]Binding{{Ref: "agent.codex", Hosts: []string{"chatgpt.com"}, Inject: "bearer", Placeholder: phGH, Prefix: jwt, Value: "real.jwt.value"}})
	if err != nil {
		t.Fatal(err)
	}
	o := s.Decide(Request{Host: "chatgpt.com", Path: "/backend-api/codex/responses", Headers: []Header{{"authorization", "Bearer " + jwt + phGH}}})
	if !o.Injected || len(o.SetHeaders) != 1 || o.SetHeaders[0].Value != "Bearer real.jwt.value" {
		t.Fatalf("%+v", o)
	}
	for _, v := range []string{"Bearer " + phGH, "Bearer x." + jwt + phGH, "Bearer at-" + phGH} {
		if o := s.Decide(Request{Host: "chatgpt.com", Path: "/", Headers: []Header{{"authorization", v}}}); !o.Refuse {
			t.Errorf("%q: %+v", v, o)
		}
	}
	for _, b := range []Binding{
		{Ref: "x", Hosts: []string{"a.com"}, Inject: "header:x-key", Placeholder: phGH, Prefix: "at-", Value: "v"},
		{Ref: "x", Hosts: []string{"a.com"}, Inject: "bearer", Placeholder: phGH, Prefix: "a b", Value: "v"},
	} {
		if _, err := NewSet([]Binding{b}); err == nil {
			t.Errorf("%+v accepted", b)
		}
	}
}
