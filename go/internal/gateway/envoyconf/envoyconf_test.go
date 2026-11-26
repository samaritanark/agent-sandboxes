package envoyconf

import (
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/egressmatch"
	"github.com/samaritanark/agent-sandboxes/go/internal/l7"
)

func cfg(t *testing.T) Config {
	dir := t.TempDir()
	return Config{Links: []Link{
		{Addr: netip.MustParseAddr("10.200.0.1"), Ports: []int{443, 6443}, Allow: []string{"*.github.com", "api.anthropic.com"}, BlockDomains: []string{"*.gist.github.com"}},
		// a long single-label wildcard: its regex must stay inside Envoy's RE2 program size limit
		{Addr: netip.MustParseAddr("10.200.1.1"), Ports: []int{443}, Allow: []string{"registry.npmjs.org", "*." + strings.Repeat(strings.Repeat("a", 63)+".", 3) + "com"}},
	},
		Deps:        []Dep{{Name: "db", Port: 5432, Addr: netip.MustParseAddr("10.200.1.2")}},
		AuthzSocket: filepath.Join(dir, "authz.sock"), AdminSocket: filepath.Join(dir, "admin.sock"),
		Resolvers: []netip.Addr{netip.MustParseAddr("192.168.127.1")}, AccessLog: filepath.Join(dir, "conn.log")}
}

func TestBootstrap(t *testing.T) {
	b, err := cfg(t).Bootstrap()
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"failure_mode_allow": false`, `"port_value": 6443`, "tls_inspector",
		"sni_dynamic_forward_proxy", "envoy.clusters.dynamic_forward_proxy", `"address": "10.200.0.1"`,
		`"address": "192.168.127.1"`, "authz.sock", `"use_resolvers_as_fallback": false`, `"include_tls_session": true`,
		`"name": "dep_db"`, `"address": "10.200.1.2"`, `"port_value": 5432`, `"address": "10.200.1.1"`, "registry.npmjs.org"} {
		if !strings.Contains(s, want) {
			t.Errorf("bootstrap lacks %s", want)
		}
	}
	for _, bad := range []string{"0.0.0.0", "http_connection_manager", "failure_mode_allow\": true"} {
		if strings.Contains(s, bad) {
			t.Errorf("bootstrap has %s", bad)
		}
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	for _, c := range []func(*Config){
		func(c *Config) { c.Links[0].Ports = nil },
		func(c *Config) { c.Links[0].Ports = []int{443, 443} },
		func(c *Config) { c.Resolvers = nil },
		func(c *Config) { c.AuthzSocket = "authz.sock" },
		func(c *Config) { c.Links[0].Addr = netip.Addr{} },
		func(c *Config) { c.Links = nil },
		func(c *Config) { c.Deps[0].Port = 443 },
		func(c *Config) { c.Deps = append(c.Deps, Dep{Name: "db2", Port: 5432, Addr: c.Deps[0].Addr}) },
	} {
		x := cfg(t)
		c(&x)
		if _, err := x.Bootstrap(); err == nil {
			t.Error("a bad config was accepted")
		}
	}
}

// TestEnvoyAccepts runs Envoy's own validation when an Envoy binary is given (ENVOY=path).
func TestEnvoyAccepts(t *testing.T) {
	envoy := os.Getenv("ENVOY")
	if envoy == "" {
		t.Skip("set ENVOY to an envoy binary to validate the bootstrap")
	}
	c := cfg(t)
	// interception, with patterns at the longest l7 accepts: their regexes must fit Envoy's limit
	dir := t.TempDir()
	testCA(t, dir, "api.anthropic.com")
	long := "/" + strings.Repeat("a", 60) + "?" + strings.Repeat("n", 60) + "=" + strings.Repeat("v-", 38) + "x"
	c.UpstreamCAs = filepath.Join(dir, "ca.pem")
	c.Links[0].Intercept = []Intercept{{Name: "api.anthropic.com", CertChain: filepath.Join(dir, "api.anthropic.com.crt"),
		PrivateKey: filepath.Join(dir, "api.anthropic.com.key"), Rules: []l7.Rule{
			{Host: "*", Methods: []string{"POST"}, PathPatterns: []string{long}, Action: l7.Deny},
			{Host: "api.anthropic.com", Methods: []string{"POST"}, PathPatterns: []string{"/v1/**"}, Action: l7.Allow}}}}
	b, err := c.Bootstrap()
	if err != nil || len(long) != l7.MaxPatternLen {
		t.Fatal(err, len(long))
	}
	p := filepath.Join(t.TempDir(), "envoy.json")
	os.WriteFile(p, b, 0o600)
	out, err := exec.Command(envoy, "--mode", "validate", "-c", p).CombinedOutput()
	if err != nil {
		t.Fatalf("envoy rejects the bootstrap: %v\n%s", err, out)
	}
}

// eval applies a predicate as Envoy's matcher does: StringMatcher with ignore_case, RE2 regexes.
func eval(t *testing.T, p obj, sni string) bool {
	switch {
	case p["single_predicate"] != nil:
		m := p["single_predicate"].(obj)["value_match"].(obj)
		s := sni
		if m["ignore_case"] == true {
			s = strings.ToLower(s)
		}
		switch {
		case m["exact"] != nil:
			return s == m["exact"]
		case m["suffix"] != nil:
			return strings.HasSuffix(s, m["suffix"].(string))
		case m["prefix"] != nil:
			return strings.HasPrefix(s, m["prefix"].(string))
		case m["safe_regex"] != nil:
			return regexp.MustCompile(m["safe_regex"].(obj)["regex"].(string)).MatchString(s)
		}
	case p["and_matcher"] != nil:
		for _, q := range p["and_matcher"].(obj)["predicate"].([]obj) {
			if !eval(t, q, sni) {
				return false
			}
		}
		return true
	case p["not_matcher"] != nil:
		return !eval(t, p["not_matcher"].(obj), sni)
	}
	t.Fatalf("unknown predicate %v", p)
	return false
}

// TestChainMatcher checks the Envoy matcher against egressmatch, the rules the check and the
// resolver use: a name reaches the "allowed" chain exactly when egressmatch.Decide allows it.
func TestChainMatcher(t *testing.T) {
	allow := []string{"*.github.com", "github.com", "api.anthropic.com", "*.pastebin.com", "**.example.org", "blocked.net", "**.corp.com", "*.a-b.io"}
	block := []string{"*.gist.github.com", "raw.github.com", "*pastebin.com", "blocked.net", "ngrok.example.org.*", "*.deep.a.corp.com", "*-evil.corp.com", "Upper.Example.org."}
	m := chainMatcher(allow, block, nil)
	names := []string{"", ".", "github.com", "api.github.com", "a.b.github.com", "gist.github.com", "x.gist.github.com", "raw.github.com",
		"RAW.GitHub.com", "API.GITHUB.COM", "xgithub.com", "api.anthropic.com", "anthropic.com", "x.pastebin.com", "pastebin.com",
		"example.org", "a.example.org", "a.b.c.example.org", "ngrok.example.org", "ngrok.example.org.x", "ngrok.example.orgx",
		"upper.example.org", "x.upper.example.org", ".example.org", "blocked.net", "corp.com", "x.corp.com", "deep.a.corp.com",
		"x.deep.a.corp.com", "a.corp.com", "z.y-evil.corp.com", "y-evil.corp.com", "x.a-b.io", "x.aab.io", "x.y.a-b.io", "evil.com",
		"github.com.evil.com", "10.0.0.1"}
	for _, n := range names {
		got := ""
		for _, fm := range m["matcher_list"].(obj)["matchers"].([]obj) {
			if eval(t, fm["predicate"].(obj), n) {
				got = fm["on_match"].(obj)["action"].(obj)["name"].(string)
				break
			}
		}
		if want := egressmatch.Decide(n, allow, block); (got == "allowed") != want {
			t.Errorf("%q: chain %q, egressmatch allows: %v", n, got, want)
		}
		blocked := false
		for _, b := range block {
			blocked = blocked || egressmatch.Blocked(egressmatch.Normalize(n), b)
		}
		if blocked != (got == "blocked") && n != "" {
			t.Errorf("%q: chain %q, blocked %v", n, got, blocked)
		}
	}
	if chainMatcher(nil, block, nil) != nil || chainMatcher([]string{""}, nil, nil) != nil {
		t.Error("a matcher with nothing allowed")
	}
}

// TestUpgradeCluster: upgrades leave by a cluster that offers HTTP/1.1 alone (an upgrade on an
// HTTP/2 connection needs extended CONNECT, which many servers lack), and every forwarding route
// has its upgrade twin first.
func TestUpgradeCluster(t *testing.T) {
	c := Config{UpstreamCAs: "/ca.pem"}
	for _, up := range []bool{false, true} {
		b, _ := json.Marshal(c.interceptedUpstream(5, up))
		s := string(b)
		h1only := strings.Contains(s, `"alpn_protocols":["http/1.1"]`) && strings.Contains(s, "explicit_http_config") && !strings.Contains(s, "http2")
		if h1only != up {
			t.Errorf("upgrades=%v: %s", up, s)
		}
	}
	rs, err := routes([]l7.Rule{{Host: "x.example", PathPatterns: []string{"/a/**"}, Action: l7.Allow}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(rs)
	if n := strings.Count(string(b), `"cluster":"`+upgradeCluster+`"`); n != 1 || !strings.Contains(string(b), `"name":"upgrade","present_match":true`) {
		t.Errorf("%d upgrade routes: %s", n, b)
	}
	if i, j := strings.Index(string(b), upgradeCluster), strings.Index(string(b), `"cluster":"`+interceptCluster+`"`); i < 0 || j < 0 || i > j {
		t.Error("the upgrade route is not first")
	}
}

// TestSDSSecret: the leaf is reloaded on a move in the SDS file's directory, not in its own
// (behind the symlink a renewal swaps).
func TestSDSSecret(t *testing.T) {
	ic := Intercept{Name: "a.example", CertChain: "/g/tls/live/0.crt", PrivateKey: "/g/tls/live/0.key", SDS: "/g/tls/0.sds.json"}
	b, err := SDSSecret(ic)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Resources []struct {
			Name           string `json:"name"`
			TLSCertificate struct {
				Watched struct{ Path string } `json:"watched_directory"`
			} `json:"tls_certificate"`
		}
	}
	if err := json.Unmarshal(b, &v); err != nil || len(v.Resources) != 1 || v.Resources[0].TLSCertificate.Watched.Path != "/g/tls" || v.Resources[0].Name != "leaf:a.example" {
		t.Errorf("%s", b)
	}
	ctx, _ := json.Marshal(leafContext(ic))
	if !strings.Contains(string(ctx), `"watched_directory":{"path":"/g/tls"}`) || !strings.Contains(string(ctx), `"name":"leaf:a.example"`) || strings.Contains(string(ctx), "tls_certificates") {
		t.Errorf("%s", ctx)
	}
}
