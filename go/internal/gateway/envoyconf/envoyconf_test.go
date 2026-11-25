package envoyconf

import (
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func cfg(t *testing.T) Config {
	dir := t.TempDir()
	return Config{Allow: []string{"*.github.com", "api.anthropic.com"}, BlockDomains: []string{"*.gist.github.com"},
		Listen: netip.MustParseAddr("10.200.0.1"), Ports: []int{443, 6443},
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
		`"address": "192.168.127.1"`, "authz.sock", `"use_resolvers_as_fallback": false`, `"include_tls_session": true`} {
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
		func(c *Config) { c.Ports = nil },
		func(c *Config) { c.Ports = []int{443, 443} },
		func(c *Config) { c.Resolvers = nil },
		func(c *Config) { c.AuthzSocket = "authz.sock" },
		func(c *Config) { c.Listen = netip.Addr{} },
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
	b, _ := cfg(t).Bootstrap()
	p := filepath.Join(t.TempDir(), "envoy.json")
	os.WriteFile(p, b, 0o600)
	out, err := exec.Command(envoy, "--mode", "validate", "-c", p).CombinedOutput()
	if err != nil {
		t.Fatalf("envoy rejects the bootstrap: %v\n%s", err, out)
	}
}

func TestServerNames(t *testing.T) {
	allow, deny := ServerNames(
		[]string{"*.github.com", "github.com", "api.anthropic.com", "*.pastebin.com", "*.example.org", "blocked.net", "*.corp.com"},
		[]string{"*.gist.github.com", "raw.github.com", "*pastebin.com", "blocked.net", "ngrok.example.org.*", "*.deep.a.corp.com"})
	wantA := "*.github.com github.com api.anthropic.com *.example.org *.corp.com"
	wantD := "gist.github.com raw.github.com"
	if got := strings.Join(allow, " "); got != wantA {
		t.Errorf("allow %q, want %q", got, wantA)
	}
	// ngrok.example.org is a single-label child too
	if got := strings.Join(deny, " "); got != wantD+" ngrok.example.org" {
		t.Errorf("deny %q", got)
	}
}
