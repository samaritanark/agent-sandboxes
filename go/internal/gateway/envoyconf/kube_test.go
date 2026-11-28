package envoyconf

import (
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/kubeapi"
)

func kubeCfg(t *testing.T) Config {
	dir := t.TempDir()
	name := "kube-0.gw.sandbox.internal"
	name1 := "kube-1.gw.sandbox.internal"
	ic := func(n string, k Kube) Intercept {
		return Intercept{Name: n, CertChain: filepath.Join(dir, n+".crt"), PrivateKey: filepath.Join(dir, n+".key"), Rules: kubeapi.DenyRules(n), Kube: &k}
	}
	return Config{Links: []Link{{Addr: netip.MustParseAddr("10.200.0.1"), Ports: []int{443}, Allow: []string{name, name1},
		BrokerSocket: filepath.Join(dir, "broker.sock"),
		Intercept: []Intercept{
			ic(name, Kube{Host: "10.0.0.5", Port: 6443, SNI: "10.0.0.5", CAFile: filepath.Join(dir, "kube-0.ca")}),
			ic(name1, Kube{Host: "rancher.example.com", Port: 443, PathPrefix: "/k8s/clusters/c-x", SNI: "rancher.example.com",
				ClientCert: filepath.Join(dir, "c.crt"), ClientKey: filepath.Join(dir, "c.key")}),
		}}},
		AuthzSocket: filepath.Join(dir, "authz.sock"), Resolvers: []netip.Addr{netip.MustParseAddr("192.168.127.1")},
		UpstreamCAs: "/etc/ssl/certs/ca-certificates.crt"}
}

// TestKubeBootstrap: a cluster's gateway name forwards to its own upstream (verified against its
// CA or the system roots, checked by address or name, with its client certificate), over
// HTTP/1.1 with WebSocket and SPDY upgrades, with its path prefix; the deny-list's routes refuse
// before any forward; and a cluster off the agent's link, or without its broker, is refused.
func TestKubeBootstrap(t *testing.T) {
	b, err := kubeCfg(t).Bootstrap()
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"name": "kube:kube-0.gw.sandbox.internal"`, `"type": "STATIC"`, `"address": "10.0.0.5"`, `"port_value": 6443`,
		`"san_type": "IP_ADDRESS"`, `kube-0.ca"`, `"name": "kube:kube-1.gw.sandbox.internal"`, `"type": "STRICT_DNS"`,
		`"sni": "rancher.example.com"`, `"san_type": "DNS"`, `c.crt"`, `c.key"`, `"upgrade_type": "SPDY/3.1"`,
		`"substitution": "/k8s/clusters/c-x\\1"`, `"status": 403`} {
		if !strings.Contains(s, want) {
			t.Errorf("bootstrap lacks %s", want)
		}
	}
	// each cluster's connection manager takes SPDY upgrades, not only its routes
	hcms := 0
	var walk func(any)
	walk = func(x any) {
		switch m := x.(type) {
		case map[string]any:
			if m["stat_prefix"] == "intercept" {
				hcms++
				b, _ := json.Marshal(m["upgrade_configs"])
				if !strings.Contains(string(b), "SPDY/3.1") {
					t.Errorf("a cluster's connection manager lacks SPDY: %s", b)
				}
			}
			for _, v := range m {
				walk(v)
			}
		case []any:
			for _, v := range m {
				walk(v)
			}
		}
	}
	walk(v)
	if hcms != 2 {
		t.Errorf("%d connection managers", hcms)
	}
	if strings.Contains(s, `"sni": "10.0.0.5"`) {
		t.Error("an address sent as SNI")
	}
	// the deny-list comes before the forwarding route on each cluster's name
	i0 := strings.Index(s, `"name": "deny:0"`)
	f0 := strings.Index(s, `"cluster": "kube:kube-0.gw.sandbox.internal"`)
	if i0 < 0 || f0 < 0 || i0 > f0 {
		t.Errorf("deny %d forward %d", i0, f0)
	}
	for name, f := range map[string]func(*Config){
		"no broker":     func(c *Config) { c.Links[0].BrokerSocket = "" },
		"bad port":      func(c *Config) { c.Links[0].Intercept[0].Kube.Port = 0 },
		"bad prefix":    func(c *Config) { c.Links[0].Intercept[1].Kube.PathPrefix = "k8s" },
		"cert, no key":  func(c *Config) { c.Links[0].Intercept[1].Kube.ClientKey = "" },
		"relative file": func(c *Config) { c.Links[0].Intercept[0].Kube.CAFile = "ca.pem" },
		"dependency link": func(c *Config) {
			c.Links = append(c.Links, Link{Addr: netip.MustParseAddr("10.200.1.1"), Ports: []int{443}, Allow: c.Links[0].Allow,
				BrokerSocket: c.Links[0].BrokerSocket, Intercept: c.Links[0].Intercept})
			c.Links[0].Intercept = nil
		},
	} {
		c := kubeCfg(t)
		f(&c)
		if _, err := c.Bootstrap(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
