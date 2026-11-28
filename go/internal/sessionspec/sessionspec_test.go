package sessionspec

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

const (
	digest = "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	ph1    = "sbxph_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	ph2    = "sbxph_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	ws     = WorkspaceStore + "/0123456789abcdef"
)

func good() *Spec {
	return &Spec{
		Version: Version, ID: "s-20261125-ab12", Name: "fix-login", Agent: "claude", Tier: 2,
		Image: "ghcr.io/example/agent" + digest, Command: []string{"claude"},
		Resources: Resources{CPUs: 4, MemoryMiB: 6144, EphemeralGiB: 20},
		Mounts: []Mount{
			{Kind: Workspace, Source: ws, Target: "/home/agent/workspace"},
			{Kind: ReadOnly, Source: ws + "/.git/config", Target: "/home/agent/workspace/.git/config", ReadOnly: true},
			{Kind: MaskFile, Target: "/home/agent/workspace/.env"},
			{Kind: MaskDir, Target: "/home/agent/workspace/secrets"},
			{Kind: History, Source: SessionStore + "/s-20261125-ab12/history", Target: "/home/agent/.claude"},
			{Kind: CABundle, Source: SessionStore + "/s-20261125-ab12/ca.pem", Target: "/etc/ssl/sandbox-ca.pem", ReadOnly: true},
		},
		Env: []EnvVar{{"TERM", "xterm-256color"}, {"ANTHROPIC_API_KEY", ph1}},
		Egress: Egress{Allow: []string{"api.anthropic.com", "*.github.com", "**.googleapis.com"}, BlockCIDRs: []string{"169.254.0.0/16"},
			BlockDomains: []string{"*.gist.github.com", "*pastebin.com", "ngrok.*", "raw.github.com"},
			L7: []L7Rule{{Host: "api.github.com", Methods: []string{"GET"}, PathPatterns: []string{"/repos/**"}, Action: "allow"},
				{Host: "*", Methods: []string{"TRACE"}, Action: "deny"}},
			HostEndpoints: []HostEndpoint{{"192.168.1.10", 6443}}, ExtraPorts: []int{8443}},
		Bindings: []Binding{{Ref: "anthropic", Hosts: []string{"api.anthropic.com"}, Inject: "header:x-api-key", Placeholder: ph1, EnvVar: "ANTHROPIC_API_KEY"}},
		Readable: []Readable{{Ref: "npm-token", EnvVar: "NPM_TOKEN"}},
		Dependencies: []Dependency{{Name: "postgres", Image: "docker.io/library/postgres" + digest, Port: 5432, RunAsUser: 999,
			Env: []EnvVar{{"POSTGRES_PASSWORD", ph2}}, Resources: Resources{CPUs: 1, MemoryMiB: 1024},
			Bindings: []Binding{{Ref: "pg", Hosts: []string{"db.internal"}, Inject: "basic", Placeholder: ph2, EnvVar: "POSTGRES_PASSWORD"}},
			Egress:   Egress{Allow: []string{"db.internal"}}}},
		KeepAlive: false, Audit: map[string]string{"profile": "default"},
	}
}

func TestGoodSpecRoundTrips(t *testing.T) {
	s := good()
	if err := s.Validate(Options{}); err != nil {
		t.Fatal(err)
	}
	b, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := back.Encode()
	if !bytes.Equal(b, b2) {
		t.Errorf("round trip differs:\n%s\n%s", b, b2)
	}
}

// TestRuntimes: a spec may name either runtime, or none (Kata).
func TestRuntimes(t *testing.T) {
	for _, rt := range []string{"", RuntimeKata, RuntimeGVisor} {
		s := good()
		s.Runtime = rt
		if err := s.Validate(Options{}); err != nil {
			t.Errorf("%q: %v", rt, err)
		}
	}
}

func TestDecodeIsStrict(t *testing.T) {
	b, _ := good().Encode()
	cases := map[string]string{
		"privileged":            strings.Replace(string(b), `"tier":2`, `"tier":2,"privileged":true`, 1),
		"capabilities":          strings.Replace(string(b), `"tier":2`, `"tier":2,"cap_add":["SYS_ADMIN"]`, 1),
		"dependency mount":      strings.Replace(string(b), `"name":"postgres"`, `"name":"postgres","mounts":[{"kind":"workspace","source":"/","target":"/x"}]`, 1),
		"trailing data":         string(b) + `{}`,
		"old version":           strings.Replace(string(b), `"version":1`, `"version":0`, 1),
		"env value as a number": strings.Replace(string(b), `"value":"xterm-256color"`, `"value":1`, 1),
	}
	for name, in := range cases {
		if _, err := Decode(strings.NewReader(in)); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}

func refusalCases() map[string]func(*Spec) {
	return map[string]func(*Spec){
		"unpinned image":            func(s *Spec) { s.Image = "ghcr.io/example/agent:latest" },
		"dependency unpinned image": func(s *Spec) { s.Dependencies[0].Image = "postgres:16" },
		"bad id":                    func(s *Spec) { s.ID = "../x" },
		"tier 4":                    func(s *Spec) { s.Tier = 4 },
		"unknown runtime":           func(s *Spec) { s.Runtime = "runc" },
		"zero memory":               func(s *Spec) { s.Resources.MemoryMiB = 0 },
		"workspace outside store":   func(s *Spec) { s.Mounts[0].Source = "/etc" },
		"workspace traversal":       func(s *Spec) { s.Mounts[0].Source = ws + "/../../../etc" },
		"host root":                 func(s *Spec) { s.Mounts[0].Source = "/" },
		"readonly not read-only":    func(s *Spec) { s.Mounts[1].ReadOnly = false },
		"mask outside workspace":    func(s *Spec) { s.Mounts[2].Target = "/etc/passwd" },
		"mask with a source":        func(s *Spec) { s.Mounts[2].Source = ws },
		"other session's history":   func(s *Spec) { s.Mounts[4].Source = SessionStore + "/other-session/history" },
		"session dir itself":        func(s *Spec) { s.Mounts[4].Source = SessionStore + "/s-20261125-ab12" },
		"writable CA":               func(s *Spec) { s.Mounts[5].ReadOnly = false },
		"proc target":               func(s *Spec) { s.Mounts[3].Target = "/proc/sys" },
		"root target":               func(s *Spec) { s.Mounts[0].Target = "/" },
		"duplicate target":          func(s *Spec) { s.Mounts[3].Target = s.Mounts[2].Target },
		"unknown mount kind":        func(s *Spec) { s.Mounts[0].Kind = "hostpath" },
		"credential in env":         func(s *Spec) { s.Env[0].Value = "ghp_0123456789abcdefghijklmnopqrstuvwxyz" },
		"bound var not placeholder": func(s *Spec) { s.Env[1].Value = "something-else" },
		"bound var unset":           func(s *Spec) { s.Env = s.Env[:1] },
		"pem in dependency env": func(s *Spec) {
			s.Dependencies[0].Env = append(s.Dependencies[0].Env, EnvVar{"KEY", "-----BEGIN PRIVATE KEY-----"})
		},
		"wildcard binding":      func(s *Spec) { s.Bindings[0].Hosts = []string{"*.anthropic.com"} },
		"binding without hosts": func(s *Spec) { s.Bindings[0].Hosts = nil },
		"bad placeholder":       func(s *Spec) { s.Bindings[0].Placeholder = "sk-real" },
		"reused placeholder": func(s *Spec) {
			s.Bindings = append(s.Bindings, Binding{Ref: "x", Hosts: []string{"a.b"}, Inject: "bearer", Placeholder: ph1})
		},
		"bad injection":   func(s *Spec) { s.Bindings[0].Inject = "cookie" },
		"negative rate":   func(s *Spec) { s.Bindings[0].RatePerMinute = -1 },
		"quota too large": func(s *Spec) { s.Bindings[0].Quota = MaxLimit + 1 },
		"one credential, two limits": func(s *Spec) {
			b := s.Bindings[0]
			b.Placeholder, b.EnvVar, b.Inject, b.Burst = "sbxph_"+strings.Repeat("Z", 43), "", "bearer", 7
			s.Bindings = append(s.Bindings, b)
		},
		"readable clashes with env": func(s *Spec) { s.Readable[0].EnvVar = "TERM" },
		"readable file clashes":     func(s *Spec) { s.Env = append(s.Env, EnvVar{"NPM_TOKEN_FILE", "/x"}) },
		"readable twice, by its file": func(s *Spec) {
			s.Readable = append(s.Readable, Readable{Ref: "x", EnvVar: "NPM_TOKEN_FILE"})
		},
		"too many readable": func(s *Spec) {
			for i := 0; i < MaxReadable; i++ {
				s.Readable = append(s.Readable, Readable{Ref: "r", EnvVar: "R" + strings.Repeat("X", i)})
			}
		},
		"root dependency":          func(s *Spec) { s.Dependencies[0].RunAsUser = 0 },
		"dependency port":          func(s *Spec) { s.Dependencies[0].Port = 0 },
		"dependency port 443":      func(s *Spec) { s.Dependencies[0].Port = 443 },
		"dependency on extra port": func(s *Spec) { s.Dependencies[0].Port = 8443 },
		"two dependencies on one port": func(s *Spec) {
			d := s.Dependencies[0]
			d.Name, d.Env, d.Bindings = "replica", nil, nil
			s.Dependencies = append(s.Dependencies, d)
		},
		"too many dependencies": func(s *Spec) {
			for i := 0; i < 6; i++ {
				d := s.Dependencies[0]
				d.Port = 6000 + i
				d.Name = "dep" + string(rune('a'+i))
				d.Env, d.Bindings = nil, nil
				s.Dependencies = append(s.Dependencies, d)
			}
		},
		"bad allow entry":         func(s *Spec) { s.Egress.Allow = []string{"*"} },
		"tld allow":               func(s *Spec) { s.Egress.Allow = []string{"*.com"} },
		"tld deep allow":          func(s *Spec) { s.Egress.Allow = []string{"**.com"} },
		"l7 bad host":             func(s *Spec) { s.Egress.L7[0].Host = "a b" },
		"l7 star in host":         func(s *Spec) { s.Egress.L7[0].Host = "a.*.com" },
		"binding not allowed":     func(s *Spec) { s.Dependencies[0].Egress.Allow = nil },
		"l7 deep wildcard":        func(s *Spec) { s.Egress.L7[0].Host = "**.github.com" },
		"l7 host not allowed":     func(s *Spec) { s.Egress.L7[0].Host = "example.org" },
		"l7 wildcard not allowed": func(s *Spec) { s.Egress.L7[0].Host = "*.anthropic.com" },
		"l7 any-host allow":       func(s *Spec) { s.Egress.L7[1].Action = "allow" },
		"l7 no action":            func(s *Spec) { s.Egress.L7[0].Action = "" },
		"l7 bad glob":             func(s *Spec) { s.Egress.L7[0].PathPatterns = []string{"/a**"} },
		"l7 lower method":         func(s *Spec) { s.Egress.L7[0].Methods = []string{"get"} },
		"triple star":             func(s *Spec) { s.Egress.Allow = []string{"***.example.com"} },
		"bad CIDR":                func(s *Spec) { s.Egress.BlockCIDRs = []string{"10.0.0.0/33"} },
		"bad block pattern":       func(s *Spec) { s.Egress.BlockDomains = []string{"a*b.com"} },
		"endpoint any":            func(s *Spec) { s.Egress.HostEndpoints = []HostEndpoint{{"0.0.0.0", 80}} },
		"endpoint port":           func(s *Spec) { s.Egress.HostEndpoints = []HostEndpoint{{"10.0.0.1", 0}} },
		"credential in audit":     func(s *Spec) { s.Audit["note"] = "sk-ant-api03-abcdefghijklmnop" },
	}
}

func TestValidateRefuses(t *testing.T) {
	cases := refusalCases()
	for name, f := range cases {
		s := good()
		f(s)
		if err := s.Validate(Options{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s := good()
	for i := 0; i < 6; i++ {
		d := s.Dependencies[0]
		d.Port = 6000 + i
		d.Name = "dep" + string(rune('a'+i))
		d.Env, d.Bindings = nil, nil
		s.Dependencies = append(s.Dependencies, d)
	}
	if err := s.Validate(Options{MaxDependencies: 7}); err != nil {
		t.Errorf("a raised dependency limit: %v", err)
	}
}

func TestCredentialFormats(t *testing.T) {
	for _, v := range []string{"sk-ant-api03-0123456789", "github_pat_11ABCDEFG0123456789", "AKIAIOSFODNN7EXAMPLE",
		"xoxb-123456789012-abc", "eyJhbGciOiJIUzI1NiJ9.e30.x"} {
		if !LooksLikeCredential(v) {
			t.Errorf("%q not recognised", v)
		}
	}
	for _, v := range []string{"xterm-256color", "sk-", "en_US.UTF-8", "/usr/bin", ph1} {
		if LooksLikeCredential(v) {
			t.Errorf("%q taken for a credential", v)
		}
	}
	if !IsPlaceholder(ph1) || IsPlaceholder("sbxph_short") {
		t.Error("placeholder form")
	}
}

// TestBindingLimits: limits within range, stated alike by every binding of a credential, pass.
func TestBindingLimits(t *testing.T) {
	s := good()
	s.Bindings[0].RatePerMinute, s.Bindings[0].Burst, s.Bindings[0].Quota = 30, 5, 1000
	b := s.Bindings[0]
	b.Placeholder, b.EnvVar, b.Inject = "sbxph_"+strings.Repeat("Z", 43), "", "bearer"
	s.Bindings = append(s.Bindings, b)
	if err := s.Validate(Options{}); err != nil {
		t.Fatal(err)
	}
}

// TestHistoryMounts: a session mounts its own history directory, or above tier 1 only its agent's
// at its own tier (D-14: tiers never share history).
func TestHistoryMounts(t *testing.T) {
	key := "0123456789abcdef"
	for src, ok := range map[string]bool{
		SessionStore + "/s-20261125-ab12/history":     true,
		AgentHistoryStore + "/claude/tier2/" + key:    true,
		AgentHistoryStore + "/claude/tier3/" + key:    false, // another tier
		AgentHistoryStore + "/codex/tier2/" + key:     false, // another agent
		AgentHistoryStore + "/claude/tier2/x":         false, // not a key
		AgentHistoryStore + "/claude/tier2/../" + key: false,
		SessionStore + "/s-other/history":             false,
	} {
		s := good()
		s.Mounts[4].Source = src
		if err := s.Validate(Options{}); (err == nil) != ok {
			t.Errorf("%s: %v", src, err)
		}
	}
	s := good()
	s.Tier = 1
	s.Mounts[4].Source = AgentHistoryStore + "/claude/tier1/" + key
	if err := s.Validate(Options{}); err == nil {
		t.Error("a tier 1 session kept history")
	}
}

// TestAgentHomeMounts (OQ-01): only copilot and grok mount an agent home, their own at their own
// tier, writable.
func TestAgentHomeMounts(t *testing.T) {
	for name, c := range map[string]struct {
		agent, src string
		ro, ok     bool
	}{
		"copilot":      {"copilot", AgentHomeStore + "/copilot/tier2", false, true},
		"grok":         {"grok", AgentHomeStore + "/grok/tier2", false, true},
		"another tier": {"copilot", AgentHomeStore + "/copilot/tier3", false, false},
		"another's":    {"copilot", AgentHomeStore + "/grok/tier2", false, false},
		"brokered":     {"claude", AgentHomeStore + "/claude/tier2", false, false},
		"read-only":    {"grok", AgentHomeStore + "/grok/tier2", true, false},
		"escape":       {"grok", AgentHomeStore + "/grok/tier2/../../x", false, false},
	} {
		s := good()
		s.Agent = c.agent
		s.Mounts = append(s.Mounts, Mount{Kind: AgentHome, Source: c.src, Target: "/home/agent/.copilot", ReadOnly: c.ro})
		if err := s.Validate(Options{}); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
	if AgentHomePath("grok", 3) != "/var/lib/sandbox/agent-home/grok/tier3" {
		t.Error(AgentHomePath("grok", 3))
	}
}

// testCA is a self-signed certificate in PEM.
func testCA(t *testing.T) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kube-ca"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestKube: tier 3 clusters are at their gateway names, on the allowlist, each with exactly one
// bearer or mtls binding, with an https server that is not loopback and a CA that parses.
func TestKube(t *testing.T) {
	ca := testCA(t)
	kube := func() *Spec {
		s := good()
		s.Tier = 3
		s.Kube = []KubeCluster{{Name: KubeName(0), Server: "https://10.0.0.5:6443", CA: ca},
			{Name: KubeName(1), Server: "https://rancher.example.com/k8s/clusters/c-x", TLSServerName: "rancher.example.com"}}
		s.Egress.Allow = append(s.Egress.Allow, KubeName(0), KubeName(1))
		s.Bindings = append(s.Bindings,
			Binding{Ref: "infra.kube.0", Hosts: []string{KubeName(0)}, Inject: "bearer", Placeholder: "sbxph_" + strings.Repeat("K", 43)},
			Binding{Ref: "infra.kube.1", Hosts: []string{KubeName(1)}, Inject: "mtls", Placeholder: "sbxph_" + strings.Repeat("M", 43)})
		return s
	}
	if err := kube().Validate(Options{}); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func(*Spec){
		"tier 2": func(s *Spec) { s.Tier = 2 },
		"wrong name": func(s *Spec) {
			s.Kube[0].Name = KubeName(5)
			s.Egress.Allow = append(s.Egress.Allow, KubeName(5))
			s.Bindings[1].Hosts = []string{KubeName(5)}
		},
		"http":            func(s *Spec) { s.Kube[0].Server = "http://10.0.0.5:6443" },
		"loopback":        func(s *Spec) { s.Kube[0].Server = "https://127.0.0.1:6443" },
		"localhost":       func(s *Spec) { s.Kube[0].Server = "https://localhost:6443" },
		"user info":       func(s *Spec) { s.Kube[0].Server = "https://u:p@k.example.com" },
		"query":           func(s *Spec) { s.Kube[0].Server = "https://k.example.com/?x=1" },
		"bad port":        func(s *Spec) { s.Kube[0].Server = "https://k.example.com:70000" },
		"bad CA":          func(s *Spec) { s.Kube[0].CA = "not a cert" },
		"not allowlisted": func(s *Spec) { s.Egress.Allow = s.Egress.Allow[:len(s.Egress.Allow)-1] },
		"no binding":      func(s *Spec) { s.Bindings = s.Bindings[:len(s.Bindings)-1] },
		"two bindings": func(s *Spec) {
			b := s.Bindings[len(s.Bindings)-1]
			b.Ref, b.Placeholder = "x", "sbxph_"+strings.Repeat("Z", 43)
			s.Bindings = append(s.Bindings, b)
		},
		"header binding":  func(s *Spec) { s.Bindings[len(s.Bindings)-1].Inject = "header:x" },
		"mtls elsewhere":  func(s *Spec) { s.Bindings[0].Inject = "mtls" },
		"bad server name": func(s *Spec) { s.Kube[1].TLSServerName = "bad name" },
	} {
		s := kube()
		f(s)
		if s.Validate(Options{}) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestUpstream: a cluster's API server as the gateway reaches it.
func TestUpstream(t *testing.T) {
	for _, c := range []struct {
		k                    KubeCluster
		host, prefix, server string
		port                 int
	}{
		{KubeCluster{Server: "https://10.0.0.5:6443"}, "10.0.0.5", "", "10.0.0.5", 6443},
		{KubeCluster{Server: "https://k.example.com/"}, "k.example.com", "", "k.example.com", 443},
		{KubeCluster{Server: "https://r.example.com/k8s/clusters/c-x", TLSServerName: "kubernetes"}, "r.example.com", "/k8s/clusters/c-x", "kubernetes", 443},
	} {
		h, p, pre, sn := c.k.Upstream()
		if h != c.host || p != c.port || pre != c.prefix || sn != c.server {
			t.Errorf("%+v: %s %d %s %s", c.k, h, p, pre, sn)
		}
	}
}
