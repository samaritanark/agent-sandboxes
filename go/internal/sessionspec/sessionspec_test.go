package sessionspec

import (
	"bytes"
	"strings"
	"testing"
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
		Egress: Egress{Allow: []string{"api.anthropic.com", "*.github.com"}, BlockCIDRs: []string{"169.254.0.0/16"},
			BlockDomains:  []string{"*.gist.github.com", "*pastebin.com", "ngrok.*", "raw.github.com"},
			L7:            []L7Rule{{Host: "api.github.com", Methods: []string{"GET"}, PathPrefixes: []string{"/repos/"}}},
			HostEndpoints: []HostEndpoint{{"192.168.1.10", 6443}}, ExtraPorts: []int{8443}},
		Bindings: []Binding{{Ref: "anthropic", Hosts: []string{"api.anthropic.com"}, Inject: "header:x-api-key", Placeholder: ph1, EnvVar: "ANTHROPIC_API_KEY"}},
		Readable: []Readable{{Ref: "npm-token", EnvVar: "NPM_TOKEN"}},
		Dependencies: []Dependency{{Name: "postgres", Image: "docker.io/library/postgres" + digest, Port: 5432, RunAsUser: 999,
			Env: []EnvVar{{"POSTGRES_PASSWORD", ph2}}, Resources: Resources{CPUs: 1, MemoryMiB: 1024},
			Bindings: []Binding{{Ref: "pg", Hosts: []string{"db.internal"}, Inject: "basic", Placeholder: ph2, EnvVar: "POSTGRES_PASSWORD"}}}},
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
		"bad injection":             func(s *Spec) { s.Bindings[0].Inject = "cookie" },
		"readable clashes with env": func(s *Spec) { s.Readable[0].EnvVar = "TERM" },
		"root dependency":           func(s *Spec) { s.Dependencies[0].RunAsUser = 0 },
		"dependency port":           func(s *Spec) { s.Dependencies[0].Port = 0 },
		"dependency port 443":       func(s *Spec) { s.Dependencies[0].Port = 443 },
		"dependency on extra port":  func(s *Spec) { s.Dependencies[0].Port = 8443 },
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
		"bad allow entry":     func(s *Spec) { s.Egress.Allow = []string{"*"} },
		"tld allow":           func(s *Spec) { s.Egress.Allow = []string{"*.com"} },
		"bad CIDR":            func(s *Spec) { s.Egress.BlockCIDRs = []string{"10.0.0.0/33"} },
		"bad block pattern":   func(s *Spec) { s.Egress.BlockDomains = []string{"a*b.com"} },
		"endpoint any":        func(s *Spec) { s.Egress.HostEndpoints = []HostEndpoint{{"0.0.0.0", 80}} },
		"endpoint port":       func(s *Spec) { s.Egress.HostEndpoints = []HostEndpoint{{"10.0.0.1", 0}} },
		"credential in audit": func(s *Spec) { s.Audit["note"] = "sk-ant-api03-abcdefghijklmnop" },
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
