package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

var kubeTestCA = selfSigned()

// selfSigned is a CA certificate in PEM, as a kubeconfig's certificate-authority-data holds.
func selfSigned() string {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kubernetes-ca"}, NotBefore: time.Unix(0, 0),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// kubeEnv is launchEnv with the host's description of the clusters, their credentials sealed as
// the host seals them, and names that resolve as given.
func kubeEnv(t *testing.T, ks []KubeCluster, resolve map[string]string) (Env, *fakeSessions, map[string][]byte) {
	e, fs, home := launchEnv(t)
	repo := filepath.Join(home, "app")
	if out, err := exec.Command("git", "init", "-q", repo).CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	e.Launch.WorkspaceCopy = func(string) (string, error) { return "/var/lib/sandbox/workspaces/0123456789abcdef", nil }
	e.Launch.AgentImage = func(tag string) (string, error) {
		if tag != "sandbox:claude-infra" {
			return "", errors.New("not preloaded")
		}
		return "docker.io/library/sandbox" + testDigest, nil
	}
	desc, _ := json.Marshal(ks)
	getenv := e.Getenv
	e.Getenv = func(k string) string {
		if k == KubeEnv {
			return string(desc)
		}
		return getenv(k)
	}
	agent := e.CredentialBinding
	e.CredentialBinding = func(ref string) (brokerseal.Binding, bool) {
		for i, k := range ks {
			if ref == KubeRef(i) {
				return brokerseal.Binding{Hosts: []string{sessionspec.KubeName(i)}, Inject: map[string]string{"token": "bearer", "mtls": "mtls"}[k.Auth]}, true
			}
		}
		return agent(ref)
	}
	e.LookupHost = func(h string) ([]netip.Addr, error) {
		if a, ok := resolve[h]; ok {
			return []netip.Addr{netip.MustParseAddr(a)}, nil
		}
		return nil, errors.New("no such host")
	}
	wrote := map[string][]byte{}
	e.Launch.WriteKubeconfig = func(id string, b []byte) error { wrote[id] = b; return nil }
	return e, fs, wrote
}

// TestLaunchKube (design 5.9.5): a tier 3 run with the host's clusters puts each in the spec, puts
// its gateway name on the allowlist, binds its credential there with a placeholder, and gives the
// agent a kubeconfig (mounted read-only, named by KUBECONFIG) that reaches each cluster through the
// gateway, trusts the gateway's CA, keeps the contexts' names and namespaces, and holds only
// placeholders.
func TestLaunchKube(t *testing.T) {
	ks := []KubeCluster{{Context: "dev", Namespace: "team", Server: "https://10.0.0.5:6443", CA: kubeTestCA, Auth: "token", Source: "/k/a"},
		{Context: "prod", Server: "https://k8s.example.com/prefix", CA: kubeTestCA, TLSServerName: "kubernetes", Auth: "mtls", Source: "/k/b"}}
	e, fs, wrote := kubeEnv(t, ks, map[string]string{"k8s.example.com": "203.0.113.7"})
	var out, errb bytes.Buffer
	if rc := Run([]string{"run", "--tier", "3", "--repo", "~/app", "--infra-kubeconfig", "/k/a", "--infra-kubeconfig", "/k/b"}, e, &out, &errb); rc != 0 {
		t.Fatalf("%d\n%s\n%s", rc, out.String(), errb.String())
	}
	sp := fs.started[0]
	if err := sp.Validate(sessionspec.Options{}); err != nil {
		t.Errorf("sandboxd refuses it: %v", err)
	}
	if len(sp.Kube) != 2 || sp.Kube[0] != (sessionspec.KubeCluster{Name: "kube-0.gw.sandbox.internal", Server: ks[0].Server, CA: kubeTestCA}) ||
		sp.Kube[1] != (sessionspec.KubeCluster{Name: "kube-1.gw.sandbox.internal", Server: ks[1].Server, CA: kubeTestCA, TLSServerName: "kubernetes"}) {
		t.Errorf("clusters %+v", sp.Kube)
	}
	allow := strings.Join(sp.Egress.Allow, " ")
	if !strings.Contains(allow, "kube-0.gw.sandbox.internal") || !strings.Contains(allow, "kube-1.gw.sandbox.internal") {
		t.Errorf("allowlist %q", allow)
	}
	phs := map[string]string{}
	for _, b := range sp.Bindings {
		if strings.HasPrefix(b.Ref, "infra.kube.") {
			phs[b.Ref] = b.Placeholder
			want := map[string][2]string{"infra.kube.0": {"kube-0.gw.sandbox.internal", "bearer"}, "infra.kube.1": {"kube-1.gw.sandbox.internal", "mtls"}}[b.Ref]
			if len(b.Hosts) != 1 || b.Hosts[0] != want[0] || b.Inject != want[1] || b.Placeholder == "" || b.EnvVar != "" {
				t.Errorf("binding %+v", b)
			}
		}
	}
	if len(phs) != 2 || phs["infra.kube.0"] == phs["infra.kube.1"] {
		t.Errorf("placeholders %q", phs)
	}
	var mount *sessionspec.Mount
	for i, m := range sp.Mounts {
		if m.Kind == sessionspec.Kubeconfig {
			mount = &sp.Mounts[i]
		}
	}
	if mount == nil || mount.Source != sessionspec.SessionStore+"/"+sp.ID+"/kube" || mount.Target != KubeconfigDir || !mount.ReadOnly {
		t.Errorf("mount %+v", mount)
	}
	kc := false
	for _, v := range sp.Env {
		kc = kc || v == (sessionspec.EnvVar{Name: "KUBECONFIG", Value: KubeconfigPath})
	}
	if !kc {
		t.Errorf("env %+v", sp.Env)
	}
	var cfg struct {
		Clusters []struct {
			Name    string            `json:"name"`
			Cluster map[string]string `json:"cluster"`
		} `json:"clusters"`
		Contexts []struct {
			Name    string            `json:"name"`
			Context map[string]string `json:"context"`
		} `json:"contexts"`
		Users []struct {
			User map[string]string `json:"user"`
		} `json:"users"`
		Current string `json:"current-context"`
	}
	if err := json.Unmarshal(wrote[sp.ID], &cfg); err != nil {
		t.Fatalf("kubeconfig %q: %v", wrote, err)
	}
	if len(cfg.Clusters) != 2 || cfg.Clusters[1].Cluster["server"] != "https://kube-1.gw.sandbox.internal" || cfg.Clusters[0].Cluster["certificate-authority"] != "/etc/ssl/sandbox/gateway-ca.pem" ||
		len(cfg.Contexts) != 2 || cfg.Contexts[0].Name != "dev" || cfg.Contexts[0].Context["namespace"] != "team" || cfg.Contexts[1].Name != "prod" ||
		cfg.Contexts[1].Context["cluster"] != cfg.Clusters[1].Name || cfg.Current != "dev" ||
		len(cfg.Users) != 2 || cfg.Users[0].User["token"] != phs["infra.kube.0"] || cfg.Users[1].User["token"] != phs["infra.kube.1"] {
		t.Errorf("kubeconfig %s", wrote[sp.ID])
	}
	if strings.Contains(string(wrote[sp.ID]), "6443") || strings.Contains(string(wrote[sp.ID]), "example.com") {
		t.Errorf("the kubeconfig names the cluster itself: %s", wrote[sp.ID])
	}
	for _, want := range []string{"==> Checking 2 cluster(s) from --infra-kubeconfig...", "  Cluster API: https://k8s.example.com/prefix (context prod)",
		"==> Cluster dev: https://10.0.0.5:6443 through the gateway (token brokered;", "==> Cluster prod: https://k8s.example.com/prefix through the gateway (client certificate brokered;"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
}

// TestLaunchKubeRefusals: run refuses, before anything starts, a server that resolves to loopback,
// a blocked one, a credential the broker does not hold as the host sealed it, a description that is
// malformed or does not match the command line, and --infra-kubeconfig without the host.
func TestLaunchKubeRefusals(t *testing.T) {
	tok := func(server string) []KubeCluster {
		return []KubeCluster{{Context: "dev", Server: server, CA: kubeTestCA, Auth: "token", Source: "/k/a"}}
	}
	args := []string{"run", "--tier", "3", "--repo", "~/app", "--infra-kubeconfig", "/k/a"}
	for name, c := range map[string]struct {
		env  func(*testing.T) Env
		args []string
		want string
	}{
		"loopback name": {func(t *testing.T) Env {
			e, _, _ := kubeEnv(t, tok("https://kube.local:6443"), map[string]string{"kube.local": "127.0.0.1"})
			return e
		}, args, "server resolves to loopback (127.0.0.1)"},
		"loopback address": {func(t *testing.T) Env { e, _, _ := kubeEnv(t, tok("https://127.0.0.1:6443"), nil); return e }, args, "is a loopback address"},
		"blocked":          {func(t *testing.T) Env { e, _, _ := kubeEnv(t, tok("https://x.pastebin.com"), nil); return e }, args, "pastebin"},
		"not sealed": {func(t *testing.T) Env {
			e, _, _ := kubeEnv(t, tok("https://10.0.0.5"), nil)
			e.CredentialBinding = func(string) (brokerseal.Binding, bool) { return brokerseal.Binding{}, false }
			return e
		}, args, "credential is not in the sandbox VM's broker as the host sealed it"},
		"bound elsewhere": {func(t *testing.T) Env {
			e, _, _ := kubeEnv(t, tok("https://10.0.0.5"), nil)
			agent := e.CredentialBinding
			e.CredentialBinding = func(ref string) (brokerseal.Binding, bool) {
				if ref == KubeRef(0) {
					return brokerseal.Binding{Hosts: []string{"evil.example.com"}, Inject: "bearer"}, true
				}
				return agent(ref)
			}
			return e
		}, args, "as the host sealed it"},
		"count": {func(t *testing.T) Env { e, _, _ := kubeEnv(t, tok("https://10.0.0.5"), nil); return e },
			[]string{"run", "--tier", "3", "--repo", "~/app", "--infra-kubeconfig", "/k/a", "--infra-kubeconfig", "/k/b"}, "described 1 clusters for 2"},
		"malformed": {func(t *testing.T) Env {
			e, _, _ := kubeEnv(t, tok("https://10.0.0.5"), nil)
			e.Getenv = func(k string) string { return map[string]string{KubeEnv: `[{"context":"dev","token":"x"}]`}[k] }
			return e
		}, args, "malformed"},
		"plain http": {func(t *testing.T) Env { e, _, _ := kubeEnv(t, tok("http://10.0.0.5"), nil); return e }, args, "kubeconfig '/k/a'"},
		"no host": {func(t *testing.T) Env {
			e, _, _ := kubeEnv(t, tok("https://10.0.0.5"), nil)
			e.Getenv = func(string) string { return "" }
			return e
		}, []string{"run", "--tier", "3", "--repo", "~/app", "--infra-kubeconfig", "~/app/.git/HEAD"}, "read on your machine by the host's sandbox binary"},
	} {
		e := c.env(t)
		fs := e.Launch.Sessions.(*fakeSessions)
		var errb bytes.Buffer
		if rc := Run(c.args, e, &bytes.Buffer{}, &errb); rc != 1 || !strings.Contains(errb.String(), c.want) || len(fs.started) != 0 {
			t.Errorf("%s: %d %d %s", name, rc, len(fs.started), errb.String())
		}
	}
}
