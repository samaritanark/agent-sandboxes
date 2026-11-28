package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/brokerkey"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

const (
	testCertPEM = "-----BEGIN CERTIFICATE-----\nMIIBY2xpZW50\n-----END CERTIFICATE-----\n"
	testKeyPEM  = "-----BEGIN EC PRIVATE KEY-----\nMHcCa2V5\n-----END EC PRIVATE KEY-----\n"
)

var testCAPEM = selfSigned()

// selfSigned is a CA certificate in PEM, as a kubeconfig's certificate-authority-data holds.
func selfSigned() string {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kubernetes-ca"}, NotBefore: time.Unix(0, 0),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// view is a minified kubeconfig as `kubectl config view -o json` prints it.
func view(ctx, server string, user map[string]any, extra map[string]any) []byte {
	cl := map[string]any{"server": server, "certificate-authority-data": b64(testCAPEM)}
	for k, v := range extra {
		cl[k] = v
	}
	b, _ := json.Marshal(map[string]any{"current-context": ctx,
		"clusters": []any{map[string]any{"name": "c", "cluster": cl}},
		"contexts": []any{map[string]any{"name": ctx, "context": map[string]any{"cluster": "c", "user": "u", "namespace": "dev"}}},
		"users":    []any{map[string]any{"name": "u", "user": user}}})
	return b
}

// TestParseKubeconfig: a token, a token file, and a client certificate and key are taken, with the
// server, the CA, and the context's name and namespace; v2's refusals and v3's (no TLS check, a
// proxy, an auth provider, an exec plugin) say what to do.
func TestParseKubeconfig(t *testing.T) {
	tf := filepath.Join(t.TempDir(), "token")
	os.WriteFile(tf, []byte("file-token\n"), 0o600)
	k, err := parseKubeconfig(view("dev", "https://10.0.0.5:6443", map[string]any{"token": "tok"}, nil), "/k", nil)
	if err != nil || k.Auth != "token" || string(k.value) != "tok" || k.CA != testCAPEM || k.Context != "dev" || k.Namespace != "dev" || k.Server != "https://10.0.0.5:6443" {
		t.Errorf("token: %+v %v", k, err)
	}
	k, err = parseKubeconfig(view("dev", "https://k", map[string]any{"tokenFile": tf}, nil), "/k", func(p string) string { return p })
	if err != nil || string(k.value) != "file-token" {
		t.Errorf("token file: %+v %v", k, err)
	}
	k, err = parseKubeconfig(view("prod", "https://k", map[string]any{"client-certificate-data": b64(testCertPEM), "client-key-data": b64(testKeyPEM)},
		map[string]any{"tls-server-name": "kubernetes"}), "/k", nil)
	if err != nil || k.Auth != "mtls" || !strings.Contains(string(k.value), "MIIBY2xpZW50") || !strings.Contains(string(k.value), "MHcCa2V5") || k.TLSServerName != "kubernetes" {
		t.Errorf("client certificate: %+v %v", k, err)
	}
	for name, c := range map[string]struct {
		raw  []byte
		want string
	}{
		"no credential":  {view("dev", "https://k", map[string]any{"username": "u", "password": "p"}, nil), "no static credentials"},
		"exec":           {view("dev", "https://k", map[string]any{"exec": map[string]any{"command": "aws"}}, nil), "exec credential plugin"},
		"auth provider":  {view("dev", "https://k", map[string]any{"auth-provider": map[string]any{"name": "oidc"}}, nil), "auth-provider"},
		"insecure":       {view("dev", "https://k", map[string]any{"token": "t"}, map[string]any{"insecure-skip-tls-verify": true}), "insecure-skip-tls-verify"},
		"proxy":          {view("dev", "https://k", map[string]any{"token": "t"}, map[string]any{"proxy-url": "http://p"}), "proxy-url"},
		"no server":      {view("dev", "", map[string]any{"token": "t"}, nil), "cluster.server"},
		"key, not a key": {view("dev", "https://k", map[string]any{"client-certificate-data": b64(testCertPEM), "client-key-data": b64(testCertPEM)}, nil), "client-key-data"},
		"not json":       {[]byte("x"), "not a kubeconfig"},
		"bad CA":         {view("dev", "https://k", map[string]any{"token": "t"}, map[string]any{"certificate-authority-data": b64(testCertPEM)}), "certificate-authority-data"},
	} {
		if _, err := parseKubeconfig(c.raw, "/k", nil); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestRunKubeconfigs: run reads each --infra-kubeconfig with the host's kubectl (the context named
// for a single one), keeps v2's context names with a suffix on a collision, hands the clusters to
// the VM's pre-pass and run without any credential, and seals each credential bound to its
// cluster's gateway name.
func TestRunKubeconfigs(t *testing.T) {
	state := t.TempDir()
	k := brokerkey.File{Path: filepath.Join(state, "broker.key")}
	var calls [][]string
	kubectl := func(args []string) ([]byte, string, error) {
		calls = append(calls, args)
		switch {
		case strings.HasSuffix(args[len(args)-1], "a.yaml") || strings.Contains(strings.Join(args, " "), "--kubeconfig=/k/a.yaml"):
			return view("dev", "https://10.0.0.5:6443", map[string]any{"token": "tok-a"}, nil), "", nil
		case strings.Contains(strings.Join(args, " "), "--kubeconfig=/k/b.yaml"):
			return view("dev", "https://b.example.com", map[string]any{"client-certificate-data": b64(testCertPEM), "client-key-data": b64(testKeyPEM)}, nil), "", nil
		}
		return nil, "error: context \"x\" does not exist", errors.New("exit status 1")
	}
	tr := &fakeTransport{release: goodRelease}
	var out, errb bytes.Buffer
	env := Env{Driver: &driver.Mock{State: driver.Running}, Transport: tr, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb,
		StateDir: state, Now: func() time.Time { return time.Unix(1800000000, 0) }, BrokerKey: k, Kubectl: kubectl}
	rc := Run(context.Background(), []string{"run", "--tier", "3", "--infra-kubeconfig", "/k/a.yaml", "--infra-kubeconfig", "/k/b.yaml"}, env)
	if rc != 0 {
		t.Fatalf("%d\n%s\n%s", rc, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "==> Minifying kubeconfig 1/2: /k/a.yaml (current-context)...") || len(calls) != 2 {
		t.Errorf("%s %q", out.String(), calls)
	}
	// the clusters reach the pre-pass and the run, without a credential
	var desc []kubeCluster
	for _, argv := range append(tr.bindingArgv, tr.runs...) {
		found := false
		for _, a := range argv {
			if v, ok := strings.CutPrefix(a, KubeEnv+"="); ok {
				found = true
				if strings.Contains(v, "tok-a") || strings.Contains(v, "MHcCa2V5") {
					t.Errorf("a credential reached the VM's command line: %s", v)
				}
				json.Unmarshal([]byte(v), &desc)
			}
		}
		if !found {
			t.Errorf("no %s in %q", KubeEnv, argv)
		}
	}
	if len(desc) != 2 || desc[0].Context != "dev" || desc[1].Context != "dev-2" || desc[0].Auth != "token" || desc[1].Auth != "mtls" || desc[0].CA != testCAPEM {
		t.Errorf("clusters %+v", desc)
	}
	// each credential sealed, bound to its gateway name
	key, _ := k.Load()
	var puts []string
	for i, c := range tr.ctl {
		if len(c) == 3 && c[1] == "broker-put" {
			puts = append(puts, c[2])
			v, b, bound, err := brokerseal.OpenBound(key, c[2], tr.ctlIn[i])
			want := map[string][2]string{"infra.kube.0": {"tok-a", "bearer"}, "infra.kube.1": {"MHcCa2V5", "mtls"}}[c[2]]
			if err != nil || !bound || !strings.Contains(string(v), want[0]) || b.Inject != want[1] || len(b.Hosts) != 1 || b.Hosts[0] != kubeName(len(puts)-1) {
				t.Errorf("%s: %q %+v %v %v", c[2], v, b, bound, err)
			}
		}
	}
	if strings.Join(puts, ",") != "infra.kube.0,infra.kube.1" {
		t.Errorf("pushed %q", puts)
	}
	// a single kubeconfig takes the context; kubectl's failure is shown, and nothing runs
	calls = nil
	tr2 := &fakeTransport{release: goodRelease}
	env.Transport = tr2
	errb.Reset()
	rc = Run(context.Background(), []string{"run", "--tier", "3", "--infra-kubeconfig", "/k/c.yaml", "--infra-kube-context", "x"}, env)
	if rc != 1 || !strings.Contains(errb.String(), "kubectl could not minify kubeconfig '/k/c.yaml':") || !strings.Contains(errb.String(), "(context requested: 'x')") ||
		len(tr2.runs) != 0 || !strings.Contains(strings.Join(calls[0], " "), "--context=x") {
		t.Errorf("%d %s %q", rc, errb.String(), calls)
	}
}
