package daemon

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/l7"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/pki"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

func kubeCA(t *testing.T) string {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kube"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestKubeSession: a tier 3 session's clusters are intercepted at their gateway names, each with
// its API server as upstream (its CA in the gateway's directory, an mtls cluster's client
// certificate written for the gateway's user on the tmpfs), and the API deny-list in its rules;
// the certificates go with the session.
func TestKubeSession(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	ca, _, err := pki.LoadOrCreate(t.TempDir(), *r.now)
	if err != nil {
		t.Fatal(err)
	}
	r.d.TLS = &TLS{CA: ca, Baseline: []l7.Rule{{Host: l7.AnyHost, Methods: []string{"TRACE"}, Action: l7.Deny}}, SystemRoots: []byte("SYSTEM ROOTS\n")}
	fb := &fakeBroker{}
	r.d.Broker = fb
	r.d.KubeRoot = filepath.Join(t.TempDir(), "kube")
	sp, err := sessionspec.Decode(bytes.NewReader(spec("s-k8s", 4096)))
	if err != nil {
		t.Fatal(err)
	}
	k0, k1 := sessionspec.KubeName(0), sessionspec.KubeName(1)
	sp.Tier = 3
	cpem := kubeCA(t)
	sp.Kube = []sessionspec.KubeCluster{{Name: k0, Server: "https://10.0.0.5:6443", CA: cpem},
		{Name: k1, Server: "https://rancher.example.com/k8s/clusters/c-x"}}
	sp.Egress.Allow = append(sp.Egress.Allow, k0, k1)
	sp.Bindings = []sessionspec.Binding{
		{Ref: "infra.kube.0", Hosts: []string{k0}, Inject: "bearer", Placeholder: "sbxph_" + strings.Repeat("K", 43)},
		{Ref: "infra.kube.1", Hosts: []string{k1}, Inject: "mtls", Placeholder: "sbxph_" + strings.Repeat("M", 43)}}
	b, _ := sp.Encode()
	id, err := r.d.Start(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	p, files := r.gw.policies[id], r.gw.files[id]
	dir := filepath.Join(r.d.SessionRoot, id, "gateway")
	got := map[string]int{}
	for i, ic := range p.Links[0].Intercept {
		got[ic.Name] = i
	}
	ic0, ic1 := p.Links[0].Intercept[got[k0]], p.Links[0].Intercept[got[k1]]
	if k := ic0.Kube; k == nil || k.Host != "10.0.0.5" || k.Port != 6443 || k.SNI != "10.0.0.5" || k.CAFile != filepath.Join(dir, "kube-0.ca") || k.ClientCert != "" {
		t.Errorf("cluster 0: %+v", ic0.Kube)
	}
	if string(files["kube-0.ca"]) != cpem {
		t.Error("cluster 0's CA is not in the gateway's files")
	}
	certDir := filepath.Join(r.d.KubeRoot, id)
	if k := ic1.Kube; k == nil || k.Host != "rancher.example.com" || k.Port != 443 || k.PathPrefix != "/k8s/clusters/c-x" || k.CAFile != "" ||
		k.ClientCert != filepath.Join(certDir, "kube-1.crt") || k.ClientKey != filepath.Join(certDir, "kube-1.key") {
		t.Errorf("cluster 1: %+v", ic1.Kube)
	}
	if b, _ := os.ReadFile(filepath.Join(certDir, "kube-1.crt")); !strings.Contains(string(b), "infra.kube.1 for "+k1) || fb.certUID != 70000 {
		t.Errorf("client certificate %q for uid %d", b, fb.certUID)
	}
	deny := 0
	for _, rl := range p.Links[0].L7 {
		if rl.Action == l7.Deny && (rl.Host == k0 || rl.Host == k1) {
			deny++
		}
	}
	if deny < 6 {
		t.Errorf("%d deny-list rules for the clusters", deny)
	}
	if err := r.d.Stop(ctx, id, "operator stop"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(certDir); err == nil {
		t.Error("the client certificates outlived the session")
	}
	// an mtls cluster with no tmpfs for its certificate is refused
	r2 := newRig(t)
	r2.d.TLS, r2.d.Broker = r.d.TLS, fb
	sp.ID, sp.Name = "s-k8s2", "s-k8s2"
	b, _ = sp.Encode()
	if _, err := r2.d.Start(ctx, b); err == nil || !strings.Contains(err.Error(), "client-certificate") {
		t.Errorf("no KubeRoot: %v", err)
	}
}
