package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

func roots(ca *CA) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// verify checks a leaf chain (leaf + intermediate) for name as a client would.
func verify(t *testing.T, ca *CA, chain []byte, name string, at time.Time) error {
	t.Helper()
	var certs []*x509.Certificate
	for {
		var b *pem.Block
		b, chain = pem.Decode(chain)
		if b == nil {
			break
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, c)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{DNSName: name, Roots: roots(ca), Intermediates: inter, CurrentTime: at})
	return err
}

func TestLoadOrCreate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	ca, made, err := LoadOrCreate(dir, t0)
	if err != nil || !made {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(dir, "ca.key")); st.Mode().Perm() != 0o600 {
		t.Errorf("key mode %v", st.Mode())
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", st.Mode())
	}
	if ca.Cert.NotAfter.Sub(ca.Cert.NotBefore) > CAValidity+2*time.Hour || ca.Cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("CA %v %v", ca.Cert.NotAfter, ca.Cert.PublicKeyAlgorithm)
	}
	again, made, _ := LoadOrCreate(dir, t0.Add(24*time.Hour))
	if made || !again.Cert.Equal(ca.Cert) {
		t.Error("an unexpired CA was replaced")
	}
	rotated, made, _ := LoadOrCreate(dir, t0.Add(CAValidity-RotateBefore+time.Hour))
	if !made || rotated.Cert.Equal(ca.Cert) {
		t.Error("a CA near its end was not rotated")
	}
	os.WriteFile(filepath.Join(dir, "ca.key"), []byte("junk"), 0o600)
	if _, made, err := LoadOrCreate(dir, t0); err != nil || !made {
		t.Errorf("unreadable files: %v %v", made, err)
	}
}

func TestSessionLeaves(t *testing.T) {
	ca, _, _ := LoadOrCreate(t.TempDir(), t0)
	leaves, ikey, err := ca.issue("s-one", []string{"api.github.com", "*.anthropic.com"}, 2*time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(t, ca, leaves[0].CertPEM, "api.github.com", t0.Add(time.Hour)); err != nil {
		t.Errorf("leaf for api.github.com: %v", err)
	}
	if err := verify(t, ca, leaves[1].CertPEM, "x.anthropic.com", t0.Add(time.Hour)); err != nil {
		t.Errorf("wildcard leaf: %v", err)
	}
	if err := verify(t, ca, leaves[0].CertPEM, "api.github.com", t0.Add(3*time.Hour)); err == nil {
		t.Error("a leaf outlived the session")
	}
	if _, err := tls.X509KeyPair(leaves[0].CertPEM, leaves[0].KeyPEM); err != nil {
		t.Errorf("leaf key pair: %v", err)
	}
	// the name constraint: the session intermediate cannot vouch for another name
	icert := parseFirst(t, leaves[0].CertPEM[len(pemFirst(leaves[0].CertPEM)):])
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	evil := &x509.Certificate{SerialNumber: bigOne(), Subject: pkix.Name{CommonName: "evil.com"}, DNSNames: []string{"evil.com"},
		NotBefore: t0, NotAfter: t0.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, evil, icert, &k.PublicKey, ikey)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pemFirst(leaves[0].CertPEM[len(pemFirst(leaves[0].CertPEM)):])...)
	if err := verify(t, ca, chain, "evil.com", t0.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "constraint") {
		t.Errorf("a leaf for evil.com from the session intermediate verified: %v", err)
	}
	// pathlen 0: the intermediate cannot make another CA
	sub := &x509.Certificate{SerialNumber: bigOne(), Subject: pkix.Name{CommonName: "sub"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: t0, NotAfter: t0.Add(time.Hour), KeyUsage: x509.KeyUsageCertSign}
	sder, _ := x509.CreateCertificate(rand.Reader, sub, icert, &k.PublicKey, ikey)
	scert, _ := x509.ParseCertificate(sder)
	leafT := &x509.Certificate{SerialNumber: bigOne(), DNSNames: []string{"api.github.com"}, NotBefore: t0, NotAfter: t0.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	lder, _ := x509.CreateCertificate(rand.Reader, leafT, scert, &k.PublicKey, k)
	chain = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: lder}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sder})...)
	chain = append(chain, pemFirst(leaves[0].CertPEM[len(pemFirst(leaves[0].CertPEM)):])...)
	if err := verify(t, ca, chain, "api.github.com", t0.Add(time.Minute)); err == nil {
		t.Error("a CA made by the session intermediate was trusted")
	}
	if _, err := ca.IssueSession("s-x", nil, time.Hour, t0); err == nil {
		t.Error("no names accepted")
	}
	if _, err := ca.IssueSession("s-x", []string{"*.*.com"}, time.Hour, t0); err == nil {
		t.Error("a double wildcard accepted")
	}
}

func TestBundle(t *testing.T) {
	ca, _, _ := LoadOrCreate(t.TempDir(), t0)
	other, _, _ := LoadOrCreate(t.TempDir(), t0)
	b := Bundle(other.CertPEM, ca, other.CertPEM, []byte("junk"))
	if n := strings.Count(string(b), "BEGIN CERTIFICATE"); n != 2 {
		t.Errorf("%d certificates in the bundle", n)
	}
	if strings.Contains(string(b), "PRIVATE") {
		t.Error("a key in the bundle")
	}
}

func pemFirst(b []byte) []byte {
	blk, rest := pem.Decode(b)
	if blk == nil {
		return nil
	}
	return b[:len(b)-len(rest)]
}

func parseFirst(t *testing.T, b []byte) *x509.Certificate {
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func bigOne() *big.Int { n, _ := serial(); return n }
