// Package pki is sandboxd's certificate authority (design 5.10). The gateway CA is generated in
// the VM (ECDSA P-256, at most a year), kept root-only, and never mounted into a guest or given to
// a gateway. For each session sandboxd issues an intermediate certificate, critically
// name-constrained to that session's intercepted names with pathlen 0 and valid for the session's
// lifetime, mints one leaf per intercepted name from it, and discards the intermediate's key: the
// gateway gets only its leaves, so a gateway compromise yields certificates for one session's
// names, not for every site for a year (S5 measured the constraint across seven TLS stacks).
package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CAValidity is the gateway CA's lifetime; RotateBefore is how long before its end a new one is made.
const (
	CAValidity   = 365 * 24 * time.Hour
	RotateBefore = 30 * 24 * time.Hour
)

// CA is the gateway CA.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     *ecdsa.PrivateKey
}

func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }

func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pemKey(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// LoadOrCreate reads the CA from dir (ca.crt, ca.key), or makes a new one when there is none or it
// ends within RotateBefore. dir is made root-only; the key file is 0600.
func LoadOrCreate(dir string, now time.Time) (*CA, bool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, false, err
	}
	certPEM, err1 := os.ReadFile(filepath.Join(dir, "ca.crt"))
	keyPEM, err2 := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err1 == nil && err2 == nil {
		ca, err := parse(certPEM, keyPEM)
		if err == nil && now.Add(RotateBefore).Before(ca.Cert.NotAfter) {
			return ca, false, nil
		}
	}
	ca, err := newCA(now)
	if err != nil {
		return nil, false, err
	}
	keyPEM, err = pemKey(ca.key)
	if err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(filepath.Join(dir, ".ca.key"), keyPEM, 0o600); err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(filepath.Join(dir, ".ca.crt"), ca.CertPEM, 0o644); err != nil {
		return nil, false, err
	}
	for _, n := range []string{"ca.key", "ca.crt"} {
		if err := os.Rename(filepath.Join(dir, "."+n), filepath.Join(dir, n)); err != nil {
			return nil, false, err
		}
	}
	return ca, true, nil
}

func parse(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, errors.New("pki: unreadable CA files")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("pki: the CA key does not match its certificate")
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: key}, nil
}

func newCA(now time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn, Subject: pkix.Name{CommonName: "sandbox gateway CA", Organization: []string{"agent-sandboxes"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(CAValidity),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	return &CA{Cert: cert, CertPEM: pemCert(der), key: key}, nil
}

// Leaf is one intercepted name's certificate for the gateway: the leaf and the session's
// intermediate (CertPEM, the chain Envoy serves) and the leaf's key.
type Leaf struct {
	Name    string
	CertPEM []byte
	KeyPEM  []byte
}

// constraint is the name constraint covering an intercepted name: a name permits itself and its
// subdomains, so "*.x" is covered by "x".
func constraint(name string) string { return strings.TrimPrefix(name, "*.") }

// IssueSession mints a session's leaves for names (exact names or "*.x" wildcards), valid for
// validity from now and never past the CA's end. The intermediate's key does not outlive the call.
func (ca *CA) IssueSession(session string, names []string, validity time.Duration, now time.Time) ([]Leaf, error) {
	leaves, _, err := ca.issue(session, names, validity, now)
	return leaves, err
}

func (ca *CA) issue(session string, names []string, validity time.Duration, now time.Time) ([]Leaf, *ecdsa.PrivateKey, error) {
	if len(names) == 0 {
		return nil, nil, errors.New("pki: no names to intercept")
	}
	end := now.Add(validity)
	if end.After(ca.Cert.NotAfter) {
		end = ca.Cert.NotAfter
	}
	var permitted []string
	seen := map[string]bool{}
	for _, n := range names {
		c := constraint(n)
		if c == "" || strings.Contains(c, "*") {
			return nil, nil, fmt.Errorf("pki: cannot intercept %q", n)
		}
		if !seen[c] {
			seen[c] = true
			permitted = append(permitted, c)
		}
	}
	ikey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	itmpl := &x509.Certificate{
		SerialNumber: sn, Subject: pkix.Name{CommonName: "sandbox session " + session, Organization: []string{"agent-sandboxes"}},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: end,
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage:            x509.KeyUsageCertSign,
		PermittedDNSDomains: permitted, PermittedDNSDomainsCritical: true,
	}
	ider, err := x509.CreateCertificate(rand.Reader, itmpl, ca.Cert, &ikey.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	icert, _ := x509.ParseCertificate(ider)
	var leaves []Leaf
	for _, n := range names {
		lkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		sn, err := serial()
		if err != nil {
			return nil, nil, err
		}
		ltmpl := &x509.Certificate{
			SerialNumber: sn, Subject: pkix.Name{CommonName: n},
			NotBefore: now.Add(-5 * time.Minute), NotAfter: end,
			DNSNames: []string{n}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		lder, err := x509.CreateCertificate(rand.Reader, ltmpl, icert, &lkey.PublicKey, ikey)
		if err != nil {
			return nil, nil, err
		}
		kp, err := pemKey(lkey)
		if err != nil {
			return nil, nil, err
		}
		leaves = append(leaves, Leaf{Name: n, CertPEM: append(pemCert(lder), pemCert(ider)...), KeyPEM: kp})
	}
	return leaves, ikey, nil
}

// Bundle is the trust bundle a session's guests get (design 5.10): the system roots, the gateway
// CA, and the operator's corporate CAs, each PEM block once.
func Bundle(systemRoots []byte, ca *CA, extra ...[]byte) []byte {
	var out bytes.Buffer
	seen := map[string]bool{}
	add := func(b []byte) {
		for {
			var blk *pem.Block
			blk, b = pem.Decode(b)
			if blk == nil {
				return
			}
			if blk.Type != "CERTIFICATE" || seen[string(blk.Bytes)] {
				continue
			}
			seen[string(blk.Bytes)] = true
			pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: blk.Bytes})
		}
	}
	add(systemRoots)
	add(ca.CertPEM)
	for _, e := range extra {
		add(e)
	}
	return out.Bytes()
}
