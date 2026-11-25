package proxycert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func subjectsPEM(t *testing.T) []string {
	b, err := os.ReadFile(filepath.Join("testdata", "subjects.pem"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return out
		}
		out = append(out, string(pem.EncodeToMemory(blk)))
	}
}

type result struct {
	rc       int
	out, err string
}

func run(t *testing.T, env Env, stdin string, args ...string) result {
	var o, e bytes.Buffer
	env.Stdout, env.Stderr, env.Stdin = &o, &e, strings.NewReader(stdin)
	rc := Run(context.Background(), args, env)
	return result{rc, o.String(), e.String()}
}

func TestMacAndWindows(t *testing.T) {
	certs := subjectsPEM(t)
	keychain := []byte(certs[14] + certs[0] + certs[17])
	out := filepath.Join(t.TempDir(), "x", "proxy-ca.crt")
	env := Env{GOOS: "darwin", DefaultOutput: out, MacKeychain: func(context.Context) ([]byte, error) { return keychain, nil }}
	r := run(t, env, "")
	want := "==> Searching macOS System keychain for proxy CA (vendors: Zscaler|Netskope|Forcepoint|Cisco Umbrella|Palo Alto|Symantec|Blue Coat|Prisma|iboss|Menlo)...\n" +
		"  Source: macOS System keychain\n  Cert(s) extracted:\n" +
		"  [1] Subject: C = US, O = Zscaler Inc., CN = Zscaler Root CA\n      Issuer:  C = US, O = Zscaler Inc., CN = Zscaler Root CA\n" +
		"==> Wrote " + out + "\n    The sandbox trusts it from the next session; no rebuild is needed.\n"
	if r.rc != 0 || r.out != want || r.err != "" {
		t.Fatalf("%+v", r)
	}
	if b, _ := os.ReadFile(out); string(b) != certs[0] {
		t.Errorf("wrote %q", b)
	}
	// an existing file needs --force, or a yes on a terminal
	if r := run(t, env, ""); r.rc != 1 || !strings.Contains(r.err, "already exists and stdin is not a TTY") {
		t.Errorf("no tty: %+v", r)
	}
	env.StdinTTY = true
	if r := run(t, env, "n\n"); r.rc != 1 || !strings.HasSuffix(r.err, "Aborted; existing file untouched.\n") {
		t.Errorf("declined: %+v", r)
	}
	env.MacKeychain = func(context.Context) ([]byte, error) { return []byte(certs[1]), nil }
	if r := run(t, env, "yes\n"); r.rc != 0 {
		t.Errorf("accepted: %+v", r)
	}
	if b, _ := os.ReadFile(out); string(b) != certs[1] {
		t.Errorf("overwrite wrote %q", b)
	}
	env.MacKeychain = func(context.Context) ([]byte, error) { return []byte(certs[14]), nil }
	if r := run(t, env, "", "--force"); r.rc != 1 || !strings.Contains(r.err, "No matching cert in /Library/Keychains/System.keychain") {
		t.Errorf("no match: %+v", r)
	}
	env.MacKeychain = func(context.Context) ([]byte, error) { return nil, errors.New("denied") }
	if r := run(t, env, "", "--force"); r.rc != 1 {
		t.Errorf("security failed: %+v", r)
	}
	// --vendor is a literal substring, so a pattern character is just a character
	env.MacKeychain = func(context.Context) ([]byte, error) { return keychain, nil }
	if r := run(t, env, "", "--vendor", "caf", "--list"); r.rc != 0 || !strings.Contains(r.out, `CN = caf\C3\A9`) || !strings.Contains(r.out, "vendors: caf|Zscaler") {
		t.Errorf("vendor: %+v", r)
	}
	env.MacKeychain = func(context.Context) ([]byte, error) { return []byte(certs[14] + certs[17]), nil }
	if r := run(t, env, "", "--vendor", ".*", "--list"); r.rc != 1 {
		t.Errorf("regex vendor matched: %+v", r)
	}

	win := Env{GOOS: "windows", DefaultOutput: out, WindowsStore: func(context.Context) ([]byte, error) { return []byte(certs[2]), nil }}
	if r := run(t, win, "", "--list"); r.rc != 0 || !strings.Contains(r.out, "Palo Alto Networks Decryption CA") || !strings.Contains(r.out, "Source: Windows") {
		t.Errorf("windows: %+v", r)
	}
}

func TestArgs(t *testing.T) {
	env := Env{GOOS: "linux", LinuxFiles: func() []string { return nil }, LinuxBundle: "/nonexistent"}
	for args, want := range map[string]string{
		"--from-wire": "setup-proxy-cert: --from-wire needs a host argument",
		"--vendor":    "setup-proxy-cert: --vendor needs a name",
		"-o":          "setup-proxy-cert: --output needs a path",
		"--bogus":     "setup-proxy-cert: unknown option '--bogus' (use --help)",
		"":            "No matching cert in the host trust store.",
	} {
		a := strings.Fields(args)
		if r := run(t, env, "", a...); r.rc != 1 || !strings.HasPrefix(r.err, "ERROR: "+want) {
			t.Errorf("%q: %+v", args, r)
		}
	}
	if r := run(t, env, "", "--help"); r.rc != 0 || !strings.HasPrefix(r.out, "Usage: sandbox setup-proxy-cert") || strings.Contains(r.out, "rebuild'") {
		t.Errorf("help: %+v", r)
	}
}

func cert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ca bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: ca, BasicConstraintsValid: true,
		DNSNames: []string{"localhost"}}
	if parent == nil {
		parent, parentKey = tmpl, k
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &k.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, k
}

func TestFromWire(t *testing.T) {
	root, rk := cert(t, "Zscaler Root CA", nil, nil, true)
	mid, mk := cert(t, "Zscaler Intermediate", root, rk, true)
	leaf, lk := cert(t, "localhost", mid, mk, false)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{leaf.Raw, mid.Raw, root.Raw}, PrivateKey: lk}}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	env := Env{GOOS: "linux", Wire: DialChain}
	r := run(t, env, "", "--from-wire", l.Addr().String(), "--list")
	if r.rc != 0 || strings.Count(r.out, "Subject:") != 2 || strings.Contains(r.out, "CN = localhost") ||
		!strings.Contains(r.out, "[1] Subject: CN = Zscaler Intermediate") || !strings.Contains(r.out, "Source: wire: 127.0.0.1:") {
		t.Fatalf("%+v", r)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	if r := run(t, env, "", "--from-wire", "127.0.0.1:"+port+"0", "--list"); r.rc != 1 || !strings.Contains(r.err, "Could not extract a cert chain") {
		t.Errorf("unreachable: %+v", r)
	}
	// one certificate only: it is kept
	one := Env{GOOS: "linux", Wire: func(context.Context, string) ([][]byte, error) { return [][]byte{leaf.Raw}, nil }}
	if r := run(t, one, "", "--from-wire", "x", "--list"); r.rc != 0 || !strings.Contains(r.out, "CN = localhost") {
		t.Errorf("single cert: %+v", r)
	}
}
