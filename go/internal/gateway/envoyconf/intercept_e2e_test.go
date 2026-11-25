package envoyconf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/l7"
)

// testCA writes a CA and one leaf per name into dir, and returns the CA file.
func testCA(t *testing.T, dir string, names ...string) string {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	caFile := filepath.Join(dir, "ca.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	for i, n := range names {
		lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		lt := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: n}, DNSNames: []string{n},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		ld, err := x509.CreateCertificate(rand.Reader, lt, ca, &lk.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		kd, _ := x509.MarshalPKCS8PrivateKey(lk)
		base := filepath.Join(dir, strings.ReplaceAll(n, "*", "_"))
		os.WriteFile(base+".crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ld}), 0o644)
		os.WriteFile(base+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	}
	return caFile
}

// TestInterceptEndToEnd terminates TLS for intercepted names with a test CA's leaves and applies
// the org baseline and a session's rules to real requests (ENVOY=path, SANDBOX_NET_TEST=1, root).
func TestInterceptEndToEnd(t *testing.T) {
	envoy := os.Getenv("ENVOY")
	if envoy == "" || os.Getenv("SANDBOX_NET_TEST") == "" || os.Geteuid() != 0 {
		t.Skip("needs ENVOY, SANDBOX_NET_TEST=1, root, and the internet")
	}
	dir := t.TempDir()
	caFile := testCA(t, dir, "api.github.com", "github.com")
	data, err := os.ReadFile("../../../../config/egress-baseline.yaml")
	if err != nil {
		data, err = os.ReadFile(os.Getenv("BASELINE"))
	}
	if err != nil {
		t.Fatal("set BASELINE to config/egress-baseline.yaml")
	}
	baseline, err := l7.ParseBaseline(data)
	if err != nil {
		t.Fatal(err)
	}
	rules := append(baseline,
		l7.Rule{Host: "api.github.com", Methods: []string{"GET", "HEAD"}, PathPatterns: []string{"/zen", "/repos/**"}, Action: l7.Allow})
	ic := func(n string) Intercept {
		return Intercept{Name: n, CertChain: filepath.Join(dir, n+".crt"), PrivateKey: filepath.Join(dir, n+".key"), Rules: rules}
	}
	gw := netip.MustParseAddr("127.0.0.78")
	allow := []string{"github.com", "api.github.com", "*.githubusercontent.com"}
	c := Config{Links: []Link{{Addr: gw, Ports: []int{443}, Allow: allow, Intercept: []Intercept{ic("api.github.com"), ic("github.com")}}},
		AdminSocket: filepath.Join(dir, "admin.sock"), Resolvers: hostResolvers(t), AccessLog: filepath.Join(dir, "conn.log"),
		UpstreamCAs: "/etc/ssl/certs/ca-certificates.crt"}
	runGateway(t, dir, envoy, &c)

	req := func(host, method, target string, extra ...string) (string, string) {
		args := append([]string{"-sS", "--path-as-is", "-o", "-", "-w", "\n%{http_code}", "--max-time", "15", "--cacert", caFile,
			"--resolve", host + ":443:" + gw.String(), "-X", method, "https://" + host + target}, extra...)
		out, err := exec.Command("curl", args...).CombinedOutput()
		s := strings.TrimSpace(string(out))
		i := strings.LastIndex(s, "\n")
		if err != nil || i < 0 {
			return "error", s
		}
		return s[i+1:], s[:i]
	}
	for _, c := range []struct {
		host, method, target string
		want                 string // a status, "upstream" (anything but our refusals), or "refused"
		extra                []string
	}{
		{"api.github.com", "GET", "/zen", "200", nil},
		{"api.github.com", "GET", "/users/octocat", "403", nil},
		{"api.github.com", "POST", "/repos/o/r/issues", "403", nil},
		{"api.github.com", "TRACE", "/zen", "403", nil},
		// path tricks: dot segments, escaped slashes, doubled slashes
		{"api.github.com", "GET", "/repos/../users/octocat", "403", nil},
		{"api.github.com", "GET", "/repos%2F..%2Fusers%2Foctocat", "403", nil},
		{"api.github.com", "GET", "/repos/%2E%2E/users/octocat", "403", nil},
		{"api.github.com", "GET", "//zen", "200", nil},
		// the authority must be the connection's name
		{"api.github.com", "GET", "/zen", "421", []string{"-H", "Host: github.com"}},
		{"api.github.com", "GET", "/zen", "421", []string{"-H", "Host: evil.com"}},
		// git push, by protocol
		{"github.com", "POST", "/o/r.git/git-receive-pack", "403", nil},
		{"github.com", "POST", "/o/r.git/git-%72eceive-pack", "403", nil},
		{"github.com", "GET", "/o/r.git/info/refs?service=git-receive-pack", "403", nil},
		{"github.com", "GET", "/o/r.git/info/refs?service=git%2Dreceive-pack", "403", nil},
		{"github.com", "GET", "/o/r.git/info/refs?x=1&service=git-receive-pack", "403", nil},
		{"github.com", "GET", "/o/r.git/info/refs?service=git-upload-pack&service=git-receive-pack", "403", nil},
		{"github.com", "GET", "/o/r.git/info/refs?servic%65=git-receive-pac%6b", "403", nil},
		{"github.com", "GET", "/o/r.git/info/refs?service=git-upload-pack&x=git-receive-pack", "upstream", nil},
		{"github.com", "GET", "/octocat/Hello-World.git/info/refs?service=git-upload-pack", "200", nil},
	} {
		code, body := req(c.host, c.method, c.target, c.extra...)
		ours := strings.Contains(body, "refused by the sandbox egress policy")
		ok := code == c.want && (code != "403" && code != "421" || ours)
		if c.want == "upstream" {
			ok = code != "error" && !ours
		}
		if !ok {
			t.Errorf("%s %s%s %v: %s, refused by us %v", c.method, c.host, c.target, c.extra, code, ours)
		}
	}
	time.Sleep(500 * time.Millisecond)
	logb, _ := os.ReadFile(c.AccessLog)
	t.Logf("log:\n%s", logb)
	if strings.Contains(string(logb), "service=") || strings.Contains(string(logb), "x=1") {
		t.Error("a query string reached the log")
	}
	if !strings.Contains(string(logb), `"rule":"deny:0"`) || !strings.Contains(string(logb), `"rule":"allow:`) {
		t.Error("the log does not name the deciding rules")
	}
}
