package envoyconf

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/l7"
)

// TestLeafRotation swaps an intercepted name's leaf while Envoy runs: a new connection gets the
// new leaf, and a connection opened before the swap goes on serving (ENVOY, SANDBOX_NET_TEST=1,
// root; no upstream: a deny rule answers).
func TestLeafRotation(t *testing.T) {
	envoy := os.Getenv("ENVOY")
	if envoy == "" || os.Getenv("SANDBOX_NET_TEST") == "" || os.Geteuid() != 0 {
		t.Skip("needs ENVOY, SANDBOX_NET_TEST=1, and root")
	}
	const host = "rotate.test"
	dir := t.TempDir()
	tlsDir := filepath.Join(dir, "tls")
	os.MkdirAll(filepath.Join(tlsDir, "v1"), 0o700)
	os.MkdirAll(filepath.Join(tlsDir, "v2"), 0o700)
	ca1 := testCA(t, filepath.Join(tlsDir, "v1"), host)
	ca2 := testCA(t, filepath.Join(tlsDir, "v2"), host)
	if err := os.Symlink("v1", filepath.Join(tlsDir, "live")); err != nil {
		t.Fatal(err)
	}
	ic := Intercept{Name: host, CertChain: filepath.Join(tlsDir, "live", host+".crt"), PrivateKey: filepath.Join(tlsDir, "live", host+".key"),
		SDS: filepath.Join(tlsDir, "0.sds.json"), Rules: []l7.Rule{{Host: host, PathPatterns: []string{"/deny"}, Action: l7.Deny}}}
	sds, err := SDSSecret(ic)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(ic.SDS, sds, 0o600)
	gw := netip.MustParseAddr("127.0.0.84")
	c := Config{Links: []Link{{Addr: gw, Ports: []int{443}, Allow: []string{host}, Intercept: []Intercept{ic}}},
		AdminSocket: filepath.Join(dir, "admin.sock"), Resolvers: []netip.Addr{netip.MustParseAddr("127.0.0.53")}, AccessLog: filepath.Join(dir, "conn.log"),
		UpstreamCAs: "/etc/ssl/certs/ca-certificates.crt"}
	runGateway(t, dir, envoy, &c)

	pool := x509.NewCertPool()
	for _, f := range []string{ca1, ca2} {
		b, _ := os.ReadFile(f)
		pool.AppendCertsFromPEM(b)
	}
	leafKey := func(v string) []byte {
		b, _ := os.ReadFile(filepath.Join(tlsDir, v, host+".crt"))
		return b
	}
	dial := func() (*tls.Conn, []byte) {
		conn, err := tls.Dial("tcp", gw.String()+":443", &tls.Config{ServerName: host, RootCAs: pool, NextProtos: []string{"http/1.1"}})
		if err != nil {
			t.Fatal(err)
		}
		return conn, conn.ConnectionState().PeerCertificates[0].Raw
	}
	pemOf := func(v string) []byte {
		b := leafKey(v)
		blk, _ := pemDecode(b)
		return blk
	}
	ask := func(conn *tls.Conn, r *bufio.Reader) (int, error) {
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(conn, "GET /deny HTTP/1.1\r\nHost: "+host+"\r\n\r\n"); err != nil {
			return 0, err
		}
		resp, err := http.ReadResponse(r, nil)
		if err != nil {
			return 0, err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode, nil
	}

	old, first := dial()
	defer old.Close()
	oldR := bufio.NewReader(old)
	if !bytes.Equal(first, pemOf("v1")) {
		t.Fatal("not serving v1 at start")
	}
	if code, err := ask(old, oldR); code != 403 || err != nil {
		t.Fatalf("before the swap: %d %v", code, err)
	}
	// the swap: a new symlink renamed over the old one, as sandboxd does it
	tmp := filepath.Join(tlsDir, "live.tmp")
	os.Symlink("v2", tmp)
	if err := os.Rename(tmp, filepath.Join(tlsDir, "live")); err != nil {
		t.Fatal(err)
	}
	var now []byte
	for i := 0; i < 50; i++ {
		var c *tls.Conn
		c, now = dial()
		c.Close()
		if bytes.Equal(now, pemOf("v2")) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !bytes.Equal(now, pemOf("v2")) {
		t.Fatal("still serving the old leaf 5 s after the swap")
	}
	if code, err := ask(old, oldR); code != 403 || err != nil {
		t.Errorf("the connection opened before the swap: %d %v", code, err)
	}
	t.Log(fmt.Sprintf("rotated; the old connection still serves"))
}

func pemDecode(b []byte) ([]byte, bool) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, false
	}
	return blk.Bytes, true
}
