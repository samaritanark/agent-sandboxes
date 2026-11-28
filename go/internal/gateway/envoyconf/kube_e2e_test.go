package envoyconf

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"

	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/broker"
	"github.com/samaritanark/agent-sandboxes/go/internal/kubeapi"
)

// kubePKI is a cluster's CA with a server certificate for addr, and a client CA with one client
// certificate, written to dir.
type kubePKI struct {
	caFile, serverCert, serverKey string
	clientCAs                     *x509.CertPool
	clientCert, clientKey         string
}

func newKubePKI(t *testing.T, dir string, addr netip.Addr) kubePKI {
	mk := func(name string, isCA bool, parent *x509.Certificate, pkey *ecdsa.PrivateKey, mod func(*x509.Certificate)) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true}
		if isCA {
			tpl.KeyUsage = x509.KeyUsageCertSign
		}
		if mod != nil {
			mod(tpl)
		}
		if parent == nil {
			parent, pkey = tpl, k
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &k.PublicKey, pkey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, k, der
	}
	write := func(name string, der []byte, k *ecdsa.PrivateKey) (string, string) {
		cf, kf := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
		os.WriteFile(cf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
		kd, _ := x509.MarshalPKCS8PrivateKey(k)
		os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
		return cf, kf
	}
	ca, caKey, caDER := mk("cluster CA", true, nil, nil, nil)
	_, sk, sDER := mk("apiserver", false, ca, caKey, func(c *x509.Certificate) {
		c.IPAddresses = []net.IP{net.IP(addr.AsSlice())}
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	})
	cca, ccaKey, _ := mk("client CA", true, nil, nil, nil)
	_, ck, cDER := mk("agent", false, cca, ccaKey, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} })
	p := kubePKI{clientCAs: x509.NewCertPool()}
	p.clientCAs.AddCert(cca)
	p.caFile, _ = write("cluster-ca", caDER, caKey)
	p.serverCert, p.serverKey = write("apiserver-"+addr.String(), sDER, sk)
	p.clientCert, p.clientKey = write("client", cDER, ck)
	return p
}

// fakeAPIServer echoes what reached it: the path, the authorization header, and the client
// certificate's name; an upgrade is answered with 101 and the same line.
func fakeAPIServer(t *testing.T, addr netip.Addr, p kubePKI, mtls bool) {
	cert, err := tls.LoadX509KeyPair(p.serverCert, p.serverKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}
	if mtls {
		cfg.ClientAuth, cfg.ClientCAs = tls.RequireAndVerifyClientCert, p.clientCAs
	}
	ln, err := tls.Listen("tcp", netip.AddrPortFrom(addr, 6443).String(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			who = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		// the credential itself is never echoed (the broker would scrub it): only whether it was right
		auth := r.Header.Get("Authorization")
		switch auth {
		case "Bearer " + kubeToken:
			auth = "token"
		case "":
			auth = "none"
		}
		body, _ := io.ReadAll(r.Body)
		line := fmt.Sprintf("path=%s auth=%s client=%q", r.URL.RequestURI(), auth, who)
		if len(body) > 0 {
			line += fmt.Sprintf(" body=%d", len(body))
		}
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			wsExecServer(w, r)
			return
		}
		if strings.EqualFold(r.Header.Get("Upgrade"), "SPDY/3.1") {
			c, rw, _ := w.(http.Hijacker).Hijack()
			rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\n\r\n" + line + "\n")
			rw.Flush()
			time.Sleep(200 * time.Millisecond)
			c.Close()
			return
		}
		fmt.Fprintln(w, line)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
}

// kubeToken is the real token of the test's bearer cluster.
const kubeToken = "eyJrealkubetoken"

// TestKubeEndToEnd sends kubectl-shaped requests through Envoy and the broker to two fake API
// servers, one taking a bearer token and one a client certificate, and checks what reached them
// (ENVOY=path, SANDBOX_NET_TEST=1, root).
func TestKubeEndToEnd(t *testing.T) {
	envoy := os.Getenv("ENVOY")
	if envoy == "" || os.Getenv("SANDBOX_NET_TEST") == "" || os.Geteuid() != 0 {
		t.Skip("needs ENVOY, SANDBOX_NET_TEST=1, and root")
	}
	dir := t.TempDir()
	k0, k1 := "kube-0.gw.sandbox.internal", "kube-1.gw.sandbox.internal"
	gwCA := testCA(t, dir, k0, k1)
	a0, a1 := netip.MustParseAddr("127.0.0.81"), netip.MustParseAddr("127.0.0.82")
	p0, p1 := newKubePKI(t, filepath.Join(dir), a0), newKubePKI(t, t.TempDir(), a1)
	fakeAPIServer(t, a0, p0, false)
	fakeAPIServer(t, a1, p1, true)

	const token = kubeToken
	ph0, ph1 := "sbxph_"+strings.Repeat("K", 43), "sbxph_"+strings.Repeat("M", 43)
	set, err := broker.NewSet([]broker.Binding{
		{Ref: "infra.kube.0", Hosts: []string{k0}, Inject: "bearer", Placeholder: ph0, Value: token},
		{Ref: "infra.kube.1", Hosts: []string{k1}, Inject: "mtls", Placeholder: ph1, Value: "x"}})
	if err != nil {
		t.Fatal(err)
	}
	bs := &broker.Server{Record: func(e broker.Event) { t.Logf("event %+v", e) }}
	bs.SetBindings(set)
	bsock := filepath.Join(dir, "broker.sock")
	ln, err := net.Listen("unix", bsock)
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(g, bs)
	go g.Serve(ln)
	defer g.Stop()

	ic := func(n string, k Kube) Intercept {
		return Intercept{Name: n, CertChain: filepath.Join(dir, n+".crt"), PrivateKey: filepath.Join(dir, n+".key"), Rules: kubeapi.DenyRules(n), Kube: &k}
	}
	gw := netip.MustParseAddr("127.0.0.79")
	c := Config{Links: []Link{{Addr: gw, Ports: []int{443}, Allow: []string{k0, k1}, BrokerSocket: bsock, Intercept: []Intercept{
		ic(k0, Kube{Host: a0.String(), Port: 6443, SNI: a0.String(), CAFile: p0.caFile}),
		ic(k1, Kube{Host: a1.String(), Port: 6443, SNI: a1.String(), CAFile: p1.caFile, PathPrefix: "/k8s/clusters/c-1",
			ClientCert: p1.clientCert, ClientKey: p1.clientKey}),
	}}}, AdminSocket: filepath.Join(dir, "admin.sock"), Resolvers: []netip.Addr{netip.MustParseAddr("127.0.0.53")},
		AccessLog: filepath.Join(dir, "conn.log"), UpstreamCAs: "/etc/ssl/certs/ca-certificates.crt"}
	runGateway(t, dir, envoy, &c)

	get := func(name, path string, hdrs ...string) (string, string) {
		args := []string{"-sS", "-o", "-", "-w", "\n%{http_code}", "--max-time", "10", "--cacert", gwCA, "--resolve", name + ":443:" + gw.String()}
		for _, h := range hdrs {
			args = append(args, "-H", h)
		}
		out, _ := exec.Command("curl", append(args, "https://"+name+path)...).CombinedOutput()
		s := strings.TrimSpace(string(out))
		i := strings.LastIndex(s, "\n")
		if i < 0 {
			return s, ""
		}
		return s[i+1:], s[:i]
	}
	if code, body := get(k0, "/api/v1/namespaces/default/pods?limit=5", "Authorization: Bearer "+ph0); code != "200" ||
		!strings.Contains(body, `path=/api/v1/namespaces/default/pods?limit=5 auth=token`) {
		t.Errorf("token cluster: %s %s", code, body)
	}
	if code, body := get(k0, "/api/v1/namespaces/default/secrets", "Authorization: Bearer "+ph0); code != "403" || strings.Contains(body, "path=") {
		t.Errorf("secrets: %s %s", code, body)
	}
	if code, _ := get(k0, "/api/v1/namespaces/default/pods"); code != "200" {
		// no credential at all goes on unauthenticated (the API server answers 401 for real)
		t.Errorf("anonymous: %s", code)
	}
	if code, body := get(k1, "/api", "Authorization: Bearer "+ph1); code != "200" || !strings.Contains(body, `path=/k8s/clusters/c-1/api auth=none client="agent"`) {
		t.Errorf("mtls cluster: %s %s", code, body)
	}
	if code, body := get(k1, "/api"); code != "403" || strings.Contains(body, "path=") {
		t.Errorf("mtls without the placeholder: %s %s", code, body)
	}
	// a workload's body is checked before it goes on: a privileged pod is refused, an ordinary one
	// arrives whole
	postBody := func(body string) (string, string) {
		args := []string{"-sS", "-o", "-", "-w", "\n%{http_code}", "--max-time", "10", "--cacert", gwCA, "--resolve", k0 + ":443:" + gw.String(),
			"-H", "Authorization: Bearer " + ph0, "-H", "Content-Type: application/json", "--data-binary", body}
		out, _ := exec.Command("curl", append(args, "https://"+k0+"/api/v1/namespaces/default/pods")...).CombinedOutput()
		s := strings.TrimSpace(string(out))
		i := strings.LastIndex(s, "\n")
		if i < 0 {
			return s, ""
		}
		return s[i+1:], s[:i]
	}
	priv := `{"kind":"Pod","spec":{"containers":[{"name":"x","securityContext":{"privileged":true}}]}}`
	if code, body := postBody(priv); code != "403" || strings.Contains(body, "path=") {
		t.Errorf("privileged pod: %s %s", code, body)
	}
	ok := `{"kind":"Pod","spec":{"containers":[{"name":"x","image":"nginx"}]}}`
	if code, body := postBody(ok); code != "200" || !strings.Contains(body, fmt.Sprintf("auth=token client=\"\" body=%d", len(ok))) {
		t.Errorf("ordinary pod: %s %s", code, body)
	}
	// kubectl exec over SPDY
	conf := &tls.Config{ServerName: k0, RootCAs: x509.NewCertPool()}
	pemCA, _ := os.ReadFile(gwCA)
	conf.RootCAs.AppendCertsFromPEM(pemCA)
	conn, err := tls.Dial("tcp", gw.String()+":443", conf)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST /api/v1/namespaces/a/pods/p/exec?command=sh HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\nX-Stream-Protocol-Version: v4.channel.k8s.io\r\n\r\n", k0, ph0)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	status, _ := r.ReadString('\n')
	rest := ""
	for {
		l, err := r.ReadString('\n')
		rest += l
		if err != nil || strings.HasPrefix(l, "path=") {
			break
		}
	}
	if !strings.Contains(status, "101") || !strings.Contains(rest, `auth=token`) {
		t.Errorf("SPDY upgrade: %q %q", status, rest)
	}
	// kubectl exec over WebSocket (kubectl 1.30+): long binary transfers both ways, and a slow
	// stream that outlasts the broker's message and call timeouts, arrive whole
	wsDial := func(mode string) (*tls.Conn, *bufio.Reader) {
		conn, err := tls.Dial("tcp", gw.String()+":443", conf)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "GET /api/v1/namespaces/a/pods/p/exec?command=sh&mode=%s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\n"+
			"Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
			"Sec-WebSocket-Protocol: v5.channel.k8s.io\r\n\r\n", mode, k0, ph0)
		conn.SetDeadline(time.Now().Add(60 * time.Second))
		r := bufio.NewReader(conn)
		status, _ := r.ReadString('\n')
		for {
			l, err := r.ReadString('\n')
			if err != nil || l == "\r\n" {
				break
			}
		}
		if !strings.Contains(status, "101") {
			t.Fatalf("WebSocket upgrade (%s): %q", mode, status)
		}
		return conn, r
	}
	for _, mode := range []string{"down", "slow"} {
		conn, r := wsDial(mode)
		n, sum, text, err := wsReadAll(r)
		conn.Close()
		if want := wsExpect(mode); err != nil || n != want.n || sum != want.sum || text != "auth=token" {
			t.Errorf("WebSocket %s: %d bytes (want %d), sum %x (want %x), %q, %v", mode, n, want.n, sum, want.sum, text, err)
		}
	}
	conn, r = wsDial("up")
	up := wsPattern(64 << 20)
	go func() {
		for off := 0; off < len(up); off += 1 << 16 {
			conn.Write(wsClientFrame(0x2, up[off:min(off+1<<16, len(up))]))
		}
		conn.Write(wsClientFrame(0x8, []byte{0x03, 0xe8}))
	}()
	if _, _, text, err := wsReadAll(r); err != nil || text != fmt.Sprintf("auth=token got=%d sum=%x", len(up), wsSum(up)) {
		t.Errorf("WebSocket upload: %q %v", text, err)
	}
	conn.Close()
	logb, _ := os.ReadFile(c.AccessLog)
	if strings.Contains(string(logb), token) || strings.Contains(string(logb), ph0) {
		t.Error("a value reached the log")
	}
}
