package envoyconf

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/miekg/dns"
	"google.golang.org/grpc"

	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/broker"
)

// rawFrame encodes an unmasked server frame; b0 is the whole first byte (FIN, RSV, opcode).
func rawFrame(b0 byte, p []byte) []byte {
	h := []byte{b0}
	switch {
	case len(p) < 126:
		h = append(h, byte(len(p)))
	default:
		h = append(h, 126, byte(len(p)>>8), byte(len(p)))
	}
	return append(h, p...)
}

// wsEchoServer is a WebSocket server that reflects the request's Authorization header back in
// frames: a text message split across three fragments (cutting through the value), a ping, the
// echo of the client's first message, and a close reason.
func wsEchoServer(t *testing.T, addr, certFile, keyFile string) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		c, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		ext := ""
		if r.URL.Path == "/ext" {
			ext = "Sec-WebSocket-Extensions: permessage-deflate\r\n"
		}
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" + ext +
			"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n")
		rw.Flush()
		auth := []byte("auth=" + r.Header.Get("Authorization"))
		if r.URL.Path == "/bad" {
			c.Write(rawFrame(0xC1, auth)) // RSV1: a compressed frame nobody negotiated
			time.Sleep(time.Second)
			return
		}
		a, b := len(auth)/3, 2*len(auth)/3
		send := func(fs ...[]byte) {
			for _, f := range fs {
				c.Write(f)
				time.Sleep(20 * time.Millisecond) // separate writes, so the chunks differ from the frames
			}
		}
		send(rawFrame(0x01, auth[:a]), rawFrame(0x00, auth[a:b]), rawFrame(0x80, auth[b:]))
		send(rawFrame(0x89, append([]byte("p:"), r.Header.Get("Authorization")[7:]...)))
		// the client's first frame (masked), echoed as text
		var hb [2]byte
		io.ReadFull(rw, hb[:])
		n := int(hb[1] & 0x7f)
		var mask [4]byte
		io.ReadFull(rw, mask[:])
		p := make([]byte, n)
		io.ReadFull(rw, p)
		for i := range p {
			p[i] ^= mask[i%4]
		}
		send(rawFrame(0x81, p))
		send(rawFrame(0x88, append([]byte{0x03, 0xe8}, "bye "+r.Header.Get("Authorization")[7:]...)))
		time.Sleep(500 * time.Millisecond)
	})
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
}

// TestBrokerWebSocketEndToEnd injects a credential into a WebSocket handshake through Envoy and the
// broker, toward a local server that reflects it in every kind of frame, and checks what the
// client receives (ENVOY, SANDBOX_NET_TEST=1, root; no internet: a local DNS server and upstream).
func TestBrokerWebSocketEndToEnd(t *testing.T) {
	envoy := os.Getenv("ENVOY")
	if envoy == "" || os.Getenv("SANDBOX_NET_TEST") == "" || os.Geteuid() != 0 {
		t.Skip("needs ENVOY, SANDBOX_NET_TEST=1, and root")
	}
	const host = "wsecho.test"
	dir := t.TempDir()
	caFile := testCA(t, dir, host)
	upstream, resolverAddr := "127.0.0.81", "127.0.0.82"
	wsEchoServer(t, upstream+":443", filepath.Join(dir, host+".crt"), filepath.Join(dir, host+".key"))
	ds := &dns.Server{Addr: resolverAddr + ":53", Net: "udp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		if len(q.Question) == 1 && q.Question[0].Name == host+"." && q.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR(host + ". 60 IN A " + upstream)
			m.Answer = append(m.Answer, rr)
		}
		w.WriteMsg(m)
	})}
	go ds.ListenAndServe()
	defer ds.Shutdown()

	const secret = "ws-realsecret-0123456789abcdef"
	ph := "sbxph_" + strings.Repeat("W", 43)
	set, err := broker.NewSet([]broker.Binding{{Ref: "ws", Hosts: []string{host}, Inject: "bearer", Placeholder: ph, Value: secret}})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var events []broker.Event
	bs := &broker.Server{Record: func(e broker.Event) { mu.Lock(); events = append(events, e); mu.Unlock() }}
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
	gw := netip.MustParseAddr("127.0.0.83")
	c := Config{Links: []Link{{Addr: gw, Ports: []int{443}, Allow: []string{host},
		Intercept: []Intercept{{Name: host, CertChain: filepath.Join(dir, host+".crt"), PrivateKey: filepath.Join(dir, host+".key")}}, BrokerSocket: bsock}},
		AdminSocket: filepath.Join(dir, "admin.sock"), Resolvers: []netip.Addr{netip.MustParseAddr(resolverAddr)}, AccessLog: filepath.Join(dir, "conn.log"),
		UpstreamCAs: caFile}
	runGateway(t, dir, envoy, &c)
	bearer := "Authorization: Bearer " + ph

	w, resp := wsDial(t, gw, host, "/", caFile, bearer)
	if resp.StatusCode != 101 {
		logb, _ := os.ReadFile(c.AccessLog)
		t.Fatalf("no upgrade: %s\n%s", resp.Status, logb)
	}
	var raw bytes.Buffer
	read := func() (byte, []byte) {
		b0, p, err := w.recv()
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		raw.WriteByte(b0)
		raw.Write(p)
		return b0, p
	}
	// the fragmented message, reassembled: its value came back as the placeholder
	var msg []byte
	for {
		b0, p := read()
		msg = append(msg, p...)
		if b0&0x80 != 0 {
			break
		}
	}
	if string(msg) != "auth=Bearer "+ph {
		t.Errorf("message %q", msg)
	}
	if b0, p := read(); b0 != 0x89 || string(p) != "p:"+ph {
		t.Errorf("ping %x %q", b0, p)
	}
	w.send(1, []byte("hello "+ph))
	if _, p := read(); string(p) != "hello "+ph {
		t.Errorf("echo %q", p)
	}
	if b0, p := read(); b0 != 0x88 || !bytes.Equal(p, []byte{0x03, 0xe8}) {
		t.Errorf("close %x %q", b0, p)
	}
	w.c.Close()
	if bytes.Contains(raw.Bytes(), []byte(secret)) {
		t.Error("the value reached the client")
	}

	// a server that accepts an extension: refused before the client sees the upgrade
	if _, resp := wsDial(t, gw, host, "/ext", caFile, bearer); resp.StatusCode == 101 {
		t.Error("an extension was accepted on an injected connection")
	}
	// a server that sends a frame the broker cannot read: the connection is cut, nothing leaks
	w, resp = wsDial(t, gw, host, "/bad", caFile, bearer)
	if resp.StatusCode == 101 {
		b0, p, err := w.recv()
		if err == nil || bytes.Contains(p, []byte(secret)) {
			t.Errorf("an unreadable frame was relayed: %x %q %v", b0, p, err)
		}
		w.c.Close()
	}
	// any other upgrade toward the bound destination: refused (Envoy refuses an upgrade type it is
	// not configured for before the broker sees it; the broker's own refusal is in TestDecide)
	if _, resp := wsDial(t, gw, host, "/", caFile, bearer, "Upgrade: h2c"); resp.StatusCode != 403 {
		t.Errorf("an h2c upgrade: %s", resp.Status)
	}
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	kinds := map[string]int{}
	for _, e := range events {
		kinds[e.Type]++
		if strings.Contains(e.Reason+e.Path, secret) {
			t.Errorf("an event carries the value: %+v", e)
		}
	}
	if kinds["credential_injected"] < 3 || kinds["credential_reflection"] < 1 || kinds["refused"] != 2 {
		t.Errorf("events %v", kinds)
	}
	logb, _ := os.ReadFile(c.AccessLog)
	if bytes.Contains(logb, []byte(secret)) {
		t.Error("the value reached the log")
	}
	t.Logf("events %v", kinds)
}
