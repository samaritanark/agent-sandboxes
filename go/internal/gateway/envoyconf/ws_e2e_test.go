package envoyconf

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
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
	"google.golang.org/grpc"
)

// wsConn is a minimal WebSocket client for the end-to-end tests (RFC 6455: masked client frames,
// no extensions).
type wsConn struct {
	c net.Conn
	r *bufio.Reader
}

func wsDial(t *testing.T, gw netip.Addr, host, path, caFile string, hdrs ...string) (*wsConn, *http.Response) {
	pool := x509.NewCertPool()
	b, _ := os.ReadFile(caFile)
	pool.AppendCertsFromPEM(b)
	c, err := tls.Dial("tcp", gw.String()+":443", &tls.Config{ServerName: host, RootCAs: pool, NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(20 * time.Second))
	key := make([]byte, 16)
	rand.Read(key)
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n",
		path, host, base64.StdEncoding.EncodeToString(key))
	for _, h := range hdrs {
		req += h + "\r\n"
	}
	io.WriteString(c, req+"\r\n")
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &wsConn{c: c, r: r}, resp
}

func (w *wsConn) send(op byte, payload []byte) error {
	h := []byte{0x80 | op}
	switch n := len(payload); {
	case n < 126:
		h = append(h, 0x80|byte(n))
	case n < 1<<16:
		h = append(h, 0x80|126, byte(n>>8), byte(n))
	default:
		h = append(h, 0x80|127)
		h = binary.BigEndian.AppendUint64(h, uint64(n))
	}
	mask := make([]byte, 4)
	rand.Read(mask)
	h = append(h, mask...)
	m := make([]byte, len(payload))
	for i := range payload {
		m[i] = payload[i] ^ mask[i%4]
	}
	_, err := w.c.Write(append(h, m...))
	return err
}

// recv reads one frame: its first byte (FIN, RSV, opcode) and payload.
func (w *wsConn) recv() (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(w.r, h[:]); err != nil {
		return 0, nil, err
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var e [2]byte
		if _, err := io.ReadFull(w.r, e[:]); err != nil {
			return 0, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(e[:]))
	case 127:
		var e [8]byte
		if _, err := io.ReadFull(w.r, e[:]); err != nil {
			return 0, nil, err
		}
		n = binary.BigEndian.Uint64(e[:])
	}
	if h[1]&0x80 != 0 {
		return 0, nil, fmt.Errorf("a masked server frame")
	}
	p := make([]byte, n)
	_, err := io.ReadFull(w.r, p)
	return h[0], p, err
}

// probeProc records what Envoy's ext_proc sends after an upgrade, and replaces one marker in the
// response body with another of a given length.
type probeProc struct {
	extprocv3.UnimplementedExternalProcessorServer
	from, to []byte
	mu       sync.Mutex
	status   string
	chunks   [][]byte
	ends     int
}

func (p *probeProc) Process(s extprocv3.ExternalProcessor_ProcessServer) error {
	for {
		req, err := s.Recv()
		if err != nil {
			return nil
		}
		resp := &extprocv3.ProcessingResponse{}
		switch r := req.Request.(type) {
		case *extprocv3.ProcessingRequest_RequestHeaders:
			resp.Response = &extprocv3.ProcessingResponse_RequestHeaders{RequestHeaders: &extprocv3.HeadersResponse{}}
		case *extprocv3.ProcessingRequest_ResponseHeaders:
			for _, h := range r.ResponseHeaders.GetHeaders().GetHeaders() {
				if h.Key == ":status" {
					p.mu.Lock()
					p.status = h.Value + string(h.RawValue)
					p.mu.Unlock()
				}
			}
			resp.Response = &extprocv3.ProcessingResponse_ResponseHeaders{ResponseHeaders: &extprocv3.HeadersResponse{}}
		case *extprocv3.ProcessingRequest_ResponseBody:
			b := r.ResponseBody.GetBody()
			p.mu.Lock()
			p.chunks = append(p.chunks, append([]byte(nil), b...))
			if r.ResponseBody.GetEndOfStream() {
				p.ends++
			}
			p.mu.Unlock()
			b = bytes.ReplaceAll(b, p.from, p.to)
			resp.Response = &extprocv3.ProcessingResponse_ResponseBody{ResponseBody: &extprocv3.BodyResponse{
				Response: &extprocv3.CommonResponse{BodyMutation: &extprocv3.BodyMutation{Mutation: &extprocv3.BodyMutation_Body{Body: b}}}}}
		default:
			resp.Response = &extprocv3.ProcessingResponse_RequestBody{RequestBody: &extprocv3.BodyResponse{}}
		}
		if err := s.Send(resp); err != nil {
			return err
		}
	}
}

// TestWebSocketThroughInterception: an intercepted name's WebSocket reaches a real server (the
// upgrade leaves over HTTP/1.1), and ext_proc sees the server's frames as response body and can
// change them (ENVOY, SANDBOX_NET_TEST=1, root, the internet: echo.websocket.org). This is what
// the broker's FrameScrubber relies on.
func TestWebSocketThroughInterception(t *testing.T) {
	envoy := os.Getenv("ENVOY")
	if envoy == "" || os.Getenv("SANDBOX_NET_TEST") == "" || os.Geteuid() != 0 {
		t.Skip("needs ENVOY, SANDBOX_NET_TEST=1, root, and the internet")
	}
	const host = "echo.websocket.org"
	dir := t.TempDir()
	caFile := testCA(t, dir, host)
	p := &probeProc{from: []byte("probe-AAAA"), to: []byte("probe-BBBB")}
	sock := filepath.Join(dir, "probe.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(g, p)
	go g.Serve(ln)
	defer g.Stop()
	gw := netip.MustParseAddr("127.0.0.80")
	c := Config{Links: []Link{{Addr: gw, Ports: []int{443}, Allow: []string{host},
		Intercept: []Intercept{{Name: host, CertChain: filepath.Join(dir, host+".crt"), PrivateKey: filepath.Join(dir, host+".key")}}, BrokerSocket: sock}},
		AdminSocket: filepath.Join(dir, "admin.sock"), Resolvers: hostResolvers(t), AccessLog: filepath.Join(dir, "conn.log"),
		UpstreamCAs: "/etc/ssl/certs/ca-certificates.crt"}
	runGateway(t, dir, envoy, &c)

	w, resp := wsDial(t, gw, host, "/", caFile)
	if resp.StatusCode != 101 {
		logb, _ := os.ReadFile(c.AccessLog)
		t.Fatalf("no upgrade: %s\n%s", resp.Status, logb)
	}
	defer w.c.Close()
	long := strings.Repeat("x", 300) + "probe-AAAA"
	for _, msg := range []string{"hello probe-AAAA", long} {
		if err := w.send(1, []byte(msg)); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	for len(got) < 3 {
		_, pl, err := w.recv()
		if err != nil {
			t.Fatalf("after %q: %v", got, err)
		}
		got = append(got, string(pl))
	}
	// the server greets first, then echoes; ext_proc's change reached the client
	if got[1] != "hello probe-BBBB" || got[2] != strings.Replace(long, "AAAA", "BBBB", 1) {
		t.Errorf("echoes %q", got[1:])
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.status != "101" || len(p.chunks) == 0 {
		t.Errorf("ext_proc saw status %s and %d body chunks", p.status, len(p.chunks))
	}
}
