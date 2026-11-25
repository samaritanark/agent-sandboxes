package envoyconf

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"

	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/broker"
	"github.com/samaritanark/agent-sandboxes/go/internal/l7"
)

// TestBrokerEndToEnd injects a credential through Envoy and the broker toward a real upstream that
// echoes requests (httpbin.org), and checks what the client receives, never the broker's own word
// (ENVOY=path, SANDBOX_NET_TEST=1, root, and the internet).
func TestBrokerEndToEnd(t *testing.T) {
	envoy := os.Getenv("ENVOY")
	if envoy == "" || os.Getenv("SANDBOX_NET_TEST") == "" || os.Geteuid() != 0 {
		t.Skip("needs ENVOY, SANDBOX_NET_TEST=1, root, and the internet")
	}
	dir := t.TempDir()
	caFile := testCA(t, dir, "httpbin.org", "api.github.com")
	const secret = "realsecret-0123456789abcdef"
	ph := "sbxph_" + strings.Repeat("Q", 43)
	set, err := broker.NewSet([]broker.Binding{{Ref: "hb", Hosts: []string{"httpbin.org"}, Inject: "bearer", Placeholder: ph, Value: secret}})
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

	rules := []l7.Rule{{Host: l7.AnyHost, Methods: []string{"TRACE", "TRACK"}, Action: l7.Deny}}
	ic := func(n string) Intercept {
		return Intercept{Name: n, CertChain: filepath.Join(dir, n+".crt"), PrivateKey: filepath.Join(dir, n+".key"), Rules: rules}
	}
	gw := netip.MustParseAddr("127.0.0.79")
	c := Config{Links: []Link{{Addr: gw, Ports: []int{443}, Allow: []string{"httpbin.org", "api.github.com"},
		Intercept: []Intercept{ic("httpbin.org"), ic("api.github.com")}, BrokerSocket: bsock}},
		AdminSocket: filepath.Join(dir, "admin.sock"), Resolvers: hostResolvers(t), AccessLog: filepath.Join(dir, "conn.log"),
		UpstreamCAs: "/etc/ssl/certs/ca-certificates.crt"}
	runGateway(t, dir, envoy, &c)

	get := func(url string, hdrs ...string) (string, string) {
		host := strings.SplitN(strings.TrimPrefix(url, "https://"), "/", 2)[0]
		args := []string{"-sS", "-N", "-o", "-", "-w", "\n%{http_code}", "--max-time", "20", "--cacert", caFile, "--resolve", host + ":443:" + gw.String()}
		for _, h := range hdrs {
			args = append(args, "-H", h)
		}
		out, err := exec.Command("curl", append(args, url)...).CombinedOutput()
		s := strings.TrimSpace(string(out))
		i := strings.LastIndex(s, "\n")
		if err != nil || i < 0 {
			return "error: " + s, ""
		}
		return s[i+1:], s[:i]
	}
	bearer := "Authorization: Bearer " + ph
	// injected, and the echo of the real value comes back as the placeholder
	code, body := get("https://httpbin.org/headers", bearer)
	if code != "200" || strings.Contains(body, secret) || !strings.Contains(body, "Bearer "+ph) {
		t.Errorf("echo: %s\n%s", code, body)
	}
	// a stream of echoes, scrubbed across chunks
	code, body = get("https://httpbin.org/stream/5", bearer)
	if code != "200" || strings.Contains(body, secret) || strings.Count(body, ph) != 5 {
		t.Errorf("stream: %s %d placeholders, leaked %v", code, strings.Count(body, ph), strings.Contains(body, secret))
	}
	// the bound destination without the placeholder, and the placeholder elsewhere: refused
	if code, body = get("https://httpbin.org/headers"); code != "403" || !strings.Contains(body, "credential broker") {
		t.Errorf("no placeholder: %s %s", code, body)
	}
	if code, body = get("https://api.github.com/zen", bearer); code != "403" || !strings.Contains(body, "credential broker") {
		t.Errorf("misuse: %s %s", code, body)
	}
	if code, _ = get("https://api.github.com/zen"); code != "200" {
		t.Errorf("an unbound intercepted host: %s", code)
	}
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	kinds := map[string]int{}
	for _, e := range events {
		kinds[e.Type]++
		if strings.Contains(e.Reason+e.Path, secret) || strings.Contains(e.Reason+e.Path, ph) {
			t.Errorf("an event carries a value: %+v", e)
		}
	}
	mu.Unlock()
	if kinds["credential_injected"] != 2 || kinds["credential_reflection"] != 2 || kinds["credential_missing"] != 1 || kinds["credential_misuse"] != 1 {
		t.Errorf("events %v", kinds)
	}
	// the broker down: nothing is forwarded, and nothing leaks
	g.Stop()
	if code, body = get("https://httpbin.org/headers", bearer); code == "200" || strings.Contains(body, secret) {
		t.Errorf("with the broker down: %s %s", code, body)
	}
	logb, _ := os.ReadFile(c.AccessLog)
	if strings.Contains(string(logb), secret) || strings.Contains(string(logb), ph) {
		t.Error("a value reached the log")
	}
	t.Logf("events %v", kinds)
}
