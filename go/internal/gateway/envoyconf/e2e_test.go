package envoyconf

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"

	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/authz"
)

// hostResolvers is the host's upstream DNS (systemd-resolved's real servers, not its stub).
func hostResolvers(t *testing.T) []netip.Addr {
	f, err := os.Open("/run/systemd/resolve/resolv.conf")
	if err != nil {
		t.Skip("no systemd-resolved upstream list")
	}
	defer f.Close()
	var out []netip.Addr
	sc := bufio.NewScanner(f)
	defer func() {
		if sc.Err() != nil {
			t.Fatal(sc.Err())
		}
	}()
	for sc.Scan() {
		if fs := strings.Fields(sc.Text()); len(fs) == 2 && fs[0] == "nameserver" {
			if a, err := netip.ParseAddr(fs[1]); err == nil && a.Is4() {
				out = append(out, a)
			}
		}
	}
	return out
}

// TestEndToEnd runs Envoy with the generated bootstrap and the authz service, and sends real
// TLS through it (ENVOY=path, SANDBOX_NET_TEST=1, as root: the listener binds port 443).
func TestEndToEnd(t *testing.T) {
	envoy := os.Getenv("ENVOY")
	if envoy == "" || os.Getenv("SANDBOX_NET_TEST") == "" || os.Geteuid() != 0 {
		t.Skip("needs ENVOY, SANDBOX_NET_TEST=1, root, and the internet")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "authz.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var decisions []authz.Decision
	s := &authz.Server{Record: func(d authz.Decision) { mu.Lock(); decisions = append(decisions, d); mu.Unlock() }}
	allow, block := []string{"*.github.com", "github.com"}, []string{"*.githubusercontent.com", "gist.github.com"}
	s.SetPolicy(&authz.Policy{Allow: allow, BlockDomains: block})
	g := grpc.NewServer()
	authv3.RegisterAuthorizationServer(g, s)
	go g.Serve(ln)
	defer g.Stop()

	gw := netip.MustParseAddr("127.0.0.77")
	c := Config{Allow: allow, BlockDomains: block, Listen: gw, Ports: []int{443}, AuthzSocket: sock, AdminSocket: filepath.Join(dir, "admin.sock"),
		Resolvers: hostResolvers(t), AccessLog: filepath.Join(dir, "conn.log")}
	b, err := c.Bootstrap()
	if err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "envoy.json")
	os.WriteFile(conf, b, 0o600)
	e := exec.Command(envoy, Args(conf)...)
	e.Stderr = os.Stderr
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { e.Process.Kill(); e.Wait() }()
	for i := 0; ; i++ {
		if c, err := net.DialTimeout("tcp", gw.String()+":443", time.Second); err == nil {
			c.Close()
			break
		}
		if i > 50 {
			t.Fatal("envoy did not listen")
		}
		time.Sleep(100 * time.Millisecond)
	}
	curl := func(host string) (string, error) {
		out, err := exec.Command("curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15",
			"--resolve", host+":443:"+gw.String(), "https://"+host+"/").CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	if code, err := curl("api.github.com"); err != nil || code == "000" {
		t.Errorf("allowed host: %s %v", code, err)
	}
	for _, h := range []string{"gist.github.com", "raw.githubusercontent.com", "example.com"} {
		if code, err := curl(h); err == nil {
			t.Errorf("%s got through: %s", h, code)
		}
	}
	// no SNI at all: an IP address
	if out, err := exec.Command("curl", "-sk", "--max-time", "10", "https://"+gw.String()+"/").CombinedOutput(); err == nil {
		t.Errorf("a connection without SNI got through: %s", out)
	}
	time.Sleep(time.Second) // the last check is recorded asynchronously
	// a refused name must never be looked up upstream (DNS would carry it out of the session)
	st, _ := exec.Command("curl", "-s", "--unix-socket", c.AdminSocket, "http://admin/stats?filter=dns_cache").CombinedOutput()
	t.Logf("dns cache stats:\n%s", st)
	if !strings.Contains(string(st), "dns_cache.sandbox_dns.dns_query_attempt: 1\n") {
		t.Errorf("names other than the allowed one were looked up:\n%s", st)
	}
	hosts, _ := exec.Command("curl", "-s", "--unix-socket", c.AdminSocket, "http://admin/clusters").CombinedOutput()
	for _, l := range strings.Split(string(hosts), "\n") {
		if strings.Contains(l, "::hostname::") && strings.HasPrefix(l, "upstream::") && !strings.Contains(l, "hostname::api.github.com:443") {
			t.Errorf("a refused name became an upstream host: %s", l)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	allowed, denied, noSNI := 0, 0, 0
	for _, d := range decisions {
		if d.SNI == "" {
			noSNI++
		}
		if d.Allowed {
			allowed++
		} else {
			denied++
		}
	}
	// the check sees allowed names; refusals are closed before it and recorded by Envoy
	if allowed != 1 || denied != 0 || noSNI != 0 {
		t.Errorf("decisions %+v", decisions)
	}
	logb, _ := os.ReadFile(c.AccessLog)
	if n := strings.Count(string(logb), `"refused":true`); n != 4 {
		t.Errorf("%d refusals logged, want 4:\n%s", n, logb)
	}
	for _, sni := range []string{`"sni":"gist.github.com"`, `"sni":"raw.githubusercontent.com"`, `"sni":"example.com"`, `"sni":null`} {
		if !strings.Contains(string(logb), sni) {
			t.Errorf("no log line with %s", sni)
		}
	}
	t.Logf("decisions: %+v", decisions)
	if b, err := os.ReadFile(c.AccessLog); err == nil {
		t.Logf("connection log:\n%s", b)
	}
}
