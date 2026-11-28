package app

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/brokerkey"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

// declarer is a driver whose host-reach control opens endpoints one by one.
type declarer struct {
	*driver.Mock
	declared map[string][]netip.AddrPort
	history  map[string][]netip.AddrPort // every declaration, closed or not
	expires  time.Time
	released int
}

func (d *declarer) DeclareEndpoints(_ context.Context, id string, eps []netip.AddrPort, exp time.Time) error {
	if d.declared == nil {
		d.declared = map[string][]netip.AddrPort{}
	}
	if d.history == nil {
		d.history = map[string][]netip.AddrPort{}
	}
	d.declared[id], d.history[id], d.expires = eps, eps, exp
	return nil
}

func (d *declarer) ReleaseEndpoints(_ context.Context, live func(string) bool) error {
	d.released++
	for id := range d.declared {
		if !live(id) {
			delete(d.declared, id)
		}
	}
	return nil
}

func (d *declarer) EndpointSessions(context.Context) ([]string, error) {
	var out []string
	for id := range d.declared {
		out = append(out, id)
	}
	return out, nil
}

// TestRunDeclaresHostEndpoints (design 5.2.6): a launch whose cluster or --infra-endpoint is an
// address of this machine (by address, or by a name that resolves to one here) declares it under a
// new session ID, bounded by the longest session's life, and hands the run the ID and endpoints;
// another machine's address and loopback are not declared; once the session is no longer live the
// endpoints are closed (a detached one's at the next command), and `vm stop` closes them all. A
// driver that cannot open endpoints one by one stops the launch.
func TestRunDeclaresHostEndpoints(t *testing.T) {
	state := t.TempDir()
	kubectl := func(args []string) ([]byte, string, error) {
		return view("k3d", "https://192.168.1.178:6443", map[string]any{"token": "t"}, nil), "", nil
	}
	d := &declarer{Mock: &driver.Mock{State: driver.Running}}
	tr := &fakeTransport{release: goodRelease}
	now := time.Unix(1800000000, 0)
	var out, errb bytes.Buffer
	env := Env{Driver: d, Transport: tr, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, StateDir: state,
		Now: func() time.Time { return now }, BrokerKey: brokerkey.File{Path: filepath.Join(state, "broker.key")}, Kubectl: kubectl,
		HostAddrs: func() ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("192.168.1.178/24"), netip.MustParsePrefix("127.0.0.1/8")}, nil
		},
		LookupHost: func(h string) ([]netip.Addr, error) {
			switch h {
			case "mymac.local":
				return []netip.Addr{netip.MustParseAddr("192.168.1.178")}, nil
			case "api.example.com":
				return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
			}
			return nil, errors.New("no such host")
		}}
	rc := Run(context.Background(), []string{"run", "--tier", "3", "--infra-kubeconfig", "/k/a.yaml",
		"--infra-endpoint", "http://mymac.local:8200/v1", "--infra-endpoint", "https://api.example.com", "--infra-endpoint", "https://127.0.0.1:9000",
		"--infra-endpoint", "https://192.168.1.178:6443", "--infra-endpoint", "http://mymac.local/plain"}, env)
	if rc != 0 {
		t.Fatalf("%d %s %s", rc, out.String(), errb.String())
	}
	if len(d.history) != 1 {
		t.Fatalf("declared %v", d.history)
	}
	var id string
	for k, eps := range d.history {
		id = k
		if len(eps) != 3 || eps[0].String() != "192.168.1.178:8200" || eps[1].String() != "192.168.1.178:6443" || eps[2].String() != "192.168.1.178:80" {
			t.Errorf("endpoints %v", eps)
		}
	}
	if !sessionIDRE.MatchString(id) || !strings.HasPrefix(id, "ses-"+now.UTC().Format("20060102-150405")) || !d.expires.Equal(now.Add(endpointLifetime)) {
		t.Errorf("id %q expires %v", id, d.expires)
	}
	runArgv := strings.Join(tr.runs[len(tr.runs)-1], " ")
	if !strings.Contains(runArgv, SessionIDEnv+"="+id) || !strings.Contains(runArgv, HostEndpointsEnv+"=192.168.1.178:8200,192.168.1.178:6443,192.168.1.178:80") {
		t.Errorf("run %q", runArgv)
	}
	if !strings.Contains(out.String(), "==> Declared host endpoint(s) 192.168.1.178:8200 192.168.1.178:6443 192.168.1.178:80 (this machine) for session "+id) {
		t.Errorf("%s", out.String())
	}
	// the session never appeared in sandboxd's list after the run: closed
	if tr.lists != 1 || len(d.declared) != 0 {
		t.Errorf("not closed: %d %v", tr.lists, d.declared)
	}

	// a keep-alive session stays open while sandboxd runs it, and closes at the next command after it ends
	d.declared = map[string][]netip.AddrPort{id: {netip.MustParseAddrPort("192.168.1.178:6443")}}
	tr.sessions = id + "\tinfra/claude\tRUNNING\t\n"
	Run(context.Background(), []string{"list"}, env)
	if len(d.declared) != 1 {
		t.Error("a live session's endpoints were closed")
	}
	tr.sessions = id + "\tinfra/claude\tTERMINATED\toperator stop\n"
	Run(context.Background(), []string{"list"}, env)
	if len(d.declared) != 0 {
		t.Error("an ended session's endpoints stayed open")
	}
	// vm stop closes every one
	d.declared = map[string][]netip.AddrPort{id: nil}
	tr.sessions = id + "\tinfra/claude\tRUNNING\t\n"
	Run(context.Background(), []string{"vm", "stop"}, env)
	if len(d.declared) != 0 {
		t.Error("vm stop left endpoints open")
	}

	// nothing of this machine's: nothing declared, no session ID
	d.State = driver.Running
	env.Kubectl = func(args []string) ([]byte, string, error) {
		return view("eks", "https://api.example.com", map[string]any{"token": "t"}, nil), "", nil
	}
	tr2 := &fakeTransport{release: goodRelease}
	env.Transport = tr2
	d.history = nil
	if Run(context.Background(), []string{"run", "--tier", "3", "--infra-kubeconfig", "/k/b.yaml"}, env) != 0 || len(d.history) != 0 ||
		strings.Contains(strings.Join(tr2.runs[len(tr2.runs)-1], " "), SessionIDEnv) || tr2.lists != 0 {
		t.Errorf("declared %v, run %q", d.declared, tr2.runs)
	}

	// a driver without per-endpoint control stops the launch before it runs
	env.Driver = &driver.Mock{State: driver.Running}
	env.Kubectl = kubectl
	tr3 := &fakeTransport{release: goodRelease}
	env.Transport = tr3
	errb.Reset()
	if rc := Run(context.Background(), []string{"run", "--tier", "3", "--infra-kubeconfig", "/k/a.yaml"}, env); rc != 1 ||
		!strings.Contains(errb.String(), "192.168.1.178:6443 is an address of this machine") || len(tr3.runs) != 0 {
		t.Errorf("%d %s %q", rc, errb.String(), tr3.runs)
	}
}
