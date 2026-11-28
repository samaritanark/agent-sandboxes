package daemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/gwpolicy"
	"github.com/samaritanark/agent-sandboxes/go/internal/l7"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/journal"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/limits"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/netsetup"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/pki"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/runtime"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

type fakeRuntime struct {
	vms       map[string]runtime.MicroVM
	started   map[string]bool
	calls     []string
	failStart string // an id whose Start fails
	failKill  string // an id whose Destroy fails
}

func (f *fakeRuntime) Create(_ context.Context, m runtime.MicroVM) error {
	if err := m.Check(); err != nil {
		return err
	}
	f.calls = append(f.calls, "create "+m.ID)
	f.vms[m.ID] = m
	return nil
}

func (f *fakeRuntime) Start(_ context.Context, id string) error {
	f.calls = append(f.calls, "start "+id)
	if id == f.failStart {
		return errors.New("boot failed: the file sh was not found\n\nStack backtrace:\n   0: <unknown>")
	}
	f.started[id] = true
	return nil
}

func (f *fakeRuntime) Destroy(_ context.Context, id string, _ time.Duration) error {
	f.calls = append(f.calls, "destroy "+id)
	if id == f.failKill {
		return errors.New("shim stuck")
	}
	delete(f.vms, id)
	delete(f.started, id)
	return nil
}

func (f *fakeRuntime) Running(_ context.Context, id string) (bool, error) { return f.started[id], nil }

func (f *fakeRuntime) Restart(_ context.Context, id string) error {
	f.calls = append(f.calls, "restart "+id)
	f.started[id] = true
	return nil
}

func (f *fakeRuntime) Exec(context.Context, string, string, []string, bool, io.Reader, io.Writer, io.Writer) (runtime.Process, error) {
	return nil, errors.New("this rig does not exec")
}

func (f *fakeRuntime) List(context.Context) ([]string, error) {
	var out []string
	for id := range f.vms {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

type fakeNS struct {
	names map[string]bool
	calls []string
}

func (f *fakeNS) Create(_ context.Context, n string) error {
	f.calls = append(f.calls, "netns "+n)
	if f.names[n] {
		return errors.New("exists")
	}
	f.names[n] = true
	return nil
}
func (f *fakeNS) Delete(_ context.Context, n string) error { delete(f.names, n); return nil }
func (f *fakeNS) List(context.Context) ([]string, error) {
	var out []string
	for n := range f.names {
		out = append(out, n)
	}
	return out, nil
}

type fakeNet struct {
	root    int
	uplinks []int
	fail    bool
	hosteps [][]netsetup.HostEndpoint // each HostEndpoints call
}

func (f *fakeNet) Root(context.Context) error { f.root++; return nil }
func (f *fakeNet) HostEndpoints(_ context.Context, eps []netsetup.HostEndpoint) error {
	f.hosteps = append(f.hosteps, eps)
	return nil
}
func (f *fakeNet) Up(_ context.Context, s netsetup.Session) error {
	if f.fail {
		return errors.New("nft failed")
	}
	f.uplinks = append(f.uplinks, s.Uplink)
	return nil
}

type fakeGW struct {
	running   map[string]int
	policies  map[string]gwpolicy.Policy
	files     map[string]map[string][]byte
	leaves    map[string]map[string][]byte
	versions  map[string]int
	renewErr  error
	renews    int
	reloadErr error
	reloads   int
	stopped   []string
	calls     *[]string
}

func (f *fakeGW) Renew(_ context.Context, id, dir string, slot, version int, leaves map[string][]byte) error {
	f.renews++
	if f.renewErr != nil {
		return f.renewErr
	}
	if f.running[id] == 0 || version != f.versions[id]+1 {
		return fmt.Errorf("renew %s to version %d", id, version)
	}
	f.versions[id] = version
	f.leaves[id] = maps.Clone(leaves)
	for k, v := range leaves {
		f.leaves[id][k] = slices.Clone(v)
	}
	return nil
}

func (f *fakeGW) Start(_ context.Context, id, ns, dir string, slot int, files, leaves map[string][]byte) (int, error) {
	if f.leaves == nil {
		f.leaves, f.versions = map[string]map[string][]byte{}, map[string]int{}
	}
	f.leaves[id] = map[string][]byte{}
	for k, v := range leaves {
		f.leaves[id][k] = slices.Clone(v)
	}
	f.versions[id] = 1
	p, err := gwpolicy.Decode(files["policy.json"])
	if err != nil {
		return 0, err
	}
	f.policies[id] = *p
	if f.files == nil {
		f.files = map[string]map[string][]byte{}
	}
	f.files[id] = files
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "policy.json"), files["policy.json"], 0o400)
	f.running[id] = 4000 + len(f.running)
	*f.calls = append(*f.calls, "gateway "+id)
	return f.running[id], nil
}

func (f *fakeGW) Reload(_ context.Context, id, dir string, slot, generation int, policy []byte) error {
	if f.running[id] == 0 {
		return errors.New("no gateway")
	}
	if f.reloadErr != nil {
		return f.reloadErr
	}
	p, err := gwpolicy.Decode(policy)
	if err != nil {
		return err
	}
	if p.Generation != generation {
		return fmt.Errorf("generation %d in a policy of %d", generation, p.Generation)
	}
	f.policies[id] = *p
	f.reloads++
	*f.calls = append(*f.calls, "reload gateway "+id)
	os.Remove(filepath.Join(dir, "policy.json")) // as the real one, by replacing the file
	return os.WriteFile(filepath.Join(dir, "policy.json"), policy, 0o400)
}

func (f *fakeGW) User(slot int) int { return 70000 + slot }

func (f *fakeGW) Stop(_ context.Context, id string, pid int) error {
	if f.running[id] != pid {
		return errors.New("wrong pid")
	}
	delete(f.running, id)
	f.stopped = append(f.stopped, id)
	*f.calls = append(*f.calls, "stop gateway "+id)
	return nil
}

type rig struct {
	net *fakeNet
	gw  *fakeGW
	d   *Daemon
	rt  *fakeRuntime
	ns  *fakeNS
	now *time.Time
}

func newRig(t *testing.T) *rig {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	r := &rig{rt: &fakeRuntime{vms: map[string]runtime.MicroVM{}, started: map[string]bool{}}, ns: &fakeNS{names: map[string]bool{}}, now: &now, net: &fakeNet{}}
	r.gw = &fakeGW{running: map[string]int{}, policies: map[string]gwpolicy.Policy{}, calls: &r.rt.calls}
	r.d = &Daemon{
		Journal: &journal.Store{Dir: filepath.Join(dir, "journal")}, Runtime: r.rt, NetNS: r.ns, Network: r.net, Gateways: r.gw,
		Resolvers: []netip.Addr{netip.MustParseAddr("192.168.127.1")},
		NetNSPath: func(n string) string { return "/var/run/netns/" + n },
		Budget:    limits.Budget{VMMemoryMiB: 16384}, SessionRoot: filepath.Join(dir, "sessions"), AuditRoot: filepath.Join(dir, "logs"),
		Now: func() time.Time { return *r.now },
	}
	if err := r.d.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	return r
}

const ws = sessionspec.WorkspaceStore + "/0123456789abcdef"

func spec(id string, mem int, deps ...string) []byte {
	s := &sessionspec.Spec{Version: 1, ID: id, Name: id, Agent: "claude", Tier: 2,
		Image: "ghcr.io/x/agent@sha256:" + strings.Repeat("a", 64), Command: []string{"claude"},
		Resources: sessionspec.Resources{CPUs: 2, MemoryMiB: mem},
		Mounts: []sessionspec.Mount{
			{Kind: sessionspec.MaskFile, Target: "/home/agent/workspace/.env"},
			{Kind: sessionspec.Workspace, Source: ws, Target: "/home/agent/workspace"},
			{Kind: sessionspec.MaskDir, Target: "/home/agent/workspace/secrets"},
		},
		Env:    []sessionspec.EnvVar{{Name: "TERM", Value: "xterm"}},
		Egress: sessionspec.Egress{Allow: []string{"api.anthropic.com"}}}
	for _, d := range deps {
		s.Dependencies = append(s.Dependencies, sessionspec.Dependency{Name: d, Image: "docker.io/library/postgres@sha256:" + strings.Repeat("b", 64),
			Port: 5432, RunAsUser: 999, Resources: sessionspec.Resources{CPUs: 1, MemoryMiB: 1024},
			Egress: sessionspec.Egress{Allow: []string{"pypi.org"}}})
	}
	b, _ := s.Encode()
	return b
}

func TestStartAndStop(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	id, err := r.d.Start(ctx, spec("s-one", 4096, "db"))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := r.d.Journal.Load(id)
	// masks, agent, gateway, and dependency netns, uplink, gateway, dependency and agent microVMs
	if s.State != journal.Running || len(s.Live()) != 8 {
		t.Fatalf("state %s, resources %+v", s.State, s.Resources)
	}
	p := r.gw.policies[id]
	if len(p.Links) != 2 || p.Links[0].Listen.String() != "10.200.0.1" || p.Links[0].Allow[0] != "api.anthropic.com" ||
		p.Links[1].Listen.String() != "10.200.1.1" || p.Links[1].Name != "db" || len(p.Links[1].Allow) != 1 || p.Links[1].Allow[0] != "pypi.org" ||
		len(p.Deps) != 1 || p.Deps[0].Addr.String() != "10.200.1.2" || p.Deps[0].Port != 5432 || p.Resolvers[0].String() != "192.168.127.1" {
		t.Errorf("gateway policy %+v", p)
	}
	if db := r.rt.vms["db.s-one"]; len(db.Mounts) != 1 || db.Mounts[0].Target != "/etc/resolv.conf" || db.NetNS != "/var/run/netns/sbx-s-one-d-db" {
		t.Errorf("dependency %+v", db)
	} else if b, _ := os.ReadFile(db.Mounts[0].Source); string(b) != "nameserver 10.200.1.1\n" {
		t.Errorf("dependency resolv.conf %q", b)
	}
	if len(r.net.uplinks) != 1 || r.net.uplinks[0] != 0 || r.net.root != 1 {
		t.Errorf("network: %+v", r.net)
	}
	agent := r.rt.vms["s-one"]
	if agent.UID != 1000 || agent.NetNS != "/var/run/netns/sbx-s-one-a" || !r.rt.started["s-one"] || !r.rt.started["db.s-one"] {
		t.Errorf("agent %+v started %v", agent, r.rt.started)
	}
	if r.rt.vms["db.s-one"].UID != 999 {
		t.Errorf("dependency %+v", r.rt.vms["db.s-one"])
	}
	if last := agent.Mounts[len(agent.Mounts)-1]; last.Target != "/etc/resolv.conf" || !last.ReadOnly {
		t.Errorf("resolv.conf mount %+v", last)
	} else if b, _ := os.ReadFile(last.Source); string(b) != "nameserver 10.200.0.1\n" {
		t.Errorf("resolv.conf %q", b)
	}
	// the workspace is mounted first, then the masks on top, read-only, from empty files
	if agent.Mounts[0].Target != "/home/agent/workspace" || !agent.Mounts[1].ReadOnly || !agent.Mounts[2].ReadOnly {
		t.Errorf("mounts %+v", agent.Mounts)
	}
	if st, err := os.Stat(agent.Mounts[1].Source); err != nil || st.Size() != 0 || !st.Mode().IsRegular() {
		t.Errorf("file mask %v %v", st, err)
	}
	if st, err := os.Stat(agent.Mounts[2].Source); err != nil || !st.IsDir() {
		t.Errorf("dir mask %v %v", st, err)
	}

	if err := r.d.Stop(ctx, id, "operator stop"); err != nil {
		t.Fatal(err)
	}
	s, _ = r.d.Journal.Load(id)
	if s.State != journal.Terminated || len(s.Live()) != 0 || s.EndReason != "operator stop" {
		t.Errorf("after stop: %+v", s)
	}
	if len(r.rt.vms) != 0 || len(r.ns.names) != 0 {
		t.Errorf("left behind: %v %v", r.rt.vms, r.ns.names)
	}
	// microVMs go first, then the gateway, then the namespaces
	last := strings.Join(r.rt.calls, ",")
	if !strings.HasSuffix(last, "destroy db.s-one,destroy s-one,stop gateway s-one") && !strings.HasSuffix(last, "destroy s-one,destroy db.s-one,stop gateway s-one") {
		t.Errorf("calls %s", last)
	}
	// the uplink is free again
	if _, err := r.d.Start(ctx, spec("s-two", 2048)); err != nil || r.net.uplinks[1] != 0 {
		t.Errorf("uplink reuse: %v %v", r.net.uplinks, err)
	}
	if _, err := os.Stat(r.d.maskDir(id)); !os.IsNotExist(err) {
		t.Error("mask directory left behind")
	}
}

func TestBudgetRefusal(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, err := r.d.Start(ctx, spec("s-big", 8192)); err != nil {
		t.Fatal(err)
	}
	_, err := r.d.Start(ctx, spec("s-two", 8192))
	if err == nil || !strings.Contains(err.Error(), "not enough memory") {
		t.Fatalf("over budget: %v", err)
	}
	s, _ := r.d.Journal.Load("s-two")
	if s.State != journal.Terminated || !strings.HasPrefix(s.EndReason, "not admitted") {
		t.Errorf("%+v", s)
	}
	if _, ok := r.rt.vms["s-two"]; ok {
		t.Error("an unadmitted session got a microVM")
	}
}

func TestFailedStartRollsBack(t *testing.T) {
	r := newRig(t)
	r.rt.failStart = "s-one"
	if _, err := r.d.Start(context.Background(), spec("s-one", 2048, "db")); err == nil {
		t.Fatal("started")
	}
	s, _ := r.d.Journal.Load("s-one")
	if s.State != journal.Terminated || s.EndReason != "start failed: container s-one: boot failed: the file sh was not found" || len(s.Live()) != 0 {
		t.Errorf("%+v", s)
	}
	if _, err := os.Stat(filepath.Join(r.d.SessionRoot, "s-one")); !os.IsNotExist(err) {
		t.Error("the empty session directory was left behind")
	}
	if len(r.rt.vms) != 0 || len(r.ns.names) != 0 {
		t.Errorf("left behind: %v %v", r.rt.vms, r.ns.names)
	}
}

func TestTeardownIncomplete(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.d.Start(ctx, spec("s-one", 2048))
	r.rt.failKill = "s-one"
	if err := r.d.Stop(ctx, "s-one", "operator stop"); err != nil {
		t.Fatal(err)
	}
	s, _ := r.d.Journal.Load("s-one")
	live := s.Live()
	if s.State != journal.Terminated || len(live) != 1 || live[0].State != journal.Incomplete || !strings.Contains(live[0].Note, "shim stuck") {
		t.Errorf("%+v", s)
	}
	// the namespace still went, after the microVM failed
	if len(r.ns.names) != 0 {
		t.Errorf("namespaces %v", r.ns.names)
	}
}

func TestReap(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.d.Start(ctx, spec("s-one", 2048))
	*r.now = r.now.Add(90 * time.Second)
	r.d.Heartbeat("s-one")
	*r.now = r.now.Add(100 * time.Second)
	r.d.Reap(ctx)
	if s, _ := r.d.Journal.Load("s-one"); s.State != journal.Running {
		t.Fatalf("reaped with a live lease: %s", s.State)
	}
	*r.now = r.now.Add(30 * time.Second)
	r.d.Reap(ctx)
	s, _ := r.d.Journal.Load("s-one")
	if s.State != journal.Terminated || !strings.Contains(s.EndReason, "attach lease expired") {
		t.Errorf("%+v", s)
	}
	if err := r.d.Heartbeat("s-one"); err == nil {
		t.Error("heartbeat for an ended session")
	}
}

func TestReconcile(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.d.Start(ctx, spec("s-one", 2048, "db"))
	// sandboxd dies; a stray microVM and namespace exist that no journal entry owns
	r.rt.vms["stray"] = runtime.MicroVM{ID: "stray"}
	r.ns.names["sbx-stray-a"] = true
	d2 := &Daemon{Journal: &journal.Store{Dir: r.d.Journal.Dir}, Runtime: r.rt, NetNS: r.ns, NetNSPath: r.d.NetNSPath,
		Network: r.net, Gateways: r.gw, Resolvers: r.d.Resolvers,
		Budget: r.d.Budget, SessionRoot: r.d.SessionRoot, Now: r.d.Now}
	if _, err := d2.Start(ctx, spec("s-two", 2048)); !errors.Is(err, ErrNotReady) {
		t.Errorf("accepted before reconciling: %v", err)
	}
	if err := d2.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	s, _ := d2.Journal.Load("s-one")
	if s.State != journal.Terminated || s.EndReason != "sandboxd restarted" {
		t.Errorf("%+v", s)
	}
	if len(r.rt.vms) != 0 || len(r.ns.names) != 0 {
		t.Errorf("left behind: %v %v", r.rt.vms, r.ns.names)
	}
	if _, err := d2.Start(ctx, spec("s-two", 2048)); err != nil {
		t.Errorf("after reconciling: %v", err)
	}
	l, _ := d2.List()
	if len(l) != 2 || l[1].State != journal.Running {
		t.Errorf("%+v", l)
	}
}

func TestRefusals(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, err := r.d.Start(ctx, []byte(`{"version":1,"privileged":true}`)); err == nil {
		t.Error("unknown field accepted")
	}
	b := strings.Replace(string(spec("s-read", 2048)), `"keep_alive":false`, `"keep_alive":false,"readable":[{"ref":"npm","env_var":"NPM_TOKEN"}]`, 1)
	if _, err := r.d.Start(ctx, []byte(b)); err == nil || !strings.Contains(err.Error(), "broker store or tmpfs") {
		t.Errorf("readable secret: %v", err)
	}
	if _, err := r.d.Start(ctx, spec("s-one", 2048)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.d.Start(ctx, spec("s-one", 2048)); !errors.Is(err, journal.ErrExists) {
		t.Errorf("duplicate id: %v", err)
	}
}

func TestServer(t *testing.T) {
	r := newRig(t)
	sock := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var denied atomic.Bool
	go r.d.Serve(ctx, ln, func(net.Conn) error {
		if denied.Load() {
			return errors.New("uid 1000 is not root or in group sandbox")
		}
		return nil
	})
	resp, err := Call(ctx, sock, Request{Op: "start", Spec: spec("s-one", 2048)})
	if err != nil || !resp.OK || resp.ID != "s-one" {
		t.Fatalf("start: %+v %v", resp, err)
	}
	if resp, _ := Call(ctx, sock, Request{Op: "heartbeat", ID: "s-one"}); !resp.OK {
		t.Errorf("heartbeat: %+v", resp)
	}
	if resp, _ := Call(ctx, sock, Request{Op: "list"}); !resp.OK || len(resp.Sessions) != 1 || resp.Sessions[0].State != journal.Running {
		t.Errorf("list: %+v", resp)
	}
	if resp, _ := Call(ctx, sock, Request{Op: "stop", ID: "s-one"}); !resp.OK {
		t.Errorf("stop: %+v", resp)
	}
	if resp, _ := Call(ctx, sock, Request{Op: "reboot"}); resp.OK || !strings.Contains(resp.Error, "unknown op") {
		t.Errorf("unknown op: %+v", resp)
	}
	c, _ := net.Dial("unix", sock)
	c.Write([]byte(`{"op":"list","extra":1}` + "\n"))
	var bad Response
	json.NewDecoder(c).Decode(&bad)
	c.Close()
	if bad.OK || !strings.Contains(bad.Error, "bad request") {
		t.Errorf("unknown field: %+v", bad)
	}
	denied.Store(true)
	if resp, _ := Call(ctx, sock, Request{Op: "list"}); resp.OK || !strings.Contains(resp.Error, "not allowed") {
		t.Errorf("unauthorized: %+v", resp)
	}
}

func TestUplinksDistinctAndNetworkFailure(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.d.Start(ctx, spec("s-a", 1024))
	r.d.Start(ctx, spec("s-b", 1024))
	if r.net.uplinks[0] == r.net.uplinks[1] {
		t.Errorf("two sessions share uplink %d", r.net.uplinks[0])
	}
	r.net.fail = true
	if _, err := r.d.Start(ctx, spec("s-c", 1024)); err == nil {
		t.Fatal("started without a network")
	}
	s, _ := r.d.Journal.Load("s-c")
	if s.State != journal.Terminated || len(s.Live()) != 0 {
		t.Errorf("%+v", s)
	}
	if _, ok := r.gw.running["s-c"]; ok {
		t.Error("a gateway was started for a session whose network failed")
	}
}

func auditTypes(t *testing.T, root, id, file string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, id, file))
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatal(err)
		}
		types = append(types, m["type"].(string))
	}
	return types
}

// fakeBroker records handovers.
type fakeBroker struct {
	key      []byte
	handed   map[string][][]Use
	sockets  []string
	failWith error
	// the uid the readable files were written for
	readableUID int
	// the uid the client certificates were written for
	certUID int
}

func (f *fakeBroker) SetKey(k []byte) error    { f.key = append([]byte(nil), k...); return nil }
func (f *fakeBroker) Put(string, []byte) error { return nil }
func (f *fakeBroker) Delete(string) error      { return nil }
func (f *fakeBroker) List() ([]string, error)  { return nil, nil }
func (f *fakeBroker) Refresh(_ context.Context, ref string, minValid time.Duration) (int64, error) {
	if ref != "agent.codex" {
		return 0, errors.New("no such login")
	}
	return int64(minValid / time.Second), nil
}
func (f *fakeBroker) Bindings() (map[string]brokerseal.Binding, error) {
	return map[string]brokerseal.Binding{"secret.X": {Readable: true}}, nil
}

// WriteReadable writes "value of <ref>\n" for each file, as the helper would write the value.
func (f *fakeBroker) WriteClientCerts(_ context.Context, dir string, uid int, certs map[string]ClientCert) error {
	if f.failWith != nil {
		return f.failWith
	}
	for name, c := range certs {
		os.WriteFile(filepath.Join(dir, name+".crt"), []byte("cert of "+c.Ref+" for "+c.Host+"\n"), 0o400)
		os.WriteFile(filepath.Join(dir, name+".key"), []byte("key of "+c.Ref+"\n"), 0o400)
	}
	f.certUID = uid
	return nil
}

func (f *fakeBroker) WriteReadable(_ context.Context, dir string, uid int, files map[string]string) error {
	if f.failWith != nil {
		return f.failWith
	}
	for name, ref := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("value of "+ref+"\n"), 0o400); err != nil {
			return err
		}
	}
	f.readableUID = uid
	return nil
}

func (f *fakeBroker) HandOver(_ context.Context, id, socket string, refs [][]Use) error {
	if f.failWith != nil {
		return f.failWith
	}
	if f.handed == nil {
		f.handed = map[string][][]Use{}
	}
	f.handed[id] = refs
	f.sockets = append(f.sockets, socket)
	return nil
}

func TestAudit(t *testing.T) {
	r := newRig(t)
	r.d.Broker = &fakeBroker{}
	ca, _, _ := pki.LoadOrCreate(t.TempDir(), *r.now)
	r.d.TLS = &TLS{CA: ca, Baseline: []l7.Rule{{Host: l7.AnyHost, Methods: []string{"TRACE"}, Action: l7.Deny}}}
	ctx := context.Background()
	b := strings.Replace(string(spec("s-aud", 2048, "db")), `"bindings":null`, `"bindings":[{"ref":"gh","hosts":["api.anthropic.com"],"inject":"bearer","placeholder":"sbxph_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]`, 1)
	if _, err := r.d.Start(ctx, []byte(b)); err != nil {
		t.Fatal(err)
	}
	// the gateway logs connections; sandboxd collects them
	gwLog := filepath.Join(r.d.SessionRoot, "s-aud", "gateway", "connections.log")
	os.MkdirAll(filepath.Dir(gwLog), 0o700)
	os.WriteFile(gwLog, []byte(`{"port":443,"refused":true,"sni":"evil.com","start":"T"}`+"\n"), 0o600)
	r.d.Collect()
	r.d.RecordDrop("s-aud", map[string]any{"rule": "forward", "dst": "1.1.1.1"})
	r.d.RecordDrop("s-unknown", map[string]any{"rule": "drop"})
	os.WriteFile(gwLog, []byte(`{"port":443,"refused":true,"sni":"evil.com","start":"T"}`+"\n"+`{"dependency":"db","port":5432,"sent":3,"start":"T"}`+"\n"), 0o600)
	r.d.Stop(ctx, "s-aud", "operator stop")
	ev := strings.Join(auditTypes(t, r.d.AuditRoot, "s-aud", "events.jsonl"), ",")
	if ev != "session_requested,dependency_up,session_running,link_drop,session_end" {
		t.Errorf("events %s", ev)
	}
	if fl := strings.Join(auditTypes(t, r.d.AuditRoot, "s-aud", "flows.jsonl"), ","); fl != "flow,flow" {
		t.Errorf("flows %s (the last line is collected at teardown)", fl)
	}
	raw, _ := os.ReadFile(filepath.Join(r.d.AuditRoot, "s-aud", "events.jsonl"))
	if strings.Contains(string(raw), "sbxph_") || !strings.Contains(string(raw), `"ref":"gh"`) {
		t.Errorf("a placeholder reached the audit log, or the binding is missing:\n%s", raw)
	}
	if _, err := os.Stat(filepath.Join(r.d.AuditRoot, "s-unknown")); err == nil {
		t.Error("a drop for an unknown session made a log")
	}
}

func TestInterception(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	mk := func(id string) []byte {
		sp, err := sessionspec.Decode(bytes.NewReader(spec(id, 2048, "db")))
		if err != nil {
			t.Fatal(err)
		}
		sp.Egress.L7 = []l7.Rule{{Host: "api.anthropic.com", Methods: []string{"POST"}, PathPatterns: []string{"/v1/**"}, Action: l7.Allow}}
		sp.Dependencies[0].Egress.L7 = []l7.Rule{{Host: "pypi.org", Methods: []string{"POST"}, Action: l7.Deny}}
		b, _ := sp.Encode()
		return b
	}
	// without a CA, a session that intercepts is refused before anything runs
	if _, err := r.d.Start(ctx, mk("s-noca")); err == nil || !strings.Contains(err.Error(), "no CA") {
		t.Fatalf("started without a CA: %v", err)
	}
	if len(r.rt.vms) != 0 {
		t.Fatalf("microVMs left: %v", r.rt.vms)
	}
	ca, _, err := pki.LoadOrCreate(t.TempDir(), *r.now)
	if err != nil {
		t.Fatal(err)
	}
	baseline := []l7.Rule{{Host: l7.AnyHost, Methods: []string{"TRACE"}, Action: l7.Deny}}
	r.d.TLS = &TLS{CA: ca, Baseline: baseline, SystemRoots: []byte("SYSTEM ROOTS\n")}
	id, err := r.d.Start(ctx, mk("s-tls"))
	if err != nil {
		t.Fatal(err)
	}
	p, files, leaves := r.gw.policies[id], r.gw.files[id], r.gw.leaves[id]
	dir := filepath.Join(r.d.SessionRoot, id, "gateway")
	if p.UpstreamCAs != filepath.Join(dir, "upstream-cas.pem") || string(files["upstream-cas.pem"]) != "SYSTEM ROOTS\n" {
		t.Errorf("upstream roots %q", p.UpstreamCAs)
	}
	for i, want := range []string{"api.anthropic.com", "pypi.org"} {
		l := p.Links[i]
		if len(l.Intercept) != 1 || l.Intercept[0].Name != want || len(l.L7) != 2 || l.L7[0].Methods[0] != "TRACE" {
			t.Fatalf("link %d: %+v", i, l)
		}
		ic := l.Intercept[0]
		if filepath.Dir(ic.CertChain) != filepath.Join(dir, "tls", "live") || filepath.Dir(ic.SDS) != filepath.Join(dir, "tls") {
			t.Errorf("link %d leaf paths %+v", i, ic)
		}
		base := filepath.Base(ic.CertChain)
		if _, err := tls.X509KeyPair(leaves[base], leaves[strings.TrimSuffix(base, ".crt")+".key"]); err != nil {
			t.Errorf("link %d leaf: %v", i, err)
		}
	}
	agent := r.rt.vms[id]
	if !slices.Contains(agent.Env, "SSL_CERT_FILE="+GuestBundle) || !slices.Contains(r.rt.vms["db."+id].Env, "NODE_EXTRA_CA_CERTS="+GuestGatewayCA) {
		t.Errorf("trust environment %v", agent.Env)
	}
	var bundle string
	for _, m := range agent.Mounts {
		if m.Target == GuestBundle && m.ReadOnly {
			bundle = m.Source
		}
	}
	if b, _ := os.ReadFile(bundle); !strings.Contains(string(b), strings.TrimSpace(string(ca.CertPEM))) || strings.Contains(string(b), "PRIVATE") {
		t.Errorf("guest bundle %q", b)
	}
}

func TestBrokerHandover(t *testing.T) {
	r := newRig(t)
	ca, _, _ := pki.LoadOrCreate(t.TempDir(), *r.now)
	r.d.TLS = &TLS{CA: ca, Baseline: []l7.Rule{{Host: l7.AnyHost, Methods: []string{"TRACE"}, Action: l7.Deny}}}
	ctx := context.Background()
	mk := func(id string) []byte {
		sp, _ := sessionspec.Decode(bytes.NewReader(spec(id, 2048, "db")))
		sp.Bindings = []sessionspec.Binding{{Ref: "anthropic", Hosts: []string{"api.anthropic.com"}, Inject: "header:x-api-key",
			Placeholder: "sbxph_" + strings.Repeat("A", 43), RatePerMinute: 30, Burst: 4, Quota: 500}}
		sp.Dependencies[0].Bindings = []sessionspec.Binding{{Ref: "pypi", Hosts: []string{"pypi.org"}, Inject: "bearer",
			Placeholder: "sbxph_" + strings.Repeat("B", 43)}}
		b, _ := sp.Encode()
		return b
	}
	// no broker store: refused, and nothing is left running
	if _, err := r.d.Start(ctx, mk("s-nob")); err == nil {
		t.Fatal("started without a broker store")
	}
	if len(r.rt.vms) != 0 || len(r.gw.running) != 0 {
		t.Fatalf("left running: %v %v", r.rt.vms, r.gw.running)
	}
	fb := &fakeBroker{}
	r.d.Broker = fb
	id, err := r.d.Start(ctx, mk("s-bro"))
	if err != nil {
		t.Fatal(err)
	}
	if refs := fb.handed[id]; len(refs) != 2 || len(refs[0]) != 1 || len(refs[1]) != 1 ||
		fmt.Sprint(refs[0][0]) != "{anthropic [api.anthropic.com] header:x-api-key}" || fmt.Sprint(refs[1][0]) != "{pypi [pypi.org] bearer}" {
		t.Errorf("handed %v", refs)
	}
	if !strings.HasSuffix(fb.sockets[0], "/gateway/handover.sock") {
		t.Errorf("socket %v", fb.sockets)
	}
	p := r.gw.policies[id]
	if b := p.Links[0].Bindings; len(b) != 1 || b[0].RatePerMinute != 30 || b[0].Burst != 4 || b[0].Quota != 500 {
		t.Errorf("the limits did not reach the gateway: %+v", b)
	}
	if len(p.Links[0].Bindings) != 1 || p.Links[0].Bindings[0].Inject != "header:x-api-key" || len(p.Links[1].Bindings) != 1 ||
		len(p.Links[0].Intercept) != 1 || p.Links[0].Intercept[0].Name != "api.anthropic.com" {
		t.Errorf("policy %+v", p.Links)
	}
	if strings.Contains(string(r.gw.files[id]["policy.json"]), "value") {
		t.Error("a value field in the gateway policy")
	}
	// a failed handover stops the start and tears the session down
	fb.failWith = errors.New("no key")
	if _, err := r.d.Start(ctx, mk("s-fail")); err == nil || !strings.Contains(err.Error(), "handover") {
		t.Fatalf("%v", err)
	}
	if _, ok := r.gw.running["s-fail"]; ok {
		t.Error("the gateway of a failed start still runs")
	}
}

// TestLeafRenewal: an attached session outlives its leaves (only keep-alive sessions have a
// lifetime); before they expire, sandboxd issues new ones for the same names and the gateway
// swaps them in.
func TestLeafRenewal(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	ca, _, err := pki.LoadOrCreate(t.TempDir(), *r.now)
	if err != nil {
		t.Fatal(err)
	}
	r.d.TLS = &TLS{CA: ca, Baseline: []l7.Rule{{Host: l7.AnyHost, Methods: []string{"TRACE"}, Action: l7.Deny}}, SystemRoots: []byte("R\n")}
	sp, _ := sessionspec.Decode(bytes.NewReader(spec("s-ren", 2048)))
	sp.Egress.L7 = []l7.Rule{{Host: "api.anthropic.com", Methods: []string{"POST"}, Action: l7.Deny}}
	b, _ := sp.Encode()
	id, err := r.d.Start(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	first := slices.Clone(r.gw.leaves[id]["0.crt"])
	notAfter := func() time.Time {
		blk, _ := pem.Decode(r.gw.leaves[id]["0.crt"])
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if len(c.DNSNames) != 1 || c.DNSNames[0] != "api.anthropic.com" {
			t.Errorf("names %v", c.DNSNames)
		}
		return c.NotAfter
	}
	end := notAfter()
	tick := func(d time.Duration) {
		*r.now = r.now.Add(d)
		r.d.Heartbeat(id)
		r.d.Reap(ctx)
	}
	tick(end.Sub(*r.now) - 49*time.Hour)
	if r.gw.versions[id] != 1 {
		t.Fatalf("renewed %v early", end.Sub(*r.now))
	}
	tick(2 * time.Hour)
	if r.gw.versions[id] != 2 || bytes.Equal(first, r.gw.leaves[id]["0.crt"]) || !notAfter().After(end) {
		t.Fatalf("not renewed 47 h before expiry: version %d", r.gw.versions[id])
	}
	if _, err := tls.X509KeyPair(r.gw.leaves[id]["0.crt"], r.gw.leaves[id]["0.key"]); err != nil {
		t.Error(err)
	}
	tick(time.Minute)
	if r.gw.versions[id] != 2 {
		t.Error("renewed again at once")
	}
	if ev := strings.Join(auditTypes(t, r.d.AuditRoot, id, "events.jsonl"), ","); !strings.Contains(ev, "tls_leaves_renewed") {
		t.Errorf("events %s", ev)
	}
	// a failed renewal leaves the session running and is retried
	end = notAfter()
	r.gw.renewErr = errors.New("disk full")
	tick(end.Sub(*r.now) - time.Hour)
	if r.gw.versions[id] != 2 || r.d.live[id] == nil {
		t.Fatalf("after a failed renewal: version %d", r.gw.versions[id])
	}
	r.gw.renewErr = nil
	tick(time.Minute)
	if r.gw.versions[id] != 3 {
		t.Error("not retried")
	}
	// an ended session is not renewed
	r.d.Stop(ctx, id, "done")
	n := r.gw.renews
	tick(30 * 24 * time.Hour)
	if r.gw.renews != n {
		t.Error("an ended session's leaves were renewed")
	}
}

// TestRenewBefore: two days ahead, or half the leaves' life when that is shorter.
func TestRenewBefore(t *testing.T) {
	d := &Daemon{}
	if d.renewBefore() != 48*time.Hour {
		t.Errorf("default %v", d.renewBefore())
	}
	d.Expiry.KeepAliveMax = time.Hour
	if d.renewBefore() != 25*time.Hour/2 {
		t.Errorf("short leaves %v", d.renewBefore())
	}
}

// TestBrokerList: broker-list answers the store's references and the bindings their entries carry.
func TestBrokerList(t *testing.T) {
	r := newRig(t)
	if resp := r.d.call(context.Background(), Request{Op: "broker-list"}); resp.OK {
		t.Error("answered with no broker store")
	}
	r.d.Broker = &fakeBroker{}
	resp := r.d.call(context.Background(), Request{Op: "broker-list"})
	if !resp.OK || len(resp.Bindings) != 1 || !resp.Bindings["secret.X"].Readable {
		t.Errorf("%+v", resp)
	}
}

// TestDependencyArgs: a dependency's args follow its image's entrypoint (Kubernetes' args); with a
// command, the command and then the args are the whole process.
func TestDependencyArgs(t *testing.T) {
	r := newRig(t)
	s, err := sessionspec.Decode(bytes.NewReader(spec("s-args", 4096, "a", "b")))
	if err != nil {
		t.Fatal(err)
	}
	s.Dependencies[0].Args = []string{"node", "dist/sse.js"}
	s.Dependencies[1].Command, s.Dependencies[1].Args, s.Dependencies[1].Port = []string{"/bin/srv"}, []string{"--port", "1"}, 5433
	b, _ := s.Encode()
	if _, err := r.d.Start(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, m := range r.rt.vms {
		if strings.HasPrefix(m.Image, "docker.io/library/postgres") {
			got = append(got, strings.Join(m.Args, " ")+"|"+strings.Join(m.ImageArgs, " "))
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != "/bin/srv --port 1|,|node dist/sse.js" {
		t.Errorf("%q", got)
	}
}

// TestRuntimeOfSession: the agent and each dependency run under the session's runtime, and the
// audit trail records it (Kata when the spec names none).
func TestRuntimeOfSession(t *testing.T) {
	for _, rt := range []string{"", sessionspec.RuntimeGVisor} {
		r := newRig(t)
		s, err := sessionspec.Decode(bytes.NewReader(spec("s-rt", 4096, "a")))
		if err != nil {
			t.Fatal(err)
		}
		s.Runtime = rt
		b, _ := s.Encode()
		if _, err := r.d.Start(context.Background(), b); err != nil {
			t.Fatal(err)
		}
		if len(r.rt.vms) != 2 {
			t.Fatalf("%d microVMs", len(r.rt.vms))
		}
		for id, m := range r.rt.vms {
			for other := range r.rt.vms {
				if other != id && strings.HasPrefix(other, id) {
					t.Errorf("container id %s is a prefix of %s (runsc would refuse it as ambiguous)", id, other)
				}
			}
			if m.Runtime != rt {
				t.Errorf("%q: %s ran under %q", rt, id, m.Runtime)
			}
		}
		want := rt
		if want == "" {
			want = sessionspec.RuntimeKata
		}
		if got := specSummary(s)["runtime"]; got != want {
			t.Errorf("%q: audit records %v", rt, got)
		}
	}
}

// TestSessionFilesRemoved: the agent configuration copy, the MCP configuration, and tier 1 history
// in a session's directory go with the session.
func TestSessionFilesRemoved(t *testing.T) {
	r := newRig(t)
	id, err := r.d.Start(context.Background(), spec("s-files", 4096))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{AgentConfigDir, SessionHistoryDir, MCPDir} {
		os.MkdirAll(filepath.Join(r.d.SessionRoot, id, d), 0o700)
		os.WriteFile(filepath.Join(r.d.SessionRoot, id, d, "f"), []byte("x"), 0o600)
	}
	if err := r.d.Stop(context.Background(), id, "test"); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{AgentConfigDir, SessionHistoryDir, MCPDir} {
		if _, err := os.Stat(filepath.Join(r.d.SessionRoot, id, d)); err == nil {
			t.Errorf("%s left", d)
		}
	}
}

// TestBrokerRefresh: the login must stay valid for longer than a keep-alive session lives.
func TestBrokerRefresh(t *testing.T) {
	r := newRig(t)
	r.d.Broker = &fakeBroker{}
	resp := r.d.call(context.Background(), Request{Op: "broker-refresh", ID: "agent.codex"})
	if !resp.OK || resp.Exp != int64((limits.DefaultKeepAliveMax+time.Hour)/time.Second) {
		t.Errorf("%+v", resp)
	}
	if resp := r.d.call(context.Background(), Request{Op: "broker-refresh", ID: "agent.x"}); resp.OK {
		t.Error("refreshed an unknown login")
	}
}

// TestReconcileStuckOrphan: a microVM that cannot be removed is logged and left, and sandboxd still
// starts serving.
func TestReconcileStuckOrphan(t *testing.T) {
	r := newRig(t)
	r.rt.vms["ses-stuck"] = runtime.MicroVM{ID: "ses-stuck"}
	r.rt.failKill = "ses-stuck"
	if err := r.d.Reconcile(context.Background()); err != nil {
		t.Fatalf("a stuck orphan stopped sandboxd: %v", err)
	}
	if !r.d.ready {
		t.Error("not ready")
	}
}

// TestExtraCAs: the operator's corporate CAs are read again at every session start (a CA added
// later applies to the next session); a file that is not a certificate, or another name, is
// skipped.
func TestExtraCAs(t *testing.T) {
	ca1, _, _ := pki.LoadOrCreate(t.TempDir(), time.Now())
	ca2, _, _ := pki.LoadOrCreate(t.TempDir(), time.Now())
	dir := t.TempDir()
	tl := &TLS{SystemRoots: []byte("SYSTEM\n"), ExtraCADirs: []string{dir, filepath.Join(dir, "missing")}}
	if got := string(tl.roots()); got != "SYSTEM\n" {
		t.Errorf("none: %q", got)
	}
	os.WriteFile(filepath.Join(dir, "proxy.crt"), ca1.CertPEM, 0o644)
	os.WriteFile(filepath.Join(dir, "junk.pem"), []byte("-----BEGIN CERTIFICATE-----\nnotbase64\n-----END CERTIFICATE-----\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "notes.txt"), ca2.CertPEM, 0o644)
	blk, _ := pem.Decode(ca2.CertPEM)
	os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: blk.Bytes}), 0o644)
	got := string(tl.roots())
	if !strings.HasPrefix(got, "SYSTEM\n") || !strings.Contains(got, string(ca1.CertPEM)) || strings.Contains(got, string(ca2.CertPEM)) ||
		strings.Contains(got, "PRIVATE") || strings.Contains(got, "notbase64") {
		t.Errorf("%q", got)
	}
	// added after start: the next session has it
	os.WriteFile(filepath.Join(dir, "second.pem"), ca2.CertPEM, 0o644)
	if !strings.Contains(string(tl.roots()), string(ca2.CertPEM)) {
		t.Error("a CA added later was not read")
	}
}

// TestHostEndpointScoping (design 5.2.6): a session with declared host endpoints has the root
// namespace let them through from its uplink only, a session without any changes nothing, and the
// endpoints are withdrawn when the session ends.
func TestHostEndpointScoping(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, err := r.d.Start(ctx, spec("s-plain", 1024)); err != nil {
		t.Fatal(err)
	}
	if len(r.net.hosteps) != 0 {
		t.Errorf("a session without host endpoints changed them: %v", r.net.hosteps)
	}
	sp, _ := sessionspec.Decode(bytes.NewReader(spec("s-k3d", 1024)))
	sp.Tier = 3
	sp.Egress.HostEndpoints = []sessionspec.HostEndpoint{{Address: "192.168.1.178", Port: 6443}}
	b, _ := sp.Encode()
	id, err := r.d.Start(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(r.net.hosteps); n != 1 || len(r.net.hosteps[0]) != 1 || r.net.hosteps[0][0] != (netsetup.HostEndpoint{Uplink: 1, Addr: netip.MustParseAddr("192.168.1.178"), Port: 6443}) {
		t.Errorf("declared: %v", r.net.hosteps)
	}
	if err := r.d.Stop(ctx, id, "operator stop"); err != nil {
		t.Fatal(err)
	}
	if n := len(r.net.hosteps); n != 2 || len(r.net.hosteps[1]) != 0 {
		t.Errorf("withdrawn: %v", r.net.hosteps)
	}
}

// TestRebind (the exec-plugin token pump, design 5.9.5): a running session's gateway is handed its
// policy's credentials again, as at the start; a session that is not running, or binds nothing, is
// refused.
func TestRebind(t *testing.T) {
	r := newRig(t)
	ca, _, _ := pki.LoadOrCreate(t.TempDir(), *r.now)
	r.d.TLS = &TLS{CA: ca, Baseline: []l7.Rule{{Host: l7.AnyHost, Methods: []string{"TRACE"}, Action: l7.Deny}}}
	fb := &fakeBroker{}
	r.d.Broker = fb
	ctx := context.Background()
	sp, _ := sessionspec.Decode(bytes.NewReader(spec("s-reb", 2048)))
	sp.Bindings = []sessionspec.Binding{{Ref: "infra.kube.0", Hosts: []string{"api.anthropic.com"}, Inject: "bearer", Placeholder: "sbxph_" + strings.Repeat("Q", 43)}}
	b, _ := sp.Encode()
	id, err := r.d.Start(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	fb.handed = nil
	if resp := r.d.call(ctx, Request{Op: "rebind", ID: id}); !resp.OK {
		t.Fatalf("rebind: %s", resp.Error)
	}
	if refs := fb.handed[id]; len(refs) != 1 || fmt.Sprint(refs[0]) != "[{infra.kube.0 [api.anthropic.com] bearer}]" || len(fb.sockets) != 2 {
		t.Errorf("handed %v %v", refs, fb.sockets)
	}
	plain, _ := r.d.Start(ctx, spec("s-none", 1024))
	if err := r.d.Rebind(ctx, plain); err == nil || !strings.Contains(err.Error(), "binds no credentials") {
		t.Errorf("no bindings: %v", err)
	}
	r.d.Stop(ctx, id, "operator stop")
	if err := r.d.Rebind(ctx, id); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Errorf("stopped: %v", err)
	}
}
