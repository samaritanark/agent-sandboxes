package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/journal"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/limits"
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

type rig struct {
	d   *Daemon
	rt  *fakeRuntime
	ns  *fakeNS
	now *time.Time
}

func newRig(t *testing.T) *rig {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	r := &rig{rt: &fakeRuntime{vms: map[string]runtime.MicroVM{}, started: map[string]bool{}}, ns: &fakeNS{names: map[string]bool{}}, now: &now}
	r.d = &Daemon{
		Journal: &journal.Store{Dir: filepath.Join(dir, "journal")}, Runtime: r.rt, NetNS: r.ns,
		NetNSPath: func(n string) string { return "/var/run/netns/" + n },
		Budget:    limits.Budget{VMMemoryMiB: 16384}, SessionRoot: filepath.Join(dir, "sessions"),
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
			Port: 5432, RunAsUser: 999, Resources: sessionspec.Resources{CPUs: 1, MemoryMiB: 1024}})
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
	if s.State != journal.Running || len(s.Live()) != 5 {
		t.Fatalf("state %s, resources %+v", s.State, s.Resources)
	}
	agent := r.rt.vms["s-one"]
	if agent.UID != 1000 || agent.NetNS != "/var/run/netns/sbx-s-one-a" || !r.rt.started["s-one"] || !r.rt.started["s-one--db"] {
		t.Errorf("agent %+v started %v", agent, r.rt.started)
	}
	if r.rt.vms["s-one--db"].UID != 999 || len(r.rt.vms["s-one--db"].Mounts) != 0 {
		t.Errorf("dependency %+v", r.rt.vms["s-one--db"])
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
	// microVMs go before their namespaces
	last := strings.Join(r.rt.calls, ",")
	if !strings.HasSuffix(last, "destroy s-one--db,destroy s-one") && !strings.HasSuffix(last, "destroy s-one,destroy s-one--db") {
		t.Errorf("calls %s", last)
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
	b := strings.Replace(string(spec("s-one", 2048)), `"keep_alive":false`, `"keep_alive":false,"readable":[{"ref":"npm","env_var":"NPM_TOKEN"}]`, 1)
	if _, err := r.d.Start(ctx, []byte(b)); err == nil || !strings.Contains(err.Error(), "broker") {
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
