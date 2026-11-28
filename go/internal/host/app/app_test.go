package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/auditpull"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncgate"
)

type fakeTransport struct {
	release string
	relErr  error
	rc      int
	runs    [][]string
	pushes  [][]byte
	reach   string
	ttys    []bool
	// the audit pull
	pulls         int
	auditSessions string
	auditRecords  map[string]string
	// sandboxd ctl calls and what each got on stdin
	ctl   [][]string
	ctlIn [][]byte
	ctlRC int
	// the first ctlFailFirst sandboxd calls fail (a transient failure)
	ctlFailFirst int
	// the run pre-pass: its output, or an error
	bindings    string
	bindingsErr error
	bindingArgs [][]string
	bindingArgv [][]string
	pushArgs    [][]string
	epoch       string
	mirrors     [][]string
	// the doctor's canary: runtime -> its error ("" passes)
	canaryFail map[string]string
	// sandboxd ctl list's output
	sessions string
	lists    int
}

func (f *fakeTransport) Run(_ context.Context, _ driver.SSHEndpoint, argv []string, stdin io.Reader, stdout, _ io.Writer, tty bool) (int, error) {
	if len(argv) >= 2 && argv[1] == ReceiveOperatorState {
		b, _ := io.ReadAll(stdin)
		f.pushes = append(f.pushes, b)
		f.pushArgs = append(f.pushArgs, argv[2:])
		return 0, nil
	}
	if len(argv) >= 2 && argv[1] == MirrorPath {
		f.mirrors = append(f.mirrors, argv[2:])
		return 0, nil
	}
	if len(argv) > 1 && argv[0] == SandboxdCommand {
		b, _ := io.ReadAll(stdin)
		f.ctl = append(f.ctl, argv[1:])
		f.ctlIn = append(f.ctlIn, b)
		if f.ctlFailFirst > 0 {
			f.ctlFailFirst--
			return 0, errors.New("ssh connection failed")
		}
		return f.ctlRC, nil
	}
	f.runs = append(f.runs, argv)
	f.ttys = append(f.ttys, tty)
	io.WriteString(stdout, "ran\n")
	return f.rc, nil
}

func (f *fakeTransport) Output(_ context.Context, _ driver.SSHEndpoint, argv []string, max int) ([]byte, error) {
	if len(argv) > 1 && argv[1] == auditpull.VMSessions {
		f.pulls++
		return []byte(f.auditSessions), nil
	}
	if i := indexOf(argv, RunBindings); i > 0 {
		f.bindingArgs = append(f.bindingArgs, argv[i+1:])
		f.bindingArgv = append(f.bindingArgv, argv)
		if f.bindings == "" && f.bindingsErr == nil {
			return []byte(`{"secrets":[],"repos":[]}`), nil
		}
		return []byte(f.bindings), f.bindingsErr
	}
	if len(argv) > 1 && argv[1] == auditpull.VMRead {
		return []byte(f.auditRecords[argv[2]+"/"+argv[3]]), nil
	}
	if len(argv) == 3 && argv[0] == "/usr/bin/sandbox" && argv[1] == "__canary" {
		if e := f.canaryFail[argv[2]]; e != "" {
			return []byte(e + "\n"), errors.New("exit status 1")
		}
		return []byte("kernel 6.12.0-kata, probe read, 1.2 s\n"), nil
	}
	if strings.Join(argv, " ") == SandboxdCommand+" ctl list" {
		f.lists++
		return []byte(f.sessions), nil
	}
	switch argv[0] {
	case "sh":
		if len(argv) > 2 && strings.Contains(argv[2], ".epoch") {
			return []byte(f.epoch), nil
		}
		return []byte("present\n"), nil
	case "timeout":
		return []byte(f.reach + "\n"), nil
	}
	if !reflect.DeepEqual(argv, []string{"cat", ReleasePath}) {
		return nil, errors.New("unexpected Output")
	}
	return []byte(f.release), f.relErr
}

func indexOf(xs []string, x string) int {
	for i, v := range xs {
		if v == x {
			return i
		}
	}
	return -1
}

type res struct {
	rc       int
	out, err string
}

func run(t *testing.T, d driver.Driver, tr *fakeTransport, state string, args ...string) res {
	t.Helper()
	var out, errb bytes.Buffer
	rc := Run(context.Background(), args, Env{Driver: d, Transport: tr, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb,
		StdinTTY: true, StateDir: state, User: "op", Now: func() time.Time { return time.Unix(1800000000, 0) }})
	return res{rc, out.String(), errb.String()}
}

const goodRelease = "IMAGE_VERSION=3.0.0\nCONTROL_API=1\n"

func TestProxy(t *testing.T) {
	d := &driver.Mock{State: driver.Running}
	tr := &fakeTransport{release: goodRelease, rc: 3}
	r := run(t, d, tr, t.TempDir(), "run", "--repo", "a b", "--name", "it's")
	if r.rc != 3 || r.out != "ran\n" || r.err != "" {
		t.Fatalf("proxy: %+v", r)
	}
	wd, _ := os.Getwd()
	if want := []string{"sandbox", "run", "--repo", filepath.Join(wd, "a b"), "--name", "it's"}; !reflect.DeepEqual(tr.runs[0], want) || !tr.ttys[0] {
		t.Fatalf("proxied %q tty=%v", tr.runs[0], tr.ttys[0])
	}
	if len(tr.pushes) != 1 {
		t.Fatalf("%d operator-state pushes before one command", len(tr.pushes))
	}
	// unknown commands and no arguments are the in-VM CLI's to answer
	run(t, d, tr, "", "bogus")
	run(t, d, tr, "")
	if len(tr.runs) != 3 || !reflect.DeepEqual(tr.runs[2], []string{"sandbox"}) {
		t.Fatalf("runs %q", tr.runs)
	}
}

func TestProxyRefusals(t *testing.T) {
	for _, c := range []struct {
		state   driver.State
		release string
		want    string
	}{
		{driver.NotCreated, goodRelease, "Run: sandbox install"},
		{driver.Stopped, goodRelease, "sandbox vm start"},
		{driver.Broken, goodRelease, "broken"},
		{driver.Running, "IMAGE_VERSION=3.0.0\nCONTROL_API=2\n", "Use a newer sandbox binary"},
		{driver.Running, "IMAGE_VERSION=3.0.0\n", "invalid"},
	} {
		tr := &fakeTransport{release: c.release}
		r := run(t, &driver.Mock{State: c.state}, tr, "", "list")
		if r.rc != 1 || !strings.Contains(r.err, c.want) || len(tr.runs) != 0 {
			t.Errorf("state %v release %q: %+v runs %q", c.state, c.release, r, tr.runs)
		}
	}
}

func TestRemovedAndNotYet(t *testing.T) {
	d := &driver.Mock{State: driver.Running}
	tr := &fakeTransport{release: goodRelease}
	if r := run(t, d, tr, "", "configure-network"); r.rc != 1 || !strings.Contains(r.err, "removed in v3: the VM follows host networking") {
		t.Errorf("configure-network: %+v", r)
	}
	if r := run(t, d, tr, "", "upgrade"); r.rc != 1 || !strings.Contains(r.err, "not available") {
		t.Errorf("upgrade: %+v", r)
	}
	var got []string
	var out, errb bytes.Buffer
	rc := Run(context.Background(), []string{"setup-proxy-cert", "--list"}, Env{Driver: d, Transport: tr, Stdout: &out, Stderr: &errb,
		HostCommands: map[string]func(context.Context, []string) int{"setup-proxy-cert": func(_ context.Context, a []string) int { got = a; return 4 }}})
	if rc != 4 || !reflect.DeepEqual(got, []string{"--list"}) {
		t.Errorf("host command: rc=%d args=%q", rc, got)
	}
	if len(tr.runs) != 0 || len(d.Calls) != 0 {
		t.Errorf("host-only commands touched the VM: %q %q", tr.runs, d.Calls)
	}
}

func TestVMLifecycle(t *testing.T) {
	d := &driver.Mock{State: driver.Stopped, Reach: driver.HostReachControl{Mechanism: "test"}}
	tr := &fakeTransport{release: goodRelease}
	if r := run(t, d, tr, "", "vm", "status"); r.rc != 0 || r.out != "VM:     stopped (driver mock)\nHost reach control: test\n" {
		t.Fatalf("status stopped: %+v", r)
	}
	if r := run(t, d, tr, "", "vm", "start"); r.rc != 0 || d.State != driver.Running || !strings.Contains(r.out, "is running") {
		t.Fatalf("start: %+v", r)
	}
	if r := run(t, d, tr, "", "vm", "start"); r.rc != 0 || r.out != "The sandbox VM is already running.\n" {
		t.Fatalf("start again: %+v", r)
	}
	if r := run(t, d, tr, "", "vm", "status"); !strings.Contains(r.out, "Image:  3.0.0 (control API 1)") {
		t.Fatalf("status running: %+v", r)
	}
	if r := run(t, d, tr, "", "vm", "stop"); r.rc != 0 || d.State != driver.Stopped {
		t.Fatalf("stop: %+v", r)
	}
	if r := run(t, d, tr, "", "vm"); r.rc != 1 || !strings.HasPrefix(r.err, "Usage: sandbox vm") {
		t.Fatalf("usage: %+v", r)
	}
	if r := run(t, d, tr, "", "vm", "bogus"); r.rc != 1 {
		t.Fatalf("bogus: %+v", r)
	}
	d.Fail = map[string]error{"Start": errors.New("boom")}
	if r := run(t, d, tr, "", "vm", "start"); r.rc != 1 || !strings.Contains(r.err, "boom") {
		t.Fatalf("start failure: %+v", r)
	}
	if r := run(t, &driver.Mock{}, tr, "", "vm", "start"); r.rc != 1 || !strings.Contains(r.err, "sandbox install") {
		t.Fatalf("start uncreated: %+v", r)
	}
}

func TestVMShellRecorded(t *testing.T) {
	state := t.TempDir()
	d := &driver.Mock{State: driver.Running}
	tr := &fakeTransport{release: goodRelease, rc: 7}
	if r := run(t, d, tr, state, "vm", "shell"); r.rc != 7 || len(tr.runs) != 1 || tr.runs[0] != nil || !tr.ttys[0] {
		t.Fatalf("shell: %+v %q", r, tr.runs)
	}
	run(t, d, tr, state, "vm", "shell")
	b, _ := os.ReadFile(filepath.Join(state, "logs", "vm-shell.log"))
	want := "2027-01-15T08:00:00Z start user=\"op\"\n2027-01-15T08:00:00Z end rc=7\n"
	if string(b) != want+want {
		t.Fatalf("log %q", b)
	}
	if st, _ := os.Stat(filepath.Join(state, "logs", "vm-shell.log")); st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("log mode %v", st.Mode())
	}
	// no log, no shell
	bad := filepath.Join(t.TempDir(), "file")
	os.WriteFile(bad, nil, 0o600)
	tr.runs = nil
	if r := run(t, d, tr, bad, "vm", "shell"); r.rc != 1 || len(tr.runs) != 0 || !strings.Contains(r.err, "unrecorded") {
		t.Fatalf("unrecordable shell: %+v %q", r, tr.runs)
	}
}

func TestSyncReview(t *testing.T) {
	state, repo := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(repo, "notes.txt"), []byte("one\n"), 0o644)
	store := &syncgate.Store{Dir: filepath.Join(state, "quarantine")}
	fileID, _ := store.Put(repo, syncgate.Change{Path: ".vscode/tasks.json", Data: []byte("{\"x\":1}\n")}, "protected path (quarantine)")
	conflictID, _ := store.Put(repo, syncgate.Change{Path: "notes.txt", Data: []byte("one\ntwo\n"), Base: "file:x"}, "changed on the host since the last sync (conflict)")
	refID, _ := store.Put(repo, syncgate.Change{Path: ".git/refs/heads/main", Data: []byte(strings.Repeat("b", 40) + "\n")}, "protected branch")
	d := &driver.Mock{}
	r := run(t, d, &fakeTransport{}, state, "sync", "review")
	if r.rc != 0 || !strings.Contains(r.out, "+ two") || !strings.Contains(r.out, "update-ref refs/heads/main") || !strings.Contains(r.out, ".vscode/tasks.json (write)") {
		t.Fatalf("%+v", r)
	}
	if r := run(t, d, &fakeTransport{}, state, "sync", "review", "--apply", conflictID); r.rc != 0 {
		t.Fatalf("%+v", r)
	}
	if b, _ := os.ReadFile(filepath.Join(repo, "notes.txt")); string(b) != "one\ntwo\n" {
		t.Errorf("not applied: %q", b)
	}
	if r := run(t, d, &fakeTransport{}, state, "sync", "review", "--apply", refID); r.rc != 0 || !strings.Contains(r.out, "does not move your branches") {
		t.Errorf("%+v", r)
	}
	if b, _ := os.ReadFile(filepath.Join(repo, ".git/refs/heads/main")); len(b) != 0 {
		t.Error("review wrote a ref")
	}
	if r := run(t, d, &fakeTransport{}, state, "sync", "review", "--discard", fileID); r.rc != 0 {
		t.Errorf("%+v", r)
	}
	if held, _ := store.List(); len(held) != 1 || held[0].ID != refID {
		t.Errorf("left %v", held)
	}
	if r := run(t, d, &fakeTransport{}, state, "sync", "review", "--apply", "nope"); r.rc != 1 {
		t.Errorf("%+v", r)
	}
	if r := run(t, d, &fakeTransport{}, t.TempDir(), "sync", "review"); r.out != "No withheld workspace changes.\n" {
		t.Errorf("%+v", r)
	}
	if len(d.Calls) != 0 {
		t.Errorf("review touched the VM: %v", d.Calls)
	}
}

func TestDoctor(t *testing.T) {
	d := &driver.Mock{State: driver.Running, EP: driver.SSHEndpoint{Host: "h", Port: 1, User: "root", HostKey: "k"}}
	if r := run(t, d, &fakeTransport{release: goodRelease, reach: "blocked"}, "", "doctor"); r.rc != 0 || strings.Contains(r.out, "FAIL") ||
		!strings.Contains(r.out, "ok    the VM cannot reach the host at 192.168.5.2: blocked") {
		t.Errorf("%+v", r)
	}
	if r := run(t, d, &fakeTransport{release: goodRelease, reach: "reachable"}, "", "doctor"); r.rc != 1 || !strings.Contains(r.out, "FAIL  the VM cannot reach the host at 192.168.5.2: reachable") {
		t.Errorf("%+v", r)
	}
	// check 3: a canary under each runtime
	if r := run(t, d, &fakeTransport{release: goodRelease, reach: "blocked"}, "", "doctor"); !strings.Contains(r.out, "ok    a canary sandbox under Kata: kernel") ||
		!strings.Contains(r.out, "ok    a canary sandbox under gVisor: kernel") {
		t.Errorf("%+v", r)
	}
	tr := &fakeTransport{release: goodRelease, reach: "blocked", canaryFail: map[string]string{"gvisor": "did not run: no runsc"}}
	if r := run(t, d, tr, "", "doctor"); r.rc != 1 || !strings.Contains(r.out, "FAIL  a canary sandbox under gVisor: did not run: no runsc") {
		t.Errorf("%+v", r)
	}
}

// netdMock is a driver whose network is a host process that can die (driver.NetworkOwner).
type netdMock struct {
	*driver.Mock
	dead bool
}

func (n *netdMock) Network(context.Context) driver.NetworkReport {
	if n.dead {
		return driver.NetworkReport{Detail: "netd is gone"}
	}
	return driver.NetworkReport{Running: true, Detail: "running (pid 7)"}
}

func (n *netdMock) Stop(ctx context.Context) error {
	n.dead = false // the next start brings up a new netd
	return n.Mock.Stop(ctx)
}

func TestNetdReported(t *testing.T) {
	d := &netdMock{Mock: &driver.Mock{State: driver.Running, EP: driver.SSHEndpoint{Host: "h", Port: 1, User: "root", HostKey: "k"}}}
	tr := &fakeTransport{release: goodRelease, reach: "blocked"}
	if r := run(t, d, tr, "", "vm", "status"); r.rc != 0 || !strings.Contains(r.out, "netd:   running (pid 7)\n") {
		t.Errorf("status: %+v", r)
	}
	if r := run(t, d, tr, "", "doctor"); r.rc != 0 || !strings.Contains(r.out, "ok    sandbox netd (the VM's network and host-reach control): running (pid 7)") {
		t.Errorf("doctor: %+v", r)
	}

	d.dead = true
	if r := run(t, d, tr, "", "vm", "status"); r.rc != 1 || !strings.Contains(r.out, "netd:   netd is gone") {
		t.Errorf("status, netd dead: %+v", r)
	}
	if r := run(t, d, tr, "", "doctor"); r.rc != 1 || !strings.Contains(r.out, "FAIL  sandbox netd") {
		t.Errorf("doctor, netd dead: %+v", r)
	}
	if r := run(t, d, tr, "", "ls"); r.rc != 1 || !strings.Contains(r.err, "netd is gone") || len(tr.runs) != 0 {
		t.Errorf("proxy, netd dead: %+v %v", r, tr.runs)
	}
	d.Calls = nil
	if r := run(t, d, tr, "", "vm", "start"); r.rc != 0 || !strings.Contains(r.out, "restarting the sandbox VM") ||
		!strings.Contains(strings.Join(d.Calls, " "), "Stop Start") || d.dead {
		t.Errorf("start, netd dead: %+v %v", r, d.Calls)
	}
}

func TestProxyPullsAudit(t *testing.T) {
	d := &driver.Mock{State: driver.Running, EP: driver.SSHEndpoint{Host: "h", Port: 1, User: "root", HostKey: "k"}}
	tr := &fakeTransport{release: goodRelease, auditSessions: "s-one\n", auditRecords: map[string]string{
		"s-one/events.jsonl": `{"seq":1,"session":"s-one","type":"session_requested"}` + "\n"}}
	state := t.TempDir()
	if r := run(t, d, tr, state, "list"); r.rc != 0 || tr.pulls != 1 {
		t.Fatalf("%+v pulls %d", r, tr.pulls)
	}
	b, err := os.ReadFile(filepath.Join(state, "logs", "s-one", "events.jsonl"))
	if err != nil || !strings.Contains(string(b), "session_requested") {
		t.Errorf("%q %v", b, err)
	}
	if r := run(t, d, tr, state, "vm", "stop"); r.rc != 0 || tr.pulls != 2 {
		t.Errorf("vm stop did not pull first: %+v pulls %d", r, tr.pulls)
	}
}
