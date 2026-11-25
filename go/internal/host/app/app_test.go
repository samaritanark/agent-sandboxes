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

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

type fakeTransport struct {
	release string
	relErr  error
	rc      int
	runs    [][]string
	ttys    []bool
}

func (f *fakeTransport) Run(_ context.Context, _ driver.SSHEndpoint, argv []string, _ io.Reader, stdout, _ io.Writer, tty bool) (int, error) {
	f.runs = append(f.runs, argv)
	f.ttys = append(f.ttys, tty)
	io.WriteString(stdout, "ran\n")
	return f.rc, nil
}

func (f *fakeTransport) Output(_ context.Context, _ driver.SSHEndpoint, argv []string, max int) ([]byte, error) {
	if !reflect.DeepEqual(argv, []string{"cat", ReleasePath}) {
		return nil, errors.New("unexpected Output")
	}
	return []byte(f.release), f.relErr
}

type res struct {
	rc       int
	out, err string
}

func run(t *testing.T, d *driver.Mock, tr *fakeTransport, state string, args ...string) res {
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
	if want := []string{"sandbox", "run", "--repo", "a b", "--name", "it's"}; !reflect.DeepEqual(tr.runs[0], want) || !tr.ttys[0] {
		t.Fatalf("proxied %q tty=%v", tr.runs[0], tr.ttys[0])
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
		{driver.Running, "IMAGE_VERSION=3.0.0\nCONTROL_API=2\n", "sandbox upgrade --app"},
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
	if r := run(t, d, tr, "", "install"); r.rc != 1 || !strings.Contains(r.err, "not available") {
		t.Errorf("install: %+v", r)
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
