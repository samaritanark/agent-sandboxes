package daemon

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/runtime"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

func readableSpec(t *testing.T, id string) []byte {
	sp, err := sessionspec.Decode(bytes.NewReader(spec(id, 2048)))
	if err != nil {
		t.Fatal(err)
	}
	sp.Readable = []sessionspec.Readable{{Ref: "secret.NPM_TOKEN", EnvVar: "NPM_TOKEN"}, {Ref: "secret.PYPI", EnvVar: "PYPI_TOKEN"}}
	b, _ := sp.Encode()
	return b
}

// TestReadableSecrets: the values are written by the broker's helper into the session's directory
// under ReadableRoot, which is mounted read-only into the agent; the agent's environment names the
// files and holds no value; each is audited; the directory goes with the session.
func TestReadableSecrets(t *testing.T) {
	r := newRig(t)
	fb := &fakeBroker{}
	r.d.Broker, r.d.ReadableRoot = fb, filepath.Join(t.TempDir(), "readable")
	ctx := context.Background()
	id, err := r.d.Start(ctx, readableSpec(t, "s-read"))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(r.d.ReadableRoot, id)
	if b, _ := os.ReadFile(filepath.Join(dir, "NPM_TOKEN")); string(b) != "value of secret.NPM_TOKEN\n" || fb.readableUID != AgentUID {
		t.Fatalf("file %q uid %d", b, fb.readableUID)
	}
	agent := r.rt.vms[id]
	found := false
	for _, m := range agent.Mounts {
		if m.Target == sessionspec.ReadableDir {
			found = m.Source == dir && m.ReadOnly
		}
	}
	if !found {
		t.Errorf("mounts %+v", agent.Mounts)
	}
	env := strings.Join(agent.Env, "\n")
	if !strings.Contains(env, "NPM_TOKEN_FILE=/run/sandbox/secrets/NPM_TOKEN\n") || !strings.Contains(env, "PYPI_TOKEN_FILE=/run/sandbox/secrets/PYPI_TOKEN") ||
		strings.Contains(env, "value of") {
		t.Errorf("env %q", agent.Env)
	}
	if ev := strings.Join(auditTypes(t, r.d.AuditRoot, id, "events.jsonl"), ","); ev != "session_requested,secret_readable,secret_readable,session_running" {
		t.Errorf("events %s", ev)
	}
	if err := r.d.Stop(ctx, id, "operator stop"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the readable directory outlived its session: %v", err)
	}
}

// TestReadableRefusals: without a tmpfs root, or when the helper fails, the session does not start
// and leaves nothing behind.
func TestReadableRefusals(t *testing.T) {
	r := newRig(t)
	r.d.Broker = &fakeBroker{}
	ctx := context.Background()
	if _, err := r.d.Start(ctx, readableSpec(t, "s-noroot")); err == nil || !strings.Contains(err.Error(), "no broker store or tmpfs") {
		t.Fatalf("no root: %v", err)
	}
	r.d.ReadableRoot = filepath.Join(t.TempDir(), "readable")
	r.d.Broker = &fakeBroker{failWith: errors.New("credential secret.NPM_TOKEN is not in the broker store")}
	if _, err := r.d.Start(ctx, readableSpec(t, "s-fail")); err == nil || !strings.Contains(err.Error(), "not in the broker store") {
		t.Fatalf("helper failure: %v", err)
	}
	if len(r.rt.vms) != 0 {
		t.Errorf("microVMs left: %v", r.rt.vms)
	}
	if ents, _ := os.ReadDir(r.d.ReadableRoot); len(ents) != 0 {
		t.Errorf("readable directories left: %v", ents)
	}
}

// TestReadableWrap runs the wrapper under a real shell: each variable is exported with its file's
// exact bytes (trailing newlines kept), the command runs with its own arguments, and an unreadable
// file stops it with 126.
func TestReadableWrap(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "A"), []byte("a value\n\n"), 0o400)
	os.WriteFile(filepath.Join(dir, "B"), []byte("it's $HOME `x`"), 0o400)
	run := func(names []string, args ...string) (string, int) {
		w := readableWrap(names, args)
		if w[0] != Shell || w[3] != "sh" {
			t.Fatalf("wrapper %q", w)
		}
		w[2] = strings.ReplaceAll(w[2], sessionspec.ReadableDir, dir)
		cmd := exec.Command(w[0], w[1:]...)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return out.String(), ee.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return out.String(), 0
	}
	out, rc := run([]string{"A", "B"}, "sh", "-c", `printf '[%s][%s][%s]' "$A" "$B" "$1"`, "x", "one arg")
	if rc != 0 || out != "[a value\n\n][it's $HOME `x`][one arg]" {
		t.Errorf("%d %q", rc, out)
	}
	if noShell(errors.New("no such task")) || noShell(errors.New(`exec: "claude": not found`)) {
		t.Error("an unrelated failure taken for a missing shell")
	}
	out, rc = run([]string{"A", "MISSING"}, "true")
	if rc != 126 || !strings.Contains(out, "cannot read the readable secret MISSING") {
		t.Errorf("missing: %d %q", rc, out)
	}
}

// noShellExecer fails an exec of the shell as an image without one does.
type noShellExecer struct {
	*execer
	tried [][]string
}

func (e *noShellExecer) Exec(ctx context.Context, id, execID string, args []string, tty bool, stdin io.Reader, stdout, stderr io.Writer) (runtime.Process, error) {
	e.tried = append(e.tried, args)
	if args[0] == Shell {
		return nil, errors.New(`failed to create shim task: OCI runtime exec failed: exec: "/bin/sh": stat /bin/sh: no such file or directory`)
	}
	return e.execer.Exec(ctx, id, execID, args, tty, stdin, stdout, stderr)
}

// TestAttachReadable: an attach to a session with readable secrets runs under the wrapper; an
// image without a shell runs the command itself (the files only), audited.
func TestAttachReadable(t *testing.T) {
	for _, shell := range []bool{true, false} {
		r := newRig(t)
		r.d.Broker, r.d.ReadableRoot = &fakeBroker{}, filepath.Join(t.TempDir(), "readable")
		ex := &execer{fakeRuntime: r.rt}
		var rt Runtime = ex
		ns := &noShellExecer{execer: ex}
		if !shell {
			rt = ns
		}
		r.d.Runtime = rt
		ctx := context.Background()
		id, err := r.d.Start(ctx, readableSpec(t, "s-ra"))
		if err != nil {
			t.Fatal(err)
		}
		inR, inW := io.Pipe()
		done := make(chan int, 1)
		go func() {
			c, _ := r.d.Attach(ctx, id, []string{"claude", "--x"}, false, AttachIO{Stdin: inR, Stdout: io.Discard, Stderr: io.Discard}, [2]uint16{}, nil, nil)
			done <- c
		}()
		io.WriteString(inW, "exit\n")
		if c := <-done; c != 3 {
			t.Fatalf("shell %v: exit %d", shell, c)
		}
		p := ex.list()[0]
		if shell {
			if p.args[0] != Shell || strings.Join(p.args[len(p.args)-2:], " ") != "claude --x" || !strings.Contains(p.args[2], "export NPM_TOKEN;") {
				t.Errorf("wrapped %q", p.args)
			}
			continue
		}
		if strings.Join(p.args, " ") != "claude --x" || len(ns.tried) != 2 {
			t.Errorf("no shell: %q tried %q", p.args, ns.tried)
		}
		if ev := strings.Join(auditTypes(t, r.d.AuditRoot, id, "events.jsonl"), ","); !strings.Contains(ev, "attached,secret_readable_file_only,detached") {
			t.Errorf("events %s", ev)
		}
	}
}
