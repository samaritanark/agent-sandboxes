package app

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/opstate"
)

// linkTransport is the VM for `link`: it records each operator-state push's file names and answers
// __link-check with rc (and need on stdout).
type linkTransport struct {
	fakeTransport
	pushed [][]string
	rc     int
	need   string
	checks [][]string
}

func (f *linkTransport) Run(ctx context.Context, ep driver.SSHEndpoint, argv []string, stdin io.Reader, stdout, stderr io.Writer, tty bool) (int, error) {
	switch {
	case len(argv) >= 2 && argv[1] == ReceiveOperatorState:
		b, _ := io.ReadAll(stdin)
		tr := tar.NewReader(bytes.NewReader(b))
		var names []string
		for {
			h, err := tr.Next()
			if err != nil {
				break
			}
			names = append(names, h.Name)
		}
		f.pushed = append(f.pushed, names)
		return 0, nil
	case indexOf(argv, LinkCheckCmd) >= 0:
		f.checks = append(f.checks, argv[indexOf(argv, LinkCheckCmd)+1:])
		io.WriteString(stdout, f.need+"\n")
		return f.rc, nil
	}
	return f.fakeTransport.Run(ctx, ep, argv, stdin, stdout, stderr, tty)
}

// TestLink (design 5.1.3): the overlay is cloned on the host into ~/.sandbox/overlays/<name>, its
// tree (not .git) pushed to the VM as the local overlay and validated there, and the link recorded
// in ~/.sandbox/config.yaml; a tree the VM refuses, or one needing a newer sandbox, is not linked;
// status, sync (rolling back a tree the VM refuses), the run-path sync, and unlink work on the
// host's clone.
func TestLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("host paths are POSIX paths the VM mirrors; v3 does not run sessions from a Windows host yet")
	}
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	remote, state := filepath.Join(tmp, "team-overlay.git"), filepath.Join(tmp, "home", ".sandbox")
	os.MkdirAll(remote, 0o755)
	os.MkdirAll(state, 0o700)
	git := func(dir string, args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@e", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git(remote, "init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(remote, "config.yaml"), []byte("vetting: required\n"), 0o644)
	git(remote, "add", ".")
	git(remote, "commit", "-q", "-m", "one")
	first := git(remote, "rev-parse", "HEAD")
	os.WriteFile(filepath.Join(state, "config.yaml"), []byte("# mine\nvetting_max_age_days: 30\n"), 0o600)
	tr := &linkTransport{fakeTransport: fakeTransport{release: goodRelease}}
	var out, errb bytes.Buffer
	env := Env{Driver: &driver.Mock{State: driver.Running}, Transport: tr, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb,
		StateDir: state, Home: filepath.Dir(state), Now: func() time.Time { return time.Unix(1800000000, 0) },
		Getenv: func(string) string { return "" },
		Git: func(dir string, args ...string) (string, error) {
			cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
			cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
			b, err := cmd.Output()
			return strings.TrimRight(string(b), "\n"), err
		}}
	cfg := func() string { b, _ := os.ReadFile(filepath.Join(state, "config.yaml")); return string(b) }
	clone := filepath.Join(state, "overlays", "team-overlay")

	// a tree the VM refuses, or one needing a newer sandbox: nothing linked, no clone left
	for _, c := range []struct {
		rc   int
		want string
	}{{1, "failed validation"}, {linkCheckNeedsVersion, "requires agent-sandboxes >= 9.0.0"}} {
		tr.rc, tr.need = c.rc, "9.0.0"
		errb.Reset()
		if rc := Run(context.Background(), []string{"link", remote}, env); rc != 1 || !strings.Contains(errb.String(), c.want) || strings.Contains(cfg(), "link_url") {
			t.Errorf("rc %d: %d %s", c.rc, rc, errb.String())
		}
		if _, err := os.Stat(clone); err == nil {
			t.Error("a refused clone was left")
		}
	}
	tr.rc, tr.pushed = 0, nil
	if rc := Run(context.Background(), []string{"link", remote}, env); rc != 0 {
		t.Fatalf("%d %s %s", rc, out.String(), errb.String())
	}
	if c := cfg(); !strings.HasPrefix(c, "# mine\nvetting_max_age_days: 30\n") || !strings.Contains(c, "overlay: "+clone+"\n") || !strings.Contains(c, "link_url: "+remote+"\n") ||
		!strings.Contains(c, "link_ref: main\n") || !strings.Contains(c, "link_commit: "+first+"\n") {
		t.Errorf("config:\n%s", c)
	}
	pushedAll := strings.Join(tr.pushed[len(tr.pushed)-1], " ")
	if !strings.Contains(pushedAll, opstate.OverlayLocal+"/config.yaml") || strings.Contains(pushedAll, ".git") {
		t.Errorf("pushed %q", pushedAll)
	}
	if len(tr.checks) == 0 || tr.checks[len(tr.checks)-1][0] != filepath.Dir(state)+"/.sandbox/"+opstate.OverlayLocal {
		t.Errorf("checked %q", tr.checks)
	}
	a := &app{env: env, ctx: context.Background()}
	if a.localOverlay() != clone {
		t.Errorf("the linked clone is not pushed as the local overlay: %q", a.localOverlay())
	}
	errb.Reset()
	if rc := Run(context.Background(), []string{"link", remote}, env); rc != 1 || !strings.Contains(errb.String(), "A link is already active") {
		t.Errorf("second link: %d %s", rc, errb.String())
	}

	// status, then a new commit upstream: behind; sync advances and records it
	os.WriteFile(filepath.Join(remote, "profiles.txt"), []byte("x\n"), 0o644)
	git(remote, "add", ".")
	git(remote, "commit", "-q", "-m", "two")
	second := git(remote, "rev-parse", "HEAD")
	out.Reset()
	Run(context.Background(), []string{"link", "status"}, env)
	if !strings.Contains(out.String(), "1 commit(s) behind 'main'") {
		t.Errorf("status: %s", out.String())
	}
	// the VM refuses the new tree: rolled back
	tr.rc = 1
	errb.Reset()
	if rc := Run(context.Background(), []string{"link", "sync"}, env); rc != 1 || git(clone, "rev-parse", "HEAD") != first || !strings.Contains(cfg(), "link_commit: "+first) {
		t.Errorf("refused sync: %d %s", rc, errb.String())
	}
	tr.rc = 0
	if rc := Run(context.Background(), []string{"link", "sync"}, env); rc != 0 || git(clone, "rev-parse", "HEAD") != second || !strings.Contains(cfg(), "link_commit: "+second) {
		t.Errorf("sync: %d %s", rc, errb.String())
	}
	// the run-path sync: a new upstream commit is taken before a launch; one needing a newer
	// sandbox stops the launch, rolled back
	os.WriteFile(filepath.Join(remote, "more.txt"), []byte("y\n"), 0o644)
	git(remote, "add", ".")
	git(remote, "commit", "-q", "-m", "three")
	third := git(remote, "rev-parse", "HEAD")
	tr.rc = linkCheckNeedsVersion
	errb.Reset()
	if rc := runDieApp(func() { a.linkSyncOnRun(driver.SSHEndpoint{}) }); rc != 1 || git(clone, "rev-parse", "HEAD") != second {
		t.Errorf("run-path sync, newer sandbox needed: %d %s", rc, errb.String())
	}
	tr.rc = 0
	out.Reset()
	a.linkSyncOnRun(driver.SSHEndpoint{})
	if git(clone, "rev-parse", "HEAD") != third || !strings.Contains(out.String(), "linked overlay updated to 'main'") {
		t.Errorf("run-path sync: %s", out.String())
	}

	// unlink: the keys and the clone go, the rest of the config stays
	if rc := Run(context.Background(), []string{"link", "unlink", "--yes"}, env); rc != 0 {
		t.Fatal(errb.String())
	}
	if c := cfg(); c != "# mine\nvetting_max_age_days: 30\n" {
		t.Errorf("after unlink:\n%s", c)
	}
	if _, err := os.Stat(clone); err == nil {
		t.Error("unlink kept the clone")
	}
}

// runDieApp runs f, returning the exit status a.die panicked with (0 if none).
func runDieApp(f func()) (rc int) {
	defer func() {
		if r := recover(); r != nil {
			if c, ok := r.(exitCode); ok {
				rc = int(c)
				return
			}
			panic(r)
		}
	}()
	f()
	return 0
}
