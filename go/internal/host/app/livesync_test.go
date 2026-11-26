package app

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/syncagent"
)

// agentTransport runs the sync agent in-process on vmdir for each sync connection.
type agentTransport struct {
	vmdir   string
	mu      sync.Mutex
	conns   int
	scripts []string // each sync connection's and epoch read's shell script
	resume  string   // the VM's answer to __resume-repos
}

func (f *agentTransport) Run(_ context.Context, _ driver.SSHEndpoint, argv []string, stdin io.Reader, stdout, _ io.Writer, _ bool) (int, error) {
	if len(argv) > 2 && strings.Contains(argv[2], "__sync-agent") {
		f.mu.Lock()
		f.conns++
		f.scripts = append(f.scripts, argv[2])
		f.mu.Unlock()
		if err := syncagent.Serve(f.vmdir, stdin, stdout); err != nil {
			return 1, nil
		}
		return 0, nil
	}
	return 0, nil
}

func (f *agentTransport) Output(_ context.Context, _ driver.SSHEndpoint, argv []string, _ int) ([]byte, error) {
	if indexOf(argv, ResumeRepos) >= 0 {
		return []byte(f.resume), nil
	}
	if len(argv) > 2 {
		f.mu.Lock()
		f.scripts = append(f.scripts, argv[2])
		f.mu.Unlock()
	}
	return []byte("0123456789abcdef0123456789abcdef\n"), nil // the copy's epoch
}

// TestLiveSync: while a session runs, a change the agent makes reaches the host without waiting
// for the end, over one agent connection per repository, and the summary counts it.
func TestLiveSync(t *testing.T) {
	old := LiveSyncInterval
	LiveSyncInterval = 20 * time.Millisecond
	defer func() { LiveSyncInterval = old }()
	repo, vmdir, state := t.TempDir(), t.TempDir(), t.TempDir()
	if out, err := exec.Command("git", "init", "-q", repo).CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
	os.WriteFile(filepath.Join(repo, "README"), []byte("hi\n"), 0o644)
	tr := &agentTransport{vmdir: vmdir}
	var out bytes.Buffer
	a := &app{env: Env{Transport: tr, StateDir: state, Stdout: &out, Stderr: &out}, ctx: context.Background()}
	if _, _, err := a.syncRepo(driver.SSHEndpoint{}, repo); err != nil {
		t.Fatal(err)
	}
	l := a.startLiveSync(driver.SSHEndpoint{}, []string{repo})
	os.WriteFile(filepath.Join(vmdir, "agent.txt"), []byte("from the agent\n"), 0o644)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if b, _ := os.ReadFile(filepath.Join(repo, "agent.txt")); string(b) == "from the agent\n" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the agent's change did not reach the host while the session ran")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// a change made just before the end comes back with the final pass
	os.WriteFile(filepath.Join(vmdir, "last.txt"), []byte("last\n"), 0o644)
	l.finish()
	if _, err := os.Stat(filepath.Join(repo, "last.txt")); err != nil {
		t.Error("the final pass did not bring the last change")
	}
	if !strings.Contains(out.String(), "==> The session's changes synced to the host: 2 file(s).") || tr.conns != 2 {
		t.Errorf("summary %q, connections %d", out.String(), tr.conns)
	}
	// the copy is made, and kept, readable by the sync group (the gates' git user)
	for _, sc := range tr.scripts {
		if strings.Contains(sc, "install -d") && !strings.Contains(sc, " -m 0750 ") {
			t.Errorf("copy mode in %q", sc)
		}
	}
	if n := len(tr.scripts); n < 3 {
		t.Errorf("scripts %q", tr.scripts)
	}
}

// TestPrepareResume: a resumed session's repositories are synced before the attach, but only those
// this host synced before; the VM cannot name another directory, and a bad answer syncs nothing.
func TestPrepareResume(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("host paths are POSIX paths the VM mirrors; v3 does not run sessions from a Windows host yet")
	}
	repo, other, vmdir, state := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	for _, r := range []string{repo, other} {
		if out, err := exec.Command("git", "init", "-q", r).CombinedOutput(); err != nil {
			t.Fatal(string(out))
		}
	}
	tr := &agentTransport{vmdir: vmdir}
	var out bytes.Buffer
	a := &app{env: Env{Transport: tr, StateDir: state, Stdout: &out, Stderr: &out}, ctx: context.Background()}
	if _, _, err := a.syncRepo(driver.SSHEndpoint{}, repo); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(vmdir, "while-away.txt"), []byte("x\n"), 0o644)
	tr.resume = `{"repos":["` + repo + `","` + other + `"]}`
	got := a.prepareResume(driver.SSHEndpoint{}, "ses-20261126-213445-5114")
	if strings.Join(got, ",") != repo || !strings.Contains(out.String(), "WARNING: not syncing "+other) {
		t.Errorf("%q\n%s", got, out.String())
	}
	if _, err := os.Stat(filepath.Join(repo, "while-away.txt")); err != nil {
		t.Error("the resume did not sync the session's repository first")
	}
	for _, bad := range []string{"", `{"repos":["rel"]}`, `{"repos":["` + repo + `"]} x`, `{"secrets":[],"repos":["` + repo + `"]}`} {
		tr.resume = bad
		if got := a.prepareResume(driver.SSHEndpoint{}, "ses-20261126-213445-5114"); len(got) != 0 {
			t.Errorf("%q synced %q", bad, got)
		}
	}
	for args, want := range map[string]string{"ses-20261126-213445-5114 --keep-alive": "ses-20261126-213445-5114",
		"--keep-alive ses-20261126-213445-5114": "ses-20261126-213445-5114", "../x": "", "": ""} {
		if got := resumeSessionID(strings.Fields(args)); got != want {
			t.Errorf("%q: %q", args, got)
		}
	}
}
