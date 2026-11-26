package app

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/syncagent"
)

// agentTransport runs the sync agent in-process on vmdir for each sync connection.
type agentTransport struct {
	vmdir string
	mu    sync.Mutex
	conns int
}

func (f *agentTransport) Run(_ context.Context, _ driver.SSHEndpoint, argv []string, stdin io.Reader, stdout, _ io.Writer, _ bool) (int, error) {
	if len(argv) > 2 && strings.Contains(argv[2], "__sync-agent") {
		f.mu.Lock()
		f.conns++
		f.mu.Unlock()
		if err := syncagent.Serve(f.vmdir, stdin, stdout); err != nil {
			return 1, nil
		}
		return 0, nil
	}
	return 0, nil
}

func (f *agentTransport) Output(_ context.Context, _ driver.SSHEndpoint, argv []string, _ int) ([]byte, error) {
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
}
