package workspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

func TestFixRepoPathCaseInsensitive(t *testing.T) {
	home := t.TempDir()
	// A case-folding volume is simulated by the repo's own spelling: .SSH beside the forbidden .ssh.
	repo := filepath.Join(home, ".SSH")
	os.MkdirAll(repo, 0o755)
	if out, err := exec.Command("git", "init", "-q", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	c := Ctx{Env: config.Env{Home: home}}
	if err := c.ValidateRepoPath(repo); err != nil {
		t.Fatalf("legacy: %v (the bash compares exact case)", err)
	}
	defer deviation.Force(deviation.RepoPathCaseInsensitive)()
	if err := c.ValidateRepoPath(repo); err == nil {
		t.Error("fixed: ~/.SSH must be refused like ~/.ssh")
	}
	ok := filepath.Join(home, "Repos", "App")
	os.MkdirAll(ok, 0o755)
	exec.Command("git", "init", "-q", ok).Run()
	if err := c.ValidateRepoPath(ok); err != nil {
		t.Errorf("fixed: an ordinary mixed-case repo refused: %v", err)
	}
}

func TestFixWorkspaceHashPruneBelowRoot(t *testing.T) {
	dir := t.TempDir()
	repo := dir + "/build" // a prune name
	os.MkdirAll(repo+"/.git/objects/ab", 0o755)
	os.WriteFile(repo+"/a.txt", []byte("a"), 0o644)
	os.WriteFile(repo+"/.git/objects/ab/cd", []byte("o"), 0o644)
	prune := []string{"build", "node_modules"}
	if n := len(HashWorkspace(repo, prune)); n != 0 {
		t.Fatalf("legacy: %d files hashed; the bash pruned the repo itself", n)
	}
	if n := len(HashWorkspace(dir+"/build/", nil)); n != 2 {
		t.Fatalf("legacy: %d files with a trailing slash; the bash hashed the git objects too", n)
	}
	defer deviation.Force(deviation.WorkspaceHashPruneBelowRoot)()
	for _, ws := range []string{repo, repo + "/", repo + "//"} {
		got := HashWorkspace(ws, prune)
		if len(got) != 1 || !strings.HasSuffix(got[0], "a.txt") {
			t.Errorf("fixed: %q hashed %q, want only a.txt", ws, got)
		}
	}
}

func TestFixDiffCountOnce(t *testing.T) {
	log, repo := t.TempDir(), t.TempDir()
	os.WriteFile(repo+"/a", []byte("a"), 0o644)
	CaptureBaseline(log, []string{repo}, nil)
	os.WriteFile(repo+"/a", []byte("b"), 0o644)
	if got := CaptureDiff(log, []string{repo}, nil); strings.Join(got, "|") != "  Workspace diff: 2|0 line(s) changed." {
		t.Fatalf("legacy: %q", got)
	}
	defer deviation.Force(deviation.DiffCountOnce)()
	if got := CaptureDiff(log, []string{repo}, nil); strings.Join(got, "|") != "  Workspace diff: 2 line(s) changed." {
		t.Errorf("fixed: %q", got)
	}
}
