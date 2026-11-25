package workspace

import (
	"os"
	"os/exec"
	"path/filepath"
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
