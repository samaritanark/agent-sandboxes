package syncgate

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func gitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", dir).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	return dir
}

func setHooks(t *testing.T, repo, v string) {
	t.Helper()
	if out, err := exec.Command("git", "-C", repo, "config", "core.hooksPath", v).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
}

func TestRepoHooksPath(t *testing.T) {
	repo := gitRepo(t)
	if hp, err := RepoHooksPath(repo); hp != "" || err != nil {
		t.Errorf("unset: %q %v", hp, err)
	}
	outside := t.TempDir()
	for v, want := range map[string]string{
		".githooks":                         ".githooks",
		"tools/hooks/":                      "tools/hooks",
		filepath.Join(repo, "ci", "hooks"):  "ci/hooks",
		filepath.Join(outside, "hooks"):     "",
		"../elsewhere":                      "",
		filepath.Join(repo, "a", "..", "b"): "b",
	} {
		setHooks(t, repo, v)
		hp, err := RepoHooksPath(repo)
		if hp != want || err != nil {
			t.Errorf("%q: %q %v, want %q", v, hp, err, want)
		}
	}
	setHooks(t, repo, ".")
	if _, err := RepoHooksPath(repo); err == nil || !strings.Contains(err.Error(), "top directory") {
		t.Errorf("the repository itself: %v", err)
	}
	// The repository reached through a symlink: still placed inside it.
	if runtime.GOOS != "windows" {
		link := filepath.Join(t.TempDir(), "link")
		os.Symlink(repo, link)
		setHooks(t, repo, filepath.Join(repo, ".githooks"))
		if hp, err := RepoHooksPath(link); hp != ".githooks" || err != nil {
			t.Errorf("through a symlink: %q %v", hp, err)
		}
	}
	if _, err := RepoHooksPath(filepath.Join(outside, "missing")); err == nil {
		t.Error("a missing repository did not fail")
	}
}
