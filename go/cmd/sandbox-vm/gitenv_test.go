package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestProtectGit: with the protected configuration, a repository's own hook and fsmonitor do not
// run, and existing command-scope entries are kept.
func TestProtectGit(t *testing.T) {
	repo := t.TempDir()
	mark := filepath.Join(t.TempDir(), "ran")
	run := func(env []string, args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = repo, env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	base := append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+t.TempDir())
	if out, err := run(base, "init", "-q"); err != nil {
		t.Fatal(out)
	}
	hook := "#!/bin/sh\ntouch " + mark + "\n"
	os.WriteFile(filepath.Join(repo, ".git", "hooks", "pre-commit"), []byte(hook), 0o755)
	run(base, "config", "core.fsmonitor", "touch "+mark+" #")
	run(base, "config", "core.pager", "touch "+mark+" #")
	env := map[string]string{"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "user.name", "GIT_CONFIG_VALUE_0": "t"}
	protectGit(func(k string) string { return env[k] }, func(k, v string) error { env[k] = v; return nil })
	full := base
	for k, v := range env {
		full = append(full, k+"="+v)
	}
	os.WriteFile(filepath.Join(repo, "f"), []byte("x"), 0o644)
	if out, err := run(full, "add", "f"); err != nil {
		t.Fatal(out)
	}
	if out, err := run(full, "-c", "user.email=t@x", "commit", "-qm", "m"); err != nil {
		t.Fatal(out)
	}
	if _, err := os.Stat(mark); err == nil {
		t.Error("the repository's hook or fsmonitor ran")
	}
	if out, _ := run(full, "config", "core.pager"); strings.TrimSpace(out) != "cat" {
		t.Errorf("pager %q", out)
	}
	if out, _ := run(full, "config", "user.name"); strings.TrimSpace(out) != "t" || env["GIT_CONFIG_COUNT"] != "8" {
		t.Errorf("earlier entries: %q %v", out, env)
	}
	// without it, the hook runs (the test can see a hook run)
	if out, err := run(append(base, "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=user.name", "GIT_CONFIG_VALUE_0=t"), "-c", "user.email=t@x", "commit", "-q", "--allow-empty", "-m", "m2"); err != nil {
		t.Fatal(out)
	}
	if _, err := os.Stat(mark); err != nil {
		t.Error("the control commit did not run the hook; the test proves nothing")
	}
}
