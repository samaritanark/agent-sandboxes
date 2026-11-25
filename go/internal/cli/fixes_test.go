package cli

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

func TestFixFlagValueErrors(t *testing.T) {
	run := func() (int, string) {
		var out, errb bytes.Buffer
		env := fixtureEnv("none", t.TempDir(), "/nonexistent", nil)
		rc := Run([]string{"profile", "save", "--tier"}, env, &out, &errb)
		return rc, errb.String()
	}
	if rc, e := run(); rc != 1 || e != "sandbox: line 0: 2: --tier requires a value\n" {
		t.Fatalf("legacy: rc=%d %q", rc, e)
	}
	defer deviation.Force(deviation.FlagValueErrors)()
	if rc, e := run(); rc != 1 || e != "ERROR: --tier requires a value\n" {
		t.Errorf("fixed: rc=%d %q", rc, e)
	}
}

func TestFixCheckHelp(t *testing.T) {
	run := func() (int, string, string) {
		var out, errb bytes.Buffer
		rc := Run([]string{"check", "--help"}, fixtureEnv("none", t.TempDir(), "/nonexistent", nil), &out, &errb)
		return rc, out.String(), errb.String()
	}
	if rc, _, e := run(); rc != 1 || e == "" {
		t.Fatalf("legacy: rc=%d %q (the bash takes --help as the path)", rc, e)
	}
	defer deviation.Force(deviation.CheckHelp)()
	if rc, o, _ := run(); rc != 0 || o != "Usage: sandbox check <WORKSPACE_PATH>\n" {
		t.Errorf("fixed: rc=%d %q", rc, o)
	}
}

func TestFixMaskPathComponents(t *testing.T) {
	bad := []string{"", ".", "..", "a/..", "./x", "x/./y", "a//b"}
	for _, r := range bad {
		if badMaskPath(r) {
			t.Fatalf("legacy: %q refused; the bash accepted it", r)
		}
	}
	defer deviation.Force(deviation.MaskPathComponents)()
	for _, r := range append(bad, "/abs", "../up", "a/../b") {
		if !badMaskPath(r) {
			t.Errorf("fixed: %q accepted", r)
		}
	}
	for _, r := range []string{"file.txt", "dir/", "a/b/c", ".env", "..x", "x..", ".hidden/"} {
		if badMaskPath(r) {
			t.Errorf("fixed: %q refused", r)
		}
	}
}

func TestFixMaskListStatus(t *testing.T) {
	home := t.TempDir()
	repo := home + "/r"
	os.MkdirAll(repo+"/.sandbox", 0o755)
	if out, err := exec.Command("git", "init", "-q", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	os.WriteFile(repo+"/.sandbox/config.yaml", []byte("masked_paths:\n  - x\n"), 0o644)
	run := func() int {
		var out, errb bytes.Buffer
		return Run([]string{"mask", "list", "--repo", repo}, fixtureEnv("none", home, "/nonexistent", nil), &out, &errb)
	}
	if rc := run(); rc != 1 {
		t.Fatalf("legacy: rc=%d, the bash exits 1 when paths are configured", rc)
	}
	defer deviation.Force(deviation.MaskListStatus)()
	if rc := run(); rc != 0 {
		t.Errorf("fixed: rc=%d", rc)
	}
}
