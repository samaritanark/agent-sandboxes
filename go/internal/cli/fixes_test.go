package cli

import (
	"bytes"
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
