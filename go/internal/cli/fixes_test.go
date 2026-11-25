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
