package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLinkCheck: the VM's half of `sandbox link` validates the pushed tree: a valid overlay passes,
// one that needs a newer sandbox says which version, and a missing one fails.
func TestLinkCheck(t *testing.T) {
	home := t.TempDir()
	env := fixtureEnv("full", home, "", nil)
	ov := filepath.Join(home, "overlay-local")
	os.MkdirAll(ov, 0o755)
	os.WriteFile(filepath.Join(ov, "config.yaml"), []byte("vetting: required\n"), 0o644)
	var out, errb bytes.Buffer
	if rc := LinkCheck([]string{ov}, env, &out, &errb); rc != 0 {
		t.Errorf("valid: %d %s", rc, errb.String())
	}
	os.WriteFile(filepath.Join(ov, "config.yaml"), []byte("min_sandbox_version: 99.0.0\n"), 0o644)
	out.Reset()
	if rc := LinkCheck([]string{ov}, env, &out, &errb); rc != LinkCheckNeedsVersion || strings.TrimSpace(out.String()) != "99.0.0" {
		t.Errorf("newer: %d %q %s", rc, out.String(), errb.String())
	}
	if rc := LinkCheck([]string{filepath.Join(home, "none")}, env, &out, &errb); rc != 1 {
		t.Errorf("missing: %d", rc)
	}
	if rc := LinkCheck(nil, env, &out, &errb); rc != 1 {
		t.Errorf("no argument: %d", rc)
	}
}
