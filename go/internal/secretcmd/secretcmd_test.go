package secretcmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHostStore: the command the host binary runs stores, lists, and deletes in the directory it is
// given, shown with ~ for the home directory.
func TestHostStore(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".sandbox", "secrets")
	run := func(stdin string, args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		rc := Run(args, Env{Dir: dir, Home: home, Stdin: strings.NewReader(stdin),
			Getenv: func(k string) string { return map[string]string{"TOK": "from env"}[k] }}, &out, &errb)
		return rc, out.String(), errb.String()
	}
	if rc, out, _ := run("", "list"); rc != 0 || out != "No secrets in ~/.sandbox/secrets/.\nAdd one with: sandbox secret set <NAME>\n" {
		t.Fatalf("%d %q", rc, out)
	}
	if rc, out, _ := run("v1", "set", "GH_TOKEN"); rc != 0 || out != "Stored secret 'GH_TOKEN'.\n" {
		t.Fatalf("%d %q", rc, out)
	}
	if rc, _, _ := run("", "set", "OTHER", "--from-env=TOK"); rc != 0 {
		t.Fatal(rc)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "OTHER")); string(b) != "from env" {
		t.Errorf("%q", b)
	}
	if rc, out, _ := run("", "list"); rc != 0 || !strings.HasPrefix(out, "NAME ") || !strings.Contains(out, "GH_TOKEN") {
		t.Errorf("%d %q", rc, out)
	}
	if rc, out, _ := run("", "delete", "GH_TOKEN"); rc != 0 || out != "Deleted secret 'GH_TOKEN'.\n" {
		t.Errorf("%d %q", rc, out)
	}
	if rc, _, errs := run("", "set", "bad-name"); rc != 1 || errs == "" {
		t.Errorf("bad name: %d %q", rc, errs)
	}
	if rc, out, _ := run("", "--help"); rc != 0 || !strings.HasPrefix(out, "sandbox secret") {
		t.Errorf("help: %d %q", rc, out)
	}
	var errb bytes.Buffer
	if Run([]string{"bogus"}, Env{Dir: dir, StderrTTY: true}, &bytes.Buffer{}, &errb); !strings.HasPrefix(errb.String(), "\033[31mERROR:\033[0m Unknown 'secret' subcommand") {
		t.Errorf("color: %q", errb.String())
	}
}
