package secretcmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
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

// TestBindings: set and bind keep a secret's binding beside it, list shows it, set without
// binding options keeps it, delete removes it, and the options' conflicts are refused.
func TestBindings(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".sandbox", "secrets")
	run := func(stdin string, args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		rc := Run(args, Env{Dir: dir, Home: home, Stdin: strings.NewReader(stdin)}, &out, &errb)
		return rc, out.String(), errb.String()
	}
	binding := func(name string) string {
		b, _ := os.ReadFile(filepath.Join(dir, ".bindings", name))
		return string(b)
	}
	if rc, out, _ := run("v", "set", "GH", "--bind", "uploads.github.com,API.github.com", "--bind=api.github.com"); rc != 0 ||
		out != "Stored secret 'GH'.\nBound 'GH' to api.github.com, uploads.github.com (bearer).\n" {
		t.Fatalf("%d %q", rc, out)
	}
	if b := binding("GH"); b != `{"hosts":["api.github.com","uploads.github.com"],"inject":"bearer"}`+"\n" {
		t.Errorf("stored %q", b)
	}
	if st, _ := os.Stat(filepath.Join(dir, ".bindings", "GH")); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	if rc, out, _ := run("v2", "set", "GH"); rc != 0 || out != "Stored secret 'GH'.\n" || binding("GH") == "" {
		t.Errorf("a new value dropped the binding: %d %q", rc, out)
	}
	run("r", "set", "NPMRC", "--allow-readable")
	run("w", "set", "PLAIN")
	_, out, _ := run("", "list")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 || !strings.HasSuffix(lines[1], "  -> api.github.com,uploads.github.com (bearer)") ||
		!strings.HasSuffix(lines[2], "  readable") || strings.Contains(lines[3], "->") || strings.HasSuffix(lines[3], "readable") {
		t.Errorf("list:\n%s", out)
	}
	if rc, out, _ := run("", "bind", "GH", "--bind", "api.github.com", "--inject", "header:X-Token"); rc != 0 || out != "Bound 'GH' to api.github.com (header:X-Token).\n" {
		t.Errorf("bind: %d %q", rc, out)
	}
	if rc, out, _ := run("", "bind", "GH", "--withhold"); rc != 0 || out != "'GH' is withheld from sessions (no binding).\n" || binding("GH") != "" {
		t.Errorf("withhold: %d %q %q", rc, out, binding("GH"))
	}
	run("", "bind", "NPMRC", "--allow-readable")
	if rc, _, _ := run("", "delete", "NPMRC"); rc != 0 || binding("NPMRC") != "" {
		t.Error("delete left the binding")
	}
	for _, c := range [][]string{
		{"bind", "GH", "--bind", "a.x.com", "--allow-readable"},
		{"bind", "GH", "--inject", "bearer"},
		{"bind", "GH", "--withhold", "--allow-readable"},
		{"bind", "GH", "--bind", "*.x.com"},
		{"bind", "GH", "--bind", "a.x.com", "--inject", "cookie"},
		{"bind", "GH"},
		{"bind", "MISSING", "--bind", "a.x.com"},
		{"bind", "GH", "--bind"},
		{"set", "GH", "--bind", "a.x.com", "--inject", "nope"},
	} {
		if rc, _, errs := run("", c...); rc != 1 || !strings.HasPrefix(errs, "ERROR: ") {
			t.Errorf("%v: %d %q", c, rc, errs)
		}
	}
	// a refused value leaves the binding as it was
	run("", "bind", "GH", "--bind", "a.x.com")
	if rc, _, _ := run("", "set", "GH", "--from-file", filepath.Join(home, "missing"), "--withhold"); rc != 1 || binding("GH") == "" {
		t.Errorf("a failed set changed the binding: %d %q", rc, binding("GH"))
	}
	if rc, out, _ := run("", "--help"); rc != 0 || !strings.Contains(out, "BINDINGS (v3):") {
		t.Errorf("help: %d", rc)
	}
	// legacy (the bash): none of it
	deviation.SetLegacy(true)
	defer deviation.SetLegacy(false)
	if rc, out, _ := run("", "--help"); rc != 0 || strings.Contains(out, "BINDINGS") {
		t.Errorf("legacy help: %d", rc)
	}
	if rc, _, errs := run("", "bind", "GH", "--bind", "a.x.com"); rc != 1 || !strings.Contains(errs, "Unknown 'secret' subcommand: bind") {
		t.Errorf("legacy bind: %d %q", rc, errs)
	}
	if rc, _, errs := run("v", "set", "GH", "--bind", "a.x.com"); rc != 1 || !strings.Contains(errs, "Unknown option for 'secret set': --bind") {
		t.Errorf("legacy set: %d %q", rc, errs)
	}
	if _, out, _ := run("", "list"); strings.Contains(out, "->") {
		t.Errorf("legacy list: %q", out)
	}
}
