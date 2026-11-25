package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestFixExceptionSpecOneLine(t *testing.T) {
	home := t.TempDir()
	repo := home + "/ex"
	os.MkdirAll(repo, 0o755)
	if out, err := exec.Command("git", "init", "-q", repo).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	evil := "n\nsecret.txt:rule-a:3\nz"
	os.WriteFile(repo+"/"+evil, []byte("s"), 0o644)
	os.MkdirAll(home+"/scen", 0o755)
	os.WriteFile(home+"/scen/ws.json", []byte(`[{"File":"@REPO@/n\nsecret.txt:rule-a:3\nz","RuleID":"r","StartLine":1}]`), 0o644)
	stubDir, _ := filepath.Abs("../gate/testdata/scan/stub")
	t.Setenv("PATH", stubDir+":/usr/bin:/bin")
	t.Setenv("STUB_SCEN", home+"/scen")
	t.Setenv("STUB_LOG", home+"/stub.log")
	t.Setenv("STUB_ROOT", home)
	run := func() (int, string) {
		os.Remove(repo + "/.betterleaksignore")
		var out, errb bytes.Buffer
		rc := Run([]string{"exceptions", "add", "--repo", repo, evil + ":r:1"}, fixtureEnv("none", home, "/nonexistent", nil), &out, &errb)
		b, _ := os.ReadFile(repo + "/.betterleaksignore")
		return rc, string(b)
	}
	if rc, ign := run(); rc != 0 || ign != "n\nsecret.txt:rule-a:3\nz:r:1\n" {
		t.Fatalf("legacy: rc=%d ignore=%q (the bash records every line)", rc, ign)
	}
	defer deviation.Force(deviation.ExceptionSpecOneLine)()
	if rc, ign := run(); rc != 1 || ign != "" {
		t.Errorf("fixed: rc=%d ignore=%q", rc, ign)
	}
}

func TestFixLinkMissingCloneMessage(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(home+"/.sandbox/overlays/team", 0o755) // recorded, but not a git clone
	os.WriteFile(home+"/.sandbox/config.yaml", []byte("overlay: "+home+"/.sandbox/overlays/team\nlink_url: u\nlink_ref: main\n"), 0o644)
	run := func(sub string) (int, string, string) {
		var out, errb bytes.Buffer
		rc := Run([]string{"link", sub}, fixtureEnv("none", home, "/nonexistent", nil), &out, &errb)
		return rc, out.String(), errb.String()
	}
	if rc, o, e := run("status"); rc != 1 || o != "" || e != "" {
		t.Fatalf("legacy: rc=%d %q %q (the bash exits 1 silently)", rc, o, e)
	}
	defer deviation.Force(deviation.LinkMissingCloneMessage)()
	if rc, _, e := run("status"); rc != 0 || !bytes.Contains([]byte(e), []byte("may be stale")) {
		t.Errorf("fixed status: rc=%d %q", rc, e)
	}
	if rc, _, e := run("sync"); rc != 1 || !bytes.Contains([]byte(e), []byte("missing or not a git clone")) {
		t.Errorf("fixed sync: rc=%d %q", rc, e)
	}
}

func TestFixCleanupDaysValidated(t *testing.T) {
	run := func(days string) (int, bool) {
		home := t.TempDir()
		os.MkdirAll(home+"/logs/ses-fresh", 0o755)
		var out, errb bytes.Buffer
		rc := Run([]string{"cleanup", "--older-than", days}, fixtureEnv("none", home, "/nonexistent", nil), &out, &errb)
		_, err := os.Stat(home + "/logs/ses-fresh")
		return rc, err == nil
	}
	if rc, kept := run("-5"); rc != 0 || kept {
		t.Fatalf("legacy: rc=%d kept=%v (the bash removes every session for -5)", rc, kept)
	}
	defer deviation.Force(deviation.CleanupDaysValidated)()
	for _, d := range []string{"-5", "abc", "1.5", " 3"} {
		if rc, kept := run(d); rc != 1 || !kept {
			t.Errorf("fixed %q: rc=%d kept=%v", d, rc, kept)
		}
	}
	if rc, kept := run("30"); rc != 0 || !kept {
		t.Errorf("fixed 30: rc=%d kept=%v", rc, kept)
	}
}

func TestFixDuplicateBasenameExact(t *testing.T) {
	// Two distinct repos under "My Repos/" share the token "My"; a pair named "my r" differs only
	// after the space.
	under := []string{"/h/My Repos/a", "/h/My Repos/b"}
	spaced := []string{"/h/x/my r", "/h/y/my s"}
	if d := firstDuplicate(xargsBasenames(under)); d != "My" {
		t.Fatalf("legacy: %q, want the bash's false duplicate My", d)
	}
	defer deviation.Force(deviation.DuplicateBasenameExact)()
	if d := firstDuplicate(xargsBasenames(under)); d != "" {
		t.Errorf("fixed: distinct repos refused as duplicate %q", d)
	}
	if d := firstDuplicate(xargsBasenames(spaced)); d != "" {
		t.Errorf("fixed: %q", d)
	}
	if d := firstDuplicate(xargsBasenames([]string{"/a/my r", "/b/my r"})); d != "my r" {
		t.Errorf("fixed: a real duplicate gave %q", d)
	}
}

func TestFixLiteralProfileLists(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"A1", "A2"} {
		os.WriteFile(filepath.Join(dir, f), nil, 0o644)
	}
	wd, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(wd)
	eq := func(a, b []string) bool {
		return strings.Join(a, "\x00") == strings.Join(b, "\x00") && len(a) == len(b)
	}
	if got := profileListNames("A*,B C,GH"); !eq(got, []string{"A1", "A2", "BC", "GH"}) {
		t.Fatalf("legacy: %q (the bash globs against the cwd and deletes inner spaces)", got)
	}
	defer deviation.Force(deviation.LiteralProfileLists)()
	if got := profileListNames("A*, B C ,GH,,"); !eq(got, []string{"A*", "B C", "GH"}) {
		t.Errorf("fixed: %q", got)
	}
}

func TestFixAllowEgressFullCheck(t *testing.T) {
	run := func(domain string) (int, string) {
		home := t.TempDir()
		os.MkdirAll(home+"/logs/ses-1", 0o755)
		os.WriteFile(home+"/logs/ses-1/session.json", []byte(`{"agent":"claude","tier":1,"allowed_domains":[]}`), 0o644)
		root, _ := filepath.Abs(filepath.Join("..", "..", ".."))
		env := fixtureEnv("none", home, root, nil)
		var out, errb bytes.Buffer
		handoffOut, handoffErr = &out, &errb
		rc := Run([]string{"allow", "ses-1", "--add-domain", domain}, env, &out, &errb)
		return rc, errb.String()
	}
	esc := "smtp" + "\\" + "u002eexample.org" // smtp<backslash>u002eexample.org, a YAML escape of smtp.example.org
	// Legacy: only the block lists are consulted, so these reach the liveness test (and stop there,
	// the fixture's session not being live).
	for _, d := range []string{"*.com", "a b", esc} {
		if _, e := run(d); !strings.Contains(e, "not running") {
			t.Fatalf("legacy: %q stopped at %q; the bash passed it to the liveness test", d, e)
		}
	}
	refused := func(ds ...string) {
		t.Helper()
		for _, d := range ds {
			if rc, e := run(d); rc == 0 || strings.Contains(e, "not running") {
				t.Errorf("fixed: %q was not refused (rc=%d %q)", d, rc, e)
			}
		}
	}
	defer deviation.Force(deviation.AllowEgressFullCheck)()
	refused("*.com") // the over-broad wildcard refusal, which --allow-domain always had
	// With the syntax fix the full check also applies (both are on in production), a space and a
	// YAML escape are refused too.
	defer deviation.Force(deviation.StrictEgressSyntax)()
	refused("*.com", "a b", esc)
	if _, e := run("a.example.org"); !strings.Contains(e, "not running") {
		t.Errorf("fixed: a plain domain was refused: %q", e)
	}
}

func TestFixFromEnvNameChecked(t *testing.T) {
	run := func() (int, string) {
		var out, errb bytes.Buffer
		env := fixtureEnv("none", t.TempDir(), "/nonexistent", nil)
		rc := Run([]string{"secret", "set", "GH_TOKEN", "--from-env=a-b"}, env, &out, &errb)
		return rc, errb.String()
	}
	if rc, e := run(); rc != 1 || e != "<ROOT>/lib/secrets.sh: line 116: a-b: invalid variable name\n" {
		t.Fatalf("legacy: rc=%d %q", rc, e)
	}
	defer deviation.Force(deviation.FromEnvNameChecked)()
	if rc, e := run(); rc != 1 || e != "ERROR: --from-env: 'a-b' is not an environment variable name.\n" {
		t.Errorf("fixed: rc=%d %q", rc, e)
	}
}

// The macOS recreate blocker cannot be reached by the Linux oracle; v2's test-resume.sh checks it.
func TestResumeBlockerMacOS(t *testing.T) {
	home := t.TempDir()
	sj := home + "/s.json"
	os.WriteFile(sj, []byte(`{"agent":"claude","tier":1,"profile":"","repos":[]}`), 0o644)
	env := fixtureEnv("none", home, "/nonexistent", nil)
	c := &cmdCtx{env: env}
	if b := c.resumeBlocker(sj); b != "" {
		t.Fatalf("linux: a simple session is blocked: %q", b)
	}
	c.env.IsMacOS = true
	if b := c.resumeBlocker(sj); !strings.Contains(b, "macOS") {
		t.Errorf("macOS: %q", b)
	}
}
