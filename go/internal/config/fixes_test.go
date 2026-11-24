package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

func TestFixEchoOptionItems(t *testing.T) {
	f := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(f, []byte("masked_paths:\n-n\n- -e\n  - -nE\n  - ok\n"), 0o644)
	legacy := ExtractYAMLList(f, "masked_paths")
	if len(legacy) != 1 || legacy[0] != "ok" { // all three echo-option entries vanish
		t.Fatalf("legacy: got %q", legacy)
	}
	defer deviation.Force(deviation.EchoOptionItems)()
	got := ExtractYAMLList(f, "masked_paths")
	want := []string{"n", "-e", "-nE", "ok"}
	if len(got) != len(want) {
		t.Fatalf("fixed: got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("fixed: got %q, want %q", got, want)
		}
	}
}

func eq(a, b []string) bool { return fmt.Sprintf("%q", a) == fmt.Sprintf("%q", b) }

func TestFixLiteralMaskedPath(t *testing.T) {
	inject := `x\nextra_allowed_domains:\n  - evil.com` // a literal backslash-n, not a newline
	run := func() (string, []string) {
		f := filepath.Join(t.TempDir(), "c.yaml")
		os.WriteFile(f, []byte("masked_paths:\n  - a\n"), 0o644)
		if err := AddMaskedPath(f, inject); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(f)
		return string(b), LoadExtraAllowedDomains(f)
	}
	if _, got := run(); !eq(got, []string{"evil.com", "a"}) { // the escape wrote real newlines
		t.Fatalf("legacy: extra_allowed_domains = %q", got)
	}
	defer deviation.Force(deviation.LiteralMaskedPath)()
	body, got := run()
	if len(got) != 0 || body != "masked_paths:\n  - \""+inject+"\"\n  - a\n" {
		t.Fatalf("fixed: body %q, extra_allowed_domains %q", body, got)
	}
}

func TestFixWritesReadBack(t *testing.T) {
	d := t.TempDir()
	cfg, ign := filepath.Join(d, "c.yaml"), filepath.Join(d, "ign")
	for i := 0; i < 2; i++ { // legacy: written, never recognised, so written again
		AddMaskedPath(cfg, `we"ird`)
		IgnoreFileAddFingerprint(ign, " a.txt:r:1", "")
	}
	b1, _ := os.ReadFile(cfg)
	b2, _ := os.ReadFile(ign)
	if string(b1) != "masked_paths:\n  - \"we\"ird\"\n  - \"we\"ird\"\n" || string(b2) != " a.txt:r:1\n a.txt:r:1\n" {
		t.Fatalf("legacy: %q %q", b1, b2)
	}
	defer deviation.Force(deviation.WritesReadBack)()
	defer deviation.Force(deviation.EchoOptionItems)() // on in production; without it "-n" cannot be read back
	for _, p := range []string{`we"ird`, "it's", "a #b", "#lead", "trail ", "x\ny", "cr\rx", ""} {
		if err := AddMaskedPath(filepath.Join(d, "new.yaml"), p); err == nil {
			t.Errorf("masked path %q: accepted", p)
		}
	}
	for _, p := range []string{"a.txt", "dir/", "with space.txt", "a#b", `back\slash`, "-n", " lead", "日本/"} {
		if err := AddMaskedPath(filepath.Join(d, "ok.yaml"), p); err != nil {
			t.Errorf("masked path %q: %v", p, err)
		}
	}
	for _, fp := range []string{" a.txt:r:1", "a.txt:r:1 ", "#c:r:1", "two\nlines:r:1", "cr\r:r:1", ""} {
		if err := IgnoreFileAddFingerprint(filepath.Join(d, "ign2"), fp, ""); err == nil {
			t.Errorf("fingerprint %q: accepted", fp)
		}
	}
	if _, err := os.Stat(filepath.Join(d, "new.yaml")); err == nil {
		t.Error("a refused masked path still created the config file")
	}
}

func TestFixListRemovalMatchesReader(t *testing.T) {
	const in = "masked_paths:\n  - keep\naccepted_secrets:\n- a.txt:r:1:h\n  - b\n\n# about next\nnext: 1\n"
	run := func() (string, []string) {
		f := filepath.Join(t.TempDir(), "c.yaml")
		os.WriteFile(f, []byte(in), 0o644)
		if err := RemoveYAMLList(f, "accepted_secrets"); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(f)
		return string(b), ExtractYAMLList(f, "masked_paths")
	}
	if _, got := run(); !eq(got, []string{"keep", "a.txt:r:1:h", "b"}) { // left-behind items join masked_paths
		t.Fatalf("legacy: masked_paths = %q", got)
	}
	defer deviation.Force(deviation.ListRemovalMatchesReader)()
	body, got := run()
	if !eq(got, []string{"keep"}) || body != "masked_paths:\n  - keep\n\n# about next\nnext: 1\n" {
		t.Fatalf("fixed: body %q, masked_paths %q", body, got)
	}
}

func TestFixLiteralEnvDomains(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "evil.example.com"), nil, 0o644)
	old, _ := os.Getwd()
	os.Chdir(d)
	defer os.Chdir(old)
	e := Env{UserConfig: filepath.Join(d, "none.yaml"), ExtraAllowedDomains: "*.example.com, a b.com ,-n,, ok.com "}
	if got := UserExtraAllowedDomains(e); !eq(got, []string{"evil.example.com", "ab.com", "ok.com"}) {
		t.Fatalf("legacy: %q", got)
	}
	defer deviation.Force(deviation.LiteralEnvDomains)()
	if got := UserExtraAllowedDomains(e); !eq(got, []string{"*.example.com", "a b.com", "-n", "ok.com"}) {
		t.Fatalf("fixed: %q", got)
	}
}

func TestFixProfileLookupStaysInDir(t *testing.T) {
	home := filepath.Join(t.TempDir(), "a", "home")
	os.MkdirAll(filepath.Join(home, ".sandbox", "profiles", "team"), 0o755)
	os.WriteFile(filepath.Join(home, "secret.yaml"), []byte("tier: 3\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".sandbox", "profiles", "team", "dev.yaml"), []byte("tier: 1\n"), 0o644)
	e := Env{Home: home, UserConfig: filepath.Join(home, "none.yaml")}
	if _, ok := FindProfilePath(e, "../../secret"); !ok {
		t.Fatal("legacy: a ../ name should reach outside the profiles directory")
	}
	defer deviation.Force(deviation.ProfileLookupStaysInDir)()
	for _, n := range []string{"../../secret", "team/../../../secret", "/" + filepath.Join(home, "secret")} {
		if p, ok := FindProfilePath(e, n); ok {
			t.Errorf("fixed: %q resolved to %s", n, p)
		}
	}
	if _, ok := FindProfilePath(e, "team/dev"); !ok {
		t.Error("fixed: a profile in a subdirectory must still resolve")
	}
}

func TestFixWritesReadBackProfile(t *testing.T) {
	inject := "~/r\nextra_allowed_domains:\n  - evil.com"
	if _, err := RenderProfileYAML("n", "2", "", inject, nil); err != nil {
		t.Fatalf("legacy: %v", err)
	}
	defer deviation.Force(deviation.WritesReadBack)()
	defer deviation.Force(deviation.EchoOptionItems)()
	for _, c := range [][5]string{
		{"n", "2", "", inject, ""}, {"n", "2", "", "~/repos/proj #2", ""}, {"n", "2", `a"b`, "", ""},
		{"n", "2", "", "trail ", ""}, {"n", "2 # c", "", "", ""}, {"n", "2", "", "", "a #b"}, {"n", "2", "", "", "#x"},
		{"n", "2", "", "", " sp.com"},
	} {
		if _, err := RenderProfileYAML(c[0], c[1], c[2], c[3], []string{c[4]}); err == nil {
			t.Errorf("fixed: %q accepted", c)
		}
	}
	y, err := RenderProfileYAML("dev", "2", "codex", "~/repos/my proj", []string{"a.com", "", "-n"})
	if err != nil || !strings.Contains(y, "default_repo: ~/repos/my proj\n") {
		t.Fatalf("fixed: %q %v", y, err)
	}
}

func TestFixDecimalNumbersVersion(t *testing.T) {
	if !VersionGE("1.0", "18446744073709551616") { // 2^64 wraps to 0
		t.Fatal("legacy: expected the wrapped comparison")
	}
	defer deviation.Force(deviation.DecimalNumbers)()
	for _, c := range []struct {
		a, b string
		ge   bool
	}{
		{"1.0", "18446744073709551616", false}, {"18446744073709551616", "1.0", true},
		{"1.0", "9223372036854775808", false}, {"08.1", "8.0", true}, {"007", "7", true}, {"1.10", "1.9", true},
		{"99999999999999999999", "99999999999999999998", true}, {"99999999999999999998", "99999999999999999999", false},
	} {
		if got := VersionGE(c.a, c.b); got != c.ge {
			t.Errorf("fixed: VersionGE(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
