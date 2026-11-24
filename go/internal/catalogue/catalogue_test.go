package catalogue

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/checks"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

// The differential tests compare against the bash oracle, so they run with every fix off; each fix
// has its own test (fixes_test.go) that turns it on.
func TestMain(m *testing.M) {
	deviation.SetLegacy(true)
	os.Exit(m.Run())
}

func dec64(t *testing.T, f string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(f, "="))
	if err != nil {
		t.Fatalf("bad base64 %q: %v", f, err)
	}
	return string(b)
}

func enc64(s string) string { return "=" + base64.StdEncoding.EncodeToString([]byte(s)) }

func readRows(t *testing.T, path string, n int) [][]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (generate it; see go/README.md)", err)
	}
	var rows [][]string
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		p := strings.Split(l, "\t")
		if len(p) != n {
			t.Fatalf("%s: malformed row %q", path, l)
		}
		rows = append(rows, p)
	}
	return rows
}

const blocked = "blocked_domains:\n  - evil.com\nblocked_cidrs:\n  - 10.0.0.0/8\n"

// newCtx is the context the oracle sets up for case directory c; mode is the cosign stub
// (absent, ok, fail), and log collects the stub's arguments.
func newCtx(c, mode string, log *strings.Builder) Ctx {
	os.WriteFile(c+"/blocked.yaml", []byte(blocked), 0o644)
	return Ctx{
		Ctx:         checks.Ctx{Env: config.Env{Home: c, UserConfig: c + "/none.yaml"}, OrgFile: c + "/blocked.yaml"},
		SandboxRoot: c + "/root",
		HasCosign:   func() bool { return mode == "ok" || mode == "fail" },
		RunCosign: func(args []string) bool {
			log.WriteString(strings.Join(args, " ") + "\n")
			return mode == "ok"
		},
	}
}

func runCase(t *testing.T, dir string, row []string) string {
	t.Helper()
	id, op := row[0], row[1]
	a1, a2, a3 := dec64(t, row[2]), dec64(t, row[3]), dec64(t, row[4])
	c := filepath.Join(dir, id)
	os.MkdirAll(c+"/root", 0o755)
	defer os.RemoveAll(c)
	var log strings.Builder
	x := newCtx(c, a2, &log)
	entry := c + "/entry.yaml"
	if op == "validate" || op == "field" || op == "haskey" {
		os.WriteFile(entry, []byte(a1), 0o644)
	}
	rc, out, errOut := 0, "", ""
	rcOf := func(ok bool) {
		if !ok {
			rc = 1
		}
	}
	switch op {
	case "name":
		rcOf(IsValidName(a1))
	case "resolve":
		for _, ch := range a1 {
			switch ch {
			case 'O':
				os.MkdirAll(c+"/root/config/catalogue", 0o755)
				os.WriteFile(c+"/root/config/catalogue/"+a2+".yaml", []byte("kind: service\n"), 0o644)
			case 'V':
				os.MkdirAll(c+"/ov/catalogue", 0o755)
				os.WriteFile(c+"/ov/catalogue/"+a2+".yaml", []byte("kind: mcp\n"), 0o644)
				x.SandboxOverlay = c + "/ov"
			case 'd':
				os.MkdirAll(c+"/ov", 0o755)
			case 'E':
				x.SandboxOverlay = c + "/ov"
			}
		}
		p, ok := x.Resolve(a2)
		if rcOf(ok); ok {
			out = p + "\n"
		}
	case "validate":
		if err := x.ValidateEntry(entry, a3); err != nil {
			rc, errOut = 1, err.Error()+"\n"
		}
	case "field":
		raw := config.ExtractYAMLScalar(entry, a2)
		if raw == "" {
			raw = a3
		}
		if out = Field(entry, a2, a3) + "\n"; echoOption.MatchString(raw) {
			out = "" // `echo -n` prints no newline either
		}
	case "haskey":
		rcOf(HasKey(entry, a2))
	default:
		t.Fatalf("%s: unknown op %q", id, op)
	}
	cl := func(s string) string { return enc64(strings.ReplaceAll(s, c, "<C>")) }
	return fmt.Sprintf("%s\t%d\t%s\t%s\t%s", id, rc, cl(out), cl(errOut), cl(log.String()))
}

func TestCatalogueGolden(t *testing.T) {
	cases := readRows(t, filepath.Join("testdata", "cases.tsv"), 5)
	golden := readRows(t, filepath.Join("testdata", "golden-catalogue.tsv"), 5)
	if len(cases) != len(golden) {
		t.Fatalf("%d cases but %d golden lines: regenerate the golden file", len(cases), len(golden))
	}
	dir := t.TempDir()
	var bad []string
	for i, row := range cases {
		want := strings.Join(golden[i], "\t")
		if got := runCase(t, dir, row); got != want {
			w, g := strings.Split(want, "\t"), strings.Split(got, "\t")
			bad = append(bad, fmt.Sprintf("%s %s %q %q %q\n    oracle: rc=%s out=%q err=%q cosign=%q\n    port:   rc=%s out=%q err=%q cosign=%q",
				row[0], row[1], dec64(t, row[2]), dec64(t, row[3]), dec64(t, row[4]),
				w[1], dec64(t, w[2]), dec64(t, w[3]), dec64(t, w[4]), g[1], dec64(t, g[2]), dec64(t, g[3]), dec64(t, g[4])))
		}
	}
	t.Logf("lib/catalogue.sh: %d cases, %d divergences", len(cases), len(bad))
	if len(bad) > 0 {
		n := len(bad)
		if n > 12 {
			bad = bad[:12]
		}
		t.Errorf("%d divergence(s) from the oracle, first %d:\n  %s", n, len(bad), strings.Join(bad, "\n  "))
	}
}

func TestCatalogueLiveOracle(t *testing.T) {
	if os.Getenv("SBX_ORACLE") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI is set but SBX_ORACLE is not: the live oracle must run in CI (no silent skips)")
		}
		t.Skip("set SBX_ORACLE=1 on Linux to run the bash oracle live")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("the oracle must run on Linux")
	}
	cmd := exec.Command(filepath.Join("testdata", "oracle.sh"))
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join("testdata", "golden-catalogue.tsv"))
	if string(b) != string(out) {
		t.Error("golden-catalogue.tsv differs from the live oracle: regenerate it")
	}
}
