package allowlist

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/agents"
	"github.com/samaritanark/agent-sandboxes/go/internal/checks"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/tier"
)

var base = filepath.Join("testdata")

func TestMain(m *testing.M) {
	deviation.SetLegacy(true)
	os.Exit(m.Run())
}

func dec(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "="))
	if err != nil {
		t.Fatalf("bad base64 %q", s)
	}
	return string(b)
}

func enc(s string) string { return "=" + base64.StdEncoding.EncodeToString([]byte(s)) }

func rows(t *testing.T, name string, n int) [][]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(base, name))
	if err != nil {
		t.Fatalf("%v (generate it; see go/README.md)", err)
	}
	var out [][]string
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		p := strings.Split(l, "\t")
		if len(p) != n {
			t.Fatalf("%s: malformed row %q", name, l)
		}
		out = append(out, p)
	}
	return out
}

// runCase builds case row (id agent tier layout extras) as oracle.sh does and returns its golden line.
func runCase(t *testing.T, dir string, row []string) string {
	id, agent, tierV, layout := row[0], row[1], row[2], row[3]
	var extras []string
	if e := dec(t, row[4]); e != "" {
		extras = strings.Split(strings.TrimSuffix(e, "\x00"), "\x00")
	}
	c := filepath.Join(dir, id)
	os.MkdirAll(c, 0o755)
	defer os.RemoveAll(c)
	root, _ := filepath.Abs(filepath.Join("..", "..", ".."))
	fx := filepath.Join(root, "go/internal/checks/testdata/fx")
	x := checks.Ctx{Env: config.Env{Home: c, UserConfig: c + "/none.yaml"}, OrgFile: c + "/missing.yaml"}
	for _, p := range strings.Split(layout, ",") {
		k, v, ok := strings.Cut(p, "=")
		if !ok || v == "-" {
			continue
		}
		switch k {
		case "o":
			x.OrgFile = filepath.Join(fx, v)
			if v == "REAL" {
				x.OrgFile = filepath.Join(root, "config/blocked-destinations.yaml")
			}
		case "u":
			x.UserConfig = filepath.Join(fx, v)
		case "b":
			b, _ := os.ReadFile(filepath.Join(fx, v))
			os.MkdirAll(c+"/ov", 0o755)
			os.WriteFile(c+"/ov/blocked-destinations.yaml", b, 0o644)
			x.SandboxOverlay = c + "/ov"
		}
	}
	var errb strings.Builder
	ad, err := agents.Domains(agent, "https://llm.example.org/v1")
	if err != nil {
		errb.WriteString(err.Error() + "\n") // the bash prints it from the process substitution and goes on
	}
	var out strings.Builder
	for _, d := range Build(x, ad, tier.Domains(tierV), extras) {
		out.WriteString(d + "\n")
	}
	return fmt.Sprintf("%s\t0\t%s\t%s", id, enc(out.String()), enc(strings.ReplaceAll(errb.String(), c, "<C>")))
}

func TestAllowlistGolden(t *testing.T) {
	cases := rows(t, "cases.tsv", 5)
	golden := rows(t, "golden-allowlist.tsv", 4)
	if len(cases) != len(golden) {
		t.Fatalf("%d cases but %d golden lines: regenerate the golden file", len(cases), len(golden))
	}
	dir := t.TempDir()
	var bad []string
	for i, row := range cases {
		want := strings.Join(golden[i], "\t")
		if got := runCase(t, dir, row); got != want {
			g, w := strings.Split(got, "\t"), golden[i]
			bad = append(bad, fmt.Sprintf("%s agent=%s tier=%s layout=%s extras=%q\n    oracle: rc=%s out=%q err=%q\n    port:   rc=%s out=%q err=%q",
				row[0], row[1], row[2], row[3], dec(t, row[4]), w[1], dec(t, w[2]), dec(t, w[3]), g[1], dec(t, g[2]), dec(t, g[3])))
		}
	}
	t.Logf("allowlist: %d cases, %d divergences", len(cases), len(bad))
	if len(bad) > 0 {
		n := len(bad)
		if n > 10 {
			bad = bad[:10]
		}
		t.Errorf("%d divergence(s) from the oracle, first %d:\n  %s", n, len(bad), strings.Join(bad, "\n  "))
	}
}

func TestAllowlistLiveOracle(t *testing.T) {
	if os.Getenv("SBX_ORACLE") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI is set but SBX_ORACLE is not: the live oracle must run in CI (no silent skips)")
		}
		t.Skip("set SBX_ORACLE=1 on Linux to run the bash oracle live")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("the oracle must run on Linux")
	}
	cmd := exec.Command(filepath.Join(base, "oracle.sh"))
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(base, "golden-allowlist.tsv"))
	if string(b) != string(out) {
		t.Error("golden-allowlist.tsv differs from the live oracle: regenerate it")
	}
}
