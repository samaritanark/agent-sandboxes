package checks

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

// The differential tests compare against the bash oracle, so they run with every fix off; each fix
// has its own test (fixes_test.go) that turns it on.
func TestMain(m *testing.M) {
	deviation.SetLegacy(true)
	os.Exit(m.Run())
}

var base = "testdata"

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

func lines(s []string) string {
	var b strings.Builder
	for _, l := range s {
		b.WriteString(l + "\n")
	}
	return b.String()
}

func rcOf(ok bool) int {
	if ok {
		return 0
	}
	return 1
}

func runCase(t *testing.T, dir string, row []string) string {
	t.Helper()
	id, op, layout := row[0], row[1], row[2]
	a1, a2 := dec64(t, row[3]), dec64(t, row[4])
	c := filepath.Join(dir, id)
	os.MkdirAll(c, 0o755)
	defer os.RemoveAll(c)
	fx, _ := filepath.Abs(filepath.Join(base, "fx"))
	x := Ctx{Env: config.Env{Home: c, UserConfig: c + "/none.yaml"}, OrgFile: c + "/missing.yaml"}
	if layout != "-" {
		for _, p := range strings.Split(layout, ",") {
			k, v, ok := strings.Cut(p, "=")
			if !ok || v == "-" {
				continue
			}
			cp := func(dst string) {
				b, _ := os.ReadFile(filepath.Join(fx, v))
				os.MkdirAll(c+"/ov", 0o755)
				os.WriteFile(dst, b, 0o644)
				x.SandboxOverlay = c + "/ov"
			}
			switch k {
			case "o":
				x.OrgFile = filepath.Join(fx, v)
			case "u":
				x.UserConfig = filepath.Join(fx, v)
			case "b":
				cp(c + "/ov/blocked-destinations.yaml")
			case "c":
				cp(c + "/ov/config.yaml")
			}
		}
	}
	rc, out, errOut := 0, "", ""
	refusal := func(w []string, err error) {
		errOut = lines(w)
		if err != nil {
			rc = 1
			errOut += err.Error() + "\n"
		}
	}
	switch op {
	case "norm":
		out = NormalizeDomain(a1) + "\n"
	case "match":
		rc = rcOf(DomainMatchesBlockPattern(a1, a2))
	case "cdnb":
		refusal(x.CheckDomainNotBlocked(a1))
	case "dib":
		rc = rcOf(x.DomainIsBlocked(a1))
	case "gbc":
		out = lines(x.BlockedCIDRs())
	case "vcidr":
		rc = rcOf(ValidateCIDR(a1))
	case "cbcv":
		refusal(nil, x.CheckBlockedCIDRsValid())
	case "ip4":
		rc = rcOf(IsIPv4Literal(a1))
	case "ip2int":
		v, ok := IPv4ToInt(a1)
		if rc = rcOf(ok); ok {
			out = fmt.Sprintf("%d\n", v)
		}
	case "iic":
		rc = rcOf(IPInCIDR(a1, a2))
	case "cinb":
		refusal(x.CheckIPNotInBlockedCIDRs(a1))
	case "mps":
		rc = rcOf(IsMultilabelPublicSuffix(a1))
	case "apex":
		rc = rcOf(ApexIsRegistrableDomain(a1))
	case "wtb":
		rc = rcOf(EgressWildcardTooBroad(a1))
	case "cetnb":
		refusal(x.CheckEgressTargetNotBlocked(a1))
	case "iet":
		rc = rcOf(x.InferenceEndpointIsTrusted(a1))
	default:
		t.Fatalf("%s: unknown op %q", id, op)
	}
	clean := func(s string) string {
		return enc64(strings.ReplaceAll(strings.ReplaceAll(s, fx, "<FX>"), c, "<C>"))
	}
	return fmt.Sprintf("%s\t%d\t%s\t%s", id, rc, clean(out), clean(errOut))
}

func TestChecksGolden(t *testing.T) {
	cases := readRows(t, filepath.Join(base, "cases.tsv"), 5)
	golden := readRows(t, filepath.Join(base, "golden-checks.tsv"), 4)
	if len(cases) != len(golden) {
		t.Fatalf("%d cases but %d golden lines: regenerate the golden file", len(cases), len(golden))
	}
	dir := t.TempDir()
	var bad []string
	for i, row := range cases {
		want := strings.Join(golden[i], "\t")
		if got := runCase(t, dir, row); got != want {
			w, g := strings.Split(want, "\t"), strings.Split(got, "\t")
			bad = append(bad, fmt.Sprintf("%s %s [%s] %q %q\n    oracle: rc=%s out=%q err=%q\n    port:   rc=%s out=%q err=%q",
				row[0], row[1], row[2], dec64(t, row[3]), dec64(t, row[4]),
				w[1], dec64(t, w[2]), dec64(t, w[3]), g[1], dec64(t, g[2]), dec64(t, g[3])))
		}
	}
	t.Logf("lib/checks.sh: %d cases, %d divergences", len(cases), len(bad))
	if len(bad) > 0 {
		n := len(bad)
		if n > 15 {
			bad = bad[:15]
		}
		t.Errorf("%d divergence(s) from the oracle, first %d:\n  %s", n, len(bad), strings.Join(bad, "\n  "))
	}
}

func TestChecksLiveOracle(t *testing.T) {
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
	b, _ := os.ReadFile(filepath.Join(base, "golden-checks.tsv"))
	if string(b) != string(out) {
		t.Error("golden-checks.tsv differs from the live oracle: regenerate it")
	}
}
