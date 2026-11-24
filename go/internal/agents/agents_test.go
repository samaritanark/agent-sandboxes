package agents

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

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

func lines(s []string) string {
	var b strings.Builder
	for _, l := range s {
		b.WriteString(l + "\n")
	}
	return b.String()
}

func runCase(t *testing.T, row []string) string {
	op, agent, args, envs := dec64(t, row[1]), dec64(t, row[2]), dec64(t, row[3]), dec64(t, row[4])
	environ := []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	if envs != "" {
		environ = append(environ, strings.Split(envs, "\x1e")...)
	}
	base := ""
	for _, e := range environ {
		if v, ok := strings.CutPrefix(e, "OPENCODE_BASE_URL="); ok {
			base = v
		}
	}
	rc, out, errOut := 0, "", ""
	fail := func(err error) {
		if err != nil {
			rc, errOut = 1, err.Error()+"\n"
		}
	}
	switch op {
	case "validate":
		fail(Validate(agent))
	case "domains":
		d, err := Domains(agent, base)
		out = lines(d)
		fail(err)
	case "endpoint":
		if agent == "opencode" && base != "" {
			out = InferenceEndpoint(agent, base) + "\n" // echo "${host}", even when empty
		}
	case "flags":
		out = fmt.Sprintf("[%s][%s][%s]\n", SessionIDFlag(agent), ResumeFlag(agent), SandboxFlags(agent))
	case "mcp":
		s := 1
		if SupportsMCP(agent) {
			s = 0
		}
		out = fmt.Sprintf("supports=%d\n", s) + lines(MCPLaunchArgs(agent))
	case "render":
		var recs []string
		if args != "" {
			recs = strings.Split(args, "\n")
		}
		var err error
		out, err = RenderMCPConfig(agent, recs)
		fail(err)
	case "cred":
		out = CredentialType(agent) + "\n"
	case "envcheck":
		e, o := CheckHostEnv(agent, environ)
		out, errOut = lines(o), lines(e)
	default:
		t.Fatalf("unknown op %q", op)
	}
	return fmt.Sprintf("%s\t%d\t%s\t%s", row[0], rc, enc64(out), enc64(errOut))
}

func TestAgentsGolden(t *testing.T) {
	read := func(name string, n int) [][]string {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		var rows [][]string
		for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
			p := strings.Split(l, "\t")
			if len(p) != n {
				t.Fatalf("%s: malformed row %q", name, l)
			}
			rows = append(rows, p)
		}
		return rows
	}
	cases, golden := read("cases.tsv", 5), read("golden-agents.tsv", 4)
	if len(cases) != len(golden) {
		t.Fatalf("%d cases but %d golden lines: regenerate the golden file", len(cases), len(golden))
	}
	var bad []string
	for i, row := range cases {
		want := strings.Join(golden[i], "\t")
		if got := runCase(t, row); got != want {
			w, g := strings.Split(want, "\t"), strings.Split(got, "\t")
			bad = append(bad, fmt.Sprintf("%s %s %q args=%q env=%q\n    oracle: rc=%s out=%q err=%q\n    port:   rc=%s out=%q err=%q",
				row[0], dec64(t, row[1]), dec64(t, row[2]), dec64(t, row[3]), dec64(t, row[4]),
				w[1], dec64(t, w[2]), dec64(t, w[3]), g[1], dec64(t, g[2]), dec64(t, g[3])))
		}
	}
	t.Logf("lib/agents.sh: %d cases, %d divergences", len(cases), len(bad))
	if len(bad) > 0 {
		n := len(bad)
		if n > 10 {
			bad = bad[:10]
		}
		t.Errorf("%d divergence(s) from the oracle, first %d:\n  %s", n, len(bad), strings.Join(bad, "\n  "))
	}
}

func TestAgentsLiveOracle(t *testing.T) {
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
	b, _ := os.ReadFile(filepath.Join("testdata", "golden-agents.tsv"))
	if string(b) != string(out) {
		t.Error("golden-agents.tsv differs from the live oracle: regenerate it")
	}
}
