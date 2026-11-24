package audit

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

// The differential tests compare against the bash oracle, so they run with every fix off; each fix
// has its own test (fixes_test.go) that turns it on.
func TestMain(m *testing.M) {
	deviation.SetLegacy(true)
	os.Exit(m.Run())
}

const now = "2026-01-02T03:04:05Z" // the oracle's fixed clock

func dec64(t *testing.T, f string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(f, "="))
	if err != nil {
		t.Fatalf("bad base64 %q: %v", f, err)
	}
	return string(b)
}

func enc64(s string) string { return "=" + base64.StdEncoding.EncodeToString([]byte(s)) }

// runSteps replays one case's steps against the port in case directory c, as oracle.sh does.
func runSteps(t *testing.T, c, steps string) (out string) {
	t.Helper()
	L := filepath.Join(c, "logs", "ses-x")
	os.MkdirAll(L, 0o755)
	env := map[string]string{}
	var overrides []Override
	var b strings.Builder
	for _, line := range strings.Split(steps, "\n") {
		var a []string
		for _, w := range strings.Fields(line) {
			a = append(a, dec64(t, w))
		}
		if len(a) == 0 {
			continue
		}
		op, a := a[0], a[1:]
		arg := func(i int) string {
			if i < len(a) {
				return a[i]
			}
			return ""
		}
		switch op {
		case "V":
			env[a[0]] = a[1]
		case "W":
			s := Session{ID: a[0], Agent: a[1], Tier: a[2], User: a[3], Name: a[5], PodName: a[6], StartTime: a[7],
				CredentialType: "cred-" + a[1], Domains: a[8:], Repos: []string{},
				Profile: env["SESSION_PROFILE"], Overlay: env["SESSION_OVERLAY"], KubeAPICIDR: env["SESSION_KUBE_API_CIDR"],
				KubeAPIPort: env["SESSION_KUBE_API_PORT"], KubeAPIContexts: env["SESSION_KUBE_API_CONTEXTS"],
				KubeHostEntity: env["SESSION_KUBE_HOST_ENTITY"], InfraToken: env["SESSION_INFRA_TOKEN"] != "",
				InfraKubeconfig: env["SESSION_INFRA_KUBECONFIG"] != ""}
			switch r := a[4]; {
			case r == "":
			case strings.HasPrefix(r, "["): // the bash's JSON-array form of the repo argument
				v, err := parseOne(r)
				if err != nil {
					t.Fatalf("corpus repo array %q is not JSON", r)
				}
				for _, x := range v.Arr {
					s.Repos = append(s.Repos, x.Str)
				}
			default:
				s.Repos = []string{r}
			}
			line, _ := WriteSessionJSON(L, s) // the oracle runs without errexit: the line prints anyway
			b.WriteString(line + "\n")
		case "O":
			overrides = append(overrides, RecordOverride(a[0], a[1], a[2:]...))
		case "F":
			FlushOverrides(L, overrides, now)
		case "E":
			UpdateEndTime(L, arg(0))
		case "R":
			RecordEndReason(L, arg(0), arg(1))
		case "A":
			RecordAgentSessionID(L, arg(0))
		case "D":
			RecordDependencies(L, arg(0))
		case "d":
			RecordDependenciesDown(L, arg(0))
		case "G":
			LogEvent(L, arg(0), arg(1), now)
		case "X":
			os.WriteFile(filepath.Join(L, "session.json"), []byte(arg(0)), 0o666)
		case "M":
			os.Remove(filepath.Join(L, "session.json"))
		case "K":
			p := filepath.Join(c, "logs", a[0])
			switch a[1] {
			case "dir":
				os.MkdirAll(p, 0o755)
			case "file":
				os.WriteFile(p, nil, 0o666)
			case "link":
				os.Symlink(L, p)
			case "dangling":
				os.Symlink(filepath.Join(c, "nowhere"), p)
			}
		case "S", "N":
			dir := filepath.Join(c, "logs")
			if op == "N" {
				dir = filepath.Join(c, "missing")
			}
			for _, x := range ListSessions(dir) {
				b.WriteString(x + "\n")
			}
			if len(ListSessions(dir)) == 0 {
				b.WriteString("\n") // printf '%s\n' with no arguments prints one empty line
			}
		default:
			t.Fatalf("unknown step %q", op)
		}
	}
	return b.String()
}

func TestAuditGolden(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
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
	cases, golden := read("cases.tsv", 2), read("golden-audit.tsv", 4)
	if len(cases) != len(golden) {
		t.Fatalf("%d cases but %d golden lines: regenerate the golden file", len(cases), len(golden))
	}
	dir := t.TempDir()
	var bad []string
	for i, row := range cases {
		c := filepath.Join(dir, row[0])
		out := strings.ReplaceAll(runSteps(t, c, dec64(t, row[1])), c, "<C>")
		file, mode := "-", "-"
		p := filepath.Join(c, "logs", "ses-x", "session.json")
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			bb, _ := os.ReadFile(p)
			file, mode = enc64(string(bb)), fmt.Sprintf("%o", st.Mode().Perm())
		}
		os.RemoveAll(c)
		got := fmt.Sprintf("%s\t%s\t%s\t%s", row[0], enc64(out), file, mode)
		if want := strings.Join(golden[i], "\t"); got != want {
			w, g := golden[i], strings.Split(got, "\t")
			df := func(f string) string {
				if f == "-" {
					return "-"
				}
				return dec64(t, f)
			}
			bad = append(bad, fmt.Sprintf("%s steps=%q\n    oracle: out=%q mode=%s file=\n%s\n    port:   out=%q mode=%s file=\n%s",
				row[0], dec64(t, row[1]), dec64(t, w[1]), w[3], df(w[2]), dec64(t, g[1]), g[3], df(g[2])))
		}
	}
	t.Logf("lib/audit.sh (session record): %d cases, %d divergences", len(cases), len(bad))
	if len(bad) > 0 {
		n := len(bad)
		if n > 4 {
			bad = bad[:4]
		}
		t.Errorf("%d divergence(s) from the oracle, first %d:\n  %s", n, len(bad), strings.Join(bad, "\n  "))
	}
}

func TestAuditLiveOracle(t *testing.T) {
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
	b, _ := os.ReadFile(filepath.Join("testdata", "golden-audit.tsv"))
	if string(b) != string(out) {
		t.Error("golden-audit.tsv differs from the live oracle: regenerate it")
	}
}
