package onboard

import (
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
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

// buildTree materializes a tree spec (see oracle.sh) under home.
func buildTree(t *testing.T, home, spec string) {
	for _, line := range strings.Split(spec, "\n") {
		w := strings.Fields(line)
		if len(w) == 0 {
			continue
		}
		k, p := dec64(t, w[0]), dec64(t, w[1])
		full := home + "/" + p
		parent := full[:strings.LastIndex(full, "/")]
		switch k {
		case "f":
			os.MkdirAll(parent, 0o755)
			os.WriteFile(full, []byte(dec64(t, w[2])), 0o666)
		case "d":
			os.MkdirAll(full, 0o755)
		case "l":
			os.MkdirAll(parent, 0o755)
			os.Symlink(dec64(t, w[2]), full)
		}
	}
}

// listing is the oracle's tree listing of c.
func listing(c string) string {
	var paths []string
	filepath.WalkDir(c, func(p string, d fs.DirEntry, err error) error {
		if p != c && err == nil {
			paths = append(paths, "./"+strings.TrimPrefix(p, c+"/"))
		}
		return nil
	})
	sort.Strings(paths)
	var b strings.Builder
	for _, rel := range paths {
		p := filepath.Join(c, rel)
		st, _ := os.Lstat(p)
		switch {
		case st.Mode()&os.ModeSymlink != 0:
			t, _ := os.Readlink(p)
			fmt.Fprintf(&b, "l %s -> %s\n", rel, t)
		case st.IsDir():
			fmt.Fprintf(&b, "d %s %o\n", rel, st.Mode().Perm())
		default:
			data, _ := os.ReadFile(p)
			fmt.Fprintf(&b, "f %s %o %s\n", rel, st.Mode().Perm(), enc64(string(data)))
		}
	}
	return b.String()
}

func runCase(t *testing.T, dir string, row []string) string {
	t.Helper()
	id := row[0]
	spec, op, flags, envs := dec64(t, row[1]), dec64(t, row[2]), dec64(t, row[3]), dec64(t, row[4])
	c := filepath.Join(dir, id)
	home := c + "/home"
	os.MkdirAll(home, 0o755)
	defer os.RemoveAll(c)
	buildTree(t, home, spec)
	env := map[string]string{}
	for _, l := range strings.Split(envs, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			env[k] = v
		}
	}
	dry, force, _ := strings.Cut(flags, ",")
	x := Ctx{Home: home, AgentHomeBase: home + "/.sandbox/agent-home", DryRun: dry == "true", Force: force == "true"}
	rc := 0
	var o Out
	switch op {
	case "warnenv":
		var n int
		o.Stderr, n = WarnForbiddenEnv(func(k string) string { return env[k] })
		o.Stdout = []string{fmt.Sprint(n)}
	case "starter":
		x.WriteStarterUserConfig(&o)
	default:
		var ok bool
		if o, ok = x.Agent(op); !ok {
			rc = 1
		}
	}
	cl := func(s string) string { return enc64(strings.ReplaceAll(s, c, "<C>")) }
	return fmt.Sprintf("%s\t%d\t%s\t%s\t%s", id, rc, cl(lines(o.Stdout)), cl(lines(o.Stderr)), enc64(listing(c)))
}

func TestOnboardGolden(t *testing.T) {
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
	cases, golden := read("cases.tsv", 5), read("golden-onboard.tsv", 5)
	if len(cases) != len(golden) {
		t.Fatalf("%d cases but %d golden lines: regenerate the golden file", len(cases), len(golden))
	}
	dir := t.TempDir()
	var bad []string
	for i, row := range cases {
		want := strings.Join(golden[i], "\t")
		if got := runCase(t, dir, row); got != want {
			w, g := strings.Split(want, "\t"), strings.Split(got, "\t")
			bad = append(bad, fmt.Sprintf("%s op=%q flags=%q\n    oracle: rc=%s out=%q err=%q\n%s\n    port:   rc=%s out=%q err=%q\n%s",
				row[0], dec64(t, row[2]), dec64(t, row[3]), w[1], dec64(t, w[2]), dec64(t, w[3]), dec64(t, w[4]),
				g[1], dec64(t, g[2]), dec64(t, g[3]), dec64(t, g[4])))
		}
	}
	t.Logf("lib/onboard.sh: %d cases, %d divergences", len(cases), len(bad))
	if len(bad) > 0 {
		n := len(bad)
		if n > 3 {
			bad = bad[:3]
		}
		t.Errorf("%d divergence(s) from the oracle, first %d:\n  %s", n, len(bad), strings.Join(bad, "\n  "))
	}
}

func TestOnboardLiveOracle(t *testing.T) {
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
	b, _ := os.ReadFile(filepath.Join("testdata", "golden-onboard.tsv"))
	if string(b) != string(out) {
		t.Error("golden-onboard.tsv differs from the live oracle: regenerate it")
	}
}
