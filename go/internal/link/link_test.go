package link

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
	"time"

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

func lines(s []string) string {
	var b strings.Builder
	for _, l := range s {
		b.WriteString(l + "\n")
	}
	return b.String()
}

// buildTree materializes an overlay spec (see oracle.sh) under dir.
func buildTree(t *testing.T, dir, spec string) {
	t.Helper()
	os.MkdirAll(dir, 0o755)
	for _, line := range strings.Split(spec, "\n") {
		w := strings.Fields(line)
		if len(w) == 0 {
			continue
		}
		k, p := dec64(t, w[0]), dec64(t, w[1])
		full := dir + "/" + p
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

func runCase(t *testing.T, dir string, row []string) string {
	t.Helper()
	id, op := row[0], row[1]
	a1, a2, a3 := dec64(t, row[2]), dec64(t, row[3]), dec64(t, row[4])
	c := filepath.Join(dir, id)
	home := c + "/home"
	os.MkdirAll(home, 0o755)
	defer os.RemoveAll(c)
	x := Ctx{Env: config.Env{Home: home, UserConfig: home + "/.sandbox/config.yaml"}, OverlaysDir: home + "/.sandbox/overlays"}
	rc, out, errOut := 0, "", ""
	rcOf := func(ok bool) {
		if !ok {
			rc = 1
		}
	}
	writeUC := func() {
		os.MkdirAll(home+"/.sandbox", 0o755)
		if a1 != "\x01" {
			os.WriteFile(x.UserConfig, []byte(a1), 0o666)
		}
	}
	switch op {
	case "name":
		rcOf(IsValidName(a1))
	case "fromurl":
		if n := NameFromURL(a1); n != "" {
			out = n + "\n"
		}
	case "norm":
		out = NormalizePath(a1, a2) + "\n"
	case "sens":
		rcOf(DefaultRepoIsSensitive(a1, a2))
	case "validate":
		buildTree(t, c+"/ov", a1)
		v := x.ValidateShape(c + "/ov")
		rcOf(v.OK)
		errOut = lines(v.Stderr)
	case "wcfg":
		writeUC()
		x.WriteConfig(a2, "u-"+a3, "r-"+a3, "c-"+a3)
	case "ccfg":
		writeUC()
		x.ClearConfig(strings.ReplaceAll(a2, "<HOME>", home))
	case "active":
		writeUC()
		if f, ok := strings.CutPrefix(a2, "file:"); ok {
			os.MkdirAll(filepath.Dir(home+"/"+f), 0o755)
			os.WriteFile(home+"/"+f, nil, 0o666)
		} else if a2 != "" {
			os.MkdirAll(home+"/"+a2, 0o755)
		}
		if d := x.ActiveDir(); d != "" {
			out = d + "\n"
		}
		yes := "no"
		if x.IsActive() {
			yes = "yes"
		}
		out += fmt.Sprintf("active=%s url=%s ref=%s commit=%s\n", yes, x.URL(), x.Ref(), x.Commit())
	case "sync":
		cmd := exec.Command("bash", filepath.Join("testdata", "setup-sync.sh"), a1, c)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: setup-sync %s: %v\n%s", id, a1, err, b)
		}
		git, _ := exec.LookPath("git")
		s := SyncCtx{Ctx: x, NoLinkCheck: a1 == "no-check", FetchTimeout: 10 * time.Second, SandboxVersion: a2, Git: git}
		r := s.SyncOnRun()
		out, errOut = lines(r.Stdout), lines(r.Stderr)
		if r.Die != "" {
			rc, errOut = 1, errOut+"DIE: "+r.Die+"\n"
		}
	default:
		t.Fatalf("%s: unknown op %q", id, op)
	}
	cl := func(s string) string { return enc64(strings.ReplaceAll(s, c, "<C>")) }
	uc := "-"
	if b, err := os.ReadFile(x.UserConfig); err == nil {
		uc = cl(string(b))
	}
	hd := "-"
	if op == "sync" {
		h, _ := exec.Command("git", "-C", home+"/.sandbox/overlays/team", "rev-parse", "HEAD").Output()
		hd = enc64(string(h))
	}
	return fmt.Sprintf("%s\t%d\t%s\t%s\t%s\t%s", id, rc, cl(out), cl(errOut), uc, hd)
}

func TestLinkGolden(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
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
	cases, golden := read("cases.tsv", 5), read("golden-link.tsv", 6)
	if len(cases) != len(golden) {
		t.Fatalf("%d cases but %d golden lines: regenerate the golden file", len(cases), len(golden))
	}
	dir := t.TempDir()
	var bad []string
	for i, row := range cases {
		want := strings.Join(golden[i], "\t")
		if got := runCase(t, dir, row); got != want {
			w, g := strings.Split(want, "\t"), strings.Split(got, "\t")
			df := func(f string) string {
				if f == "-" {
					return "-"
				}
				return dec64(t, f)
			}
			bad = append(bad, fmt.Sprintf("%s %s %q %q %q\n    oracle: rc=%s out=%q err=%q uc=%q head=%q\n    port:   rc=%s out=%q err=%q uc=%q head=%q",
				row[0], row[1], dec64(t, row[2]), dec64(t, row[3]), dec64(t, row[4]),
				w[1], df(w[2]), df(w[3]), df(w[4]), df(w[5]), g[1], df(g[2]), df(g[3]), df(g[4]), df(g[5])))
		}
	}
	t.Logf("lib/link.sh: %d cases, %d divergences", len(cases), len(bad))
	if len(bad) > 0 {
		n := len(bad)
		if n > 10 {
			bad = bad[:10]
		}
		t.Errorf("%d divergence(s) from the oracle, first %d:\n  %s", n, len(bad), strings.Join(bad, "\n  "))
	}
}

func TestLinkLiveOracle(t *testing.T) {
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
	b, _ := os.ReadFile(filepath.Join("testdata", "golden-link.tsv"))
	if string(b) != string(out) {
		t.Error("golden-link.tsv differs from the live oracle: regenerate it")
	}
}
