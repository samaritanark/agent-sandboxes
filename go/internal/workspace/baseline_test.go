package workspace

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
)

var baselineBase = filepath.Join("testdata", "baseline")

func b64(s string) string { return "=" + base64.StdEncoding.EncodeToString([]byte(s)) }

func unb64(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "="))
	if err != nil {
		t.Fatalf("bad base64 %q", s)
	}
	return string(b)
}

func tsvRows(t *testing.T, name string, n int) [][]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(baselineBase, name))
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

// steps applies tree steps (one per line, base64 fields) as oracle.sh does.
func steps(t *testing.T, home, log, spec string) {
	for _, line := range strings.Split(spec, "\n") {
		if line == "" {
			continue
		}
		w := strings.Split(line, " ")
		k, p := unb64(t, w[0]), unb64(t, w[1])
		var arg string
		if len(w) > 2 {
			arg = unb64(t, w[2])
		}
		if strings.HasPrefix(p, "LOG/") {
			p = log + "/" + strings.TrimPrefix(p, "LOG/")
		} else {
			p = home + "/" + p
		}
		switch k {
		case "f":
			os.MkdirAll(filepath.Dir(p), 0o755)
			os.WriteFile(p, []byte(arg), 0o644)
		case "d":
			os.MkdirAll(p, 0o755)
		case "l":
			os.MkdirAll(filepath.Dir(p), 0o755)
			os.Symlink(arg, p)
		case "r":
			os.RemoveAll(p)
		case "u":
			os.Chmod(p, 0)
		case "p":
			os.MkdirAll(filepath.Dir(p), 0o755)
			syscall.Mkfifo(p, 0o644)
		}
	}
}

func runBaselineCase(t *testing.T, dir string, row []string) string {
	id, prune := row[0], row[1]
	c := filepath.Join(dir, id)
	home, log, root := c+"/home", c+"/log", c+"/root"
	for _, d := range []string{home, log, root + "/config"} {
		os.MkdirAll(d, 0o755)
	}
	defer func() {
		filepath.Walk(c, func(p string, _ os.FileInfo, _ error) error { os.Chmod(p, 0o755); return nil })
		os.RemoveAll(c)
	}()
	switch prune {
	case "real":
		root, _ = filepath.Abs(filepath.Join("..", "..", ".."))
	case "none":
	default:
		b, _ := os.ReadFile(filepath.Join(baselineBase, "fx", prune))
		os.WriteFile(root+"/config/workspace-audit.yaml", b, 0o644)
	}
	var repos []string
	for _, r := range strings.Split(unb64(t, row[2]), "\x00") {
		repos = append(repos, home+"/"+r)
	}
	steps(t, home, log, unb64(t, row[3]))
	pd := PruneDirs(root)
	var out []string
	out = append(out, CaptureBaseline(log, repos, pd))
	steps(t, home, log, unb64(t, row[4]))
	out = append(out, CaptureDiff(log, repos, pd)...)
	norm := strings.NewReplacer(home, "<HOME>", log, "<LOG>")
	file := func(p string) string {
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() {
			return "-"
		}
		b, _ := os.ReadFile(p)
		return b64(norm.Replace(string(b)))
	}
	left := 0
	if _, err := os.Lstat(log + "/current.sha256"); err == nil {
		left = 1
	}
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%d", id, b64(norm.Replace(strings.Join(out, "\n")+"\n")),
		file(log+"/baseline.sha256"), file(log+"/files.log"), left)
}

func TestBaselineGolden(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	cases := tsvRows(t, "cases.tsv", 5)
	golden := tsvRows(t, "golden-baseline.tsv", 5)
	if len(cases) != len(golden) {
		t.Fatalf("%d cases but %d golden lines: regenerate the golden file", len(cases), len(golden))
	}
	dir := t.TempDir()
	var bad []string
	for i, row := range cases {
		want := strings.Join(golden[i], "\t")
		if got := runBaselineCase(t, dir, row); got != want {
			g, w := strings.Split(got, "\t"), golden[i]
			show := func(f []string) string {
				d := func(s string) string {
					if s == "-" {
						return "-"
					}
					return fmt.Sprintf("%q", unb64(t, s))
				}
				return fmt.Sprintf("out=%s\n      baseline=%s\n      files.log=%s left=%s", d(f[1]), d(f[2]), d(f[3]), f[4])
			}
			bad = append(bad, fmt.Sprintf("%s prune=%s repos=%q\n    oracle: %s\n    port:   %s", row[0], row[1], unb64(t, row[2]), show(w), show(g)))
		}
	}
	t.Logf("workspace baseline and diff: %d cases, %d divergences", len(cases), len(bad))
	if len(bad) > 0 {
		n := len(bad)
		if n > 6 {
			bad = bad[:6]
		}
		t.Errorf("%d divergence(s) from the oracle, first %d:\n  %s", n, len(bad), strings.Join(bad, "\n  "))
	}
}

func TestBaselineLiveOracle(t *testing.T) {
	if os.Getenv("SBX_ORACLE") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI is set but SBX_ORACLE is not: the live oracle must run in CI (no silent skips)")
		}
		t.Skip("set SBX_ORACLE=1 on Linux to run the bash oracle live")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("the oracle must run on Linux")
	}
	cmd := exec.Command(filepath.Join(baselineBase, "oracle.sh"))
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(baselineBase, "golden-baseline.tsv"))
	if string(b) != string(out) {
		t.Error("golden-baseline.tsv differs from the live oracle: regenerate it")
	}
}
