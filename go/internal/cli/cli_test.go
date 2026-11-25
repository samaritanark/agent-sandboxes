package cli

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func dec64(t *testing.T, f string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(f, "="))
	if err != nil {
		t.Fatalf("bad base64 %q: %v", f, err)
	}
	return string(b)
}

func enc64(s string) string { return "=" + base64.StdEncoding.EncodeToString([]byte(s)) }

// fixtureEnv is the environment the oracle gives bin/sandbox, in its normalized form.
func fixtureEnv(ver string) Env {
	e := Env{Root: "<ROOT>", LogsDir: "<HOME>/logs", Runtime: "<RT>"}
	if ver == "full" {
		e.Version = VersionInfo{"v3.0.0-test", "0123456789ab", "2026-11-24", "2026-11-25", "clean"}
	}
	return e
}

func TestCLIGolden(t *testing.T) {
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
	cases, golden := read("cases.tsv", 3), read("golden-cli.tsv", 4)
	if len(cases) != len(golden) {
		t.Fatalf("%d cases but %d golden lines: regenerate the golden file", len(cases), len(golden))
	}
	var bad []string
	for i, row := range cases {
		var args []string
		if a := dec64(t, row[2]); a != "" {
			args = strings.Split(strings.TrimSuffix(a, "\x00"), "\x00")
		}
		var out, errb bytes.Buffer
		rc := Run(args, fixtureEnv(row[1]), &out, &errb)
		got := fmt.Sprintf("%s\t%d\t%s\t%s", row[0], rc, enc64(out.String()), enc64(errb.String()))
		if want := strings.Join(golden[i], "\t"); got != want {
			w := golden[i]
			bad = append(bad, fmt.Sprintf("%s %s %q\n    oracle: rc=%s out=%q err=%q\n    port:   rc=%d out=%q err=%q",
				row[0], row[1], args, w[1], dec64(t, w[2]), dec64(t, w[3]), rc, out.String(), errb.String()))
		}
	}
	t.Logf("bin/sandbox dispatch, usage, version: %d cases, %d divergences", len(cases), len(bad))
	if len(bad) > 0 {
		n := len(bad)
		if n > 5 {
			bad = bad[:5]
		}
		t.Errorf("%d divergence(s) from the oracle, first %d:\n  %s", n, len(bad), strings.Join(bad, "\n  "))
	}
}

func TestCLILiveOracle(t *testing.T) {
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
	b, _ := os.ReadFile(filepath.Join("testdata", "golden-cli.tsv"))
	if string(b) != string(out) {
		t.Error("golden-cli.tsv differs from the live oracle: regenerate it")
	}
	// The usage texts are captured from bin/sandbox; regenerate them and compare.
	tmp := t.TempDir()
	for _, f := range mustGlob(t, filepath.Join("usage", "*.txt")) {
		b, _ := os.ReadFile(f)
		os.WriteFile(filepath.Join(tmp, filepath.Base(f)), b, 0o644)
	}
	if out, err := exec.Command(filepath.Join("testdata", "gen-usage.sh")).CombinedOutput(); err != nil {
		t.Fatalf("gen-usage: %v\n%s", err, out)
	}
	for _, f := range mustGlob(t, filepath.Join("usage", "*.txt")) {
		now, _ := os.ReadFile(f)
		was, _ := os.ReadFile(filepath.Join(tmp, filepath.Base(f)))
		if !bytes.Equal(now, was) {
			t.Errorf("%s differs from bin/sandbox: commit the regenerated file", f)
		}
	}
}

func mustGlob(t *testing.T, p string) []string {
	m, err := filepath.Glob(p)
	if err != nil || len(m) == 0 {
		t.Fatalf("no files match %s", p)
	}
	return m
}
