package config

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

var writeBase = filepath.Join("testdata", "write")

func dec64(t *testing.T, f string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(f, "="))
	if err != nil {
		t.Fatalf("bad base64 %q: %v", f, err)
	}
	return string(b)
}

func enc64(b []byte) string { return "=" + base64.StdEncoding.EncodeToString(b) }

func lines(items []string) string {
	var b strings.Builder
	for _, s := range items {
		b.WriteString(s + "\n")
	}
	return b.String()
}

// runWriteCase builds case row (id, op, fixture, mode, arg1, arg2) under dir exactly as oracle.sh
// does and returns the golden line the oracle would print for it.
func runWriteCase(t *testing.T, dir string, row []string) string {
	t.Helper()
	id, op, fx, mode := row[0], row[1], row[2], row[3]
	a1, a2 := dec64(t, row[4]), dec64(t, row[5])
	c := filepath.Join(dir, id)
	os.MkdirAll(c, 0o755)
	defer os.RemoveAll(c)
	fxPath, _ := filepath.Abs(filepath.Join(writeBase, "fx", fx))
	put := func(p string) {
		if fx == "-" {
			return
		}
		b, err := os.ReadFile(fxPath)
		if err != nil {
			t.Fatal(err)
		}
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, b, 0o644)
		var m uint32
		fmt.Sscanf(mode, "%o", &m)
		os.Chmod(p, os.FileMode(m))
	}
	e := Env{Home: c, UserConfig: c + "/none.yaml"}
	target := "-"
	var out string
	var err error
	switch op {
	case "rmscalar", "rmlist":
		target = c + "/f.yaml"
		put(target)
		if op == "rmscalar" {
			err = RemoveYAMLScalar(target, a1)
		} else {
			err = RemoveYAMLList(target, a1)
		}
	case "addmask":
		target = c + "/r/.sandbox/config.yaml"
		put(target)
		err = AddMaskedPath(target, a1)
	case "addfp":
		target = c + "/ign"
		put(target)
		err = IgnoreFileAddFingerprint(target, a1, a2)
	case "ignfile":
		r := c + "/r"
		os.MkdirAll(r, 0o755)
		for _, ch := range a1 {
			switch ch {
			case 'B':
				put(r + "/.betterleaksignore")
			case 'b':
				os.Mkdir(r+"/.betterleaksignore", 0o755)
			case 'G':
				put(r + "/.gitleaksignore")
			case 'g':
				os.Mkdir(r+"/.gitleaksignore", 0o755)
			}
		}
		out = RepoIgnoreFile(r) + "\n" + lines(LoadRepoIgnoreFingerprints(r))
	case "honor":
		os.MkdirAll(c+"/ov", 0o755)
		put(c + "/ov/config.yaml")
		uc := func(s string) {
			os.WriteFile(c+"/uc.yaml", []byte("overlay: "+s+"\n"), 0o644)
			e.UserConfig = c + "/uc.yaml"
		}
		switch a1 {
		case "env":
			e.SandboxOverlay = c + "/ov"
		case "env-empty", "user":
			uc(c + "/ov")
		case "user-tilde":
			uc("~/ov")
		}
		out = fmt.Sprintf("%t\n", HonorRepoAllowedDomains(e))
	case "envdom":
		if fx != "-" {
			e.UserConfig = fxPath
		}
		e.ExtraAllowedDomains = a1
		cwd := c + "/cwd"
		os.MkdirAll(cwd, 0o755)
		for _, f := range []string{"evil.example.com", "x.example.com", ".hidden.example.com", "a1", "b1", "c1"} {
			os.WriteFile(filepath.Join(cwd, f), nil, 0o644)
		}
		old, _ := os.Getwd()
		os.Chdir(cwd)
		out = lines(UserExtraAllowedDomains(e))
		os.Chdir(old)
	default:
		t.Fatalf("%s: unknown op %q", id, op)
	}
	rc := 0
	if err != nil {
		rc = 1
	}
	out = strings.ReplaceAll(out, c, "<C>")
	file, m := "-", "-"
	if target != "-" && IsFile(target) {
		b, _ := os.ReadFile(target)
		st, _ := os.Stat(target)
		file, m = enc64(b), fmt.Sprintf("%o", st.Mode().Perm())
	}
	return fmt.Sprintf("%s\t%d\t%s\t%s\t%s", id, rc, enc64([]byte(out)), file, m)
}

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

// explain decodes a golden line's base64 fields so a divergence is readable.
func explain(t *testing.T, line string) string {
	p := strings.Split(line, "\t")
	f := p[3]
	if f != "-" {
		f = fmt.Sprintf("%q", dec64(t, f))
	}
	return fmt.Sprintf("rc=%s out=%q file=%s mode=%s", p[1], dec64(t, p[2]), f, p[4])
}

func TestWriteGolden(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	cases := readRows(t, filepath.Join(writeBase, "cases.tsv"), 6)
	golden := readRows(t, filepath.Join(writeBase, "golden-write.tsv"), 5)
	if len(cases) != len(golden) {
		t.Fatalf("%d cases but %d golden lines: regenerate the golden file", len(cases), len(golden))
	}
	dir := t.TempDir()
	var bad []string
	for i, row := range cases {
		want := strings.Join(golden[i], "\t")
		if got := runWriteCase(t, dir, row); got != want {
			bad = append(bad, fmt.Sprintf("%s %s fx=%s arg1=%q arg2=%q\n    oracle: %s\n    port:   %s",
				row[0], row[1], row[2], dec64(t, row[4]), dec64(t, row[5]), explain(t, want), explain(t, got)))
		}
	}
	t.Logf("config writers and readers: %d cases, %d divergences", len(cases), len(bad))
	if len(bad) > 0 {
		n := len(bad)
		if n > 15 {
			bad = bad[:15]
		}
		t.Errorf("%d divergence(s) from the oracle, first %d:\n  %s", n, len(bad), strings.Join(bad, "\n  "))
	}
}

func TestWriteLiveOracle(t *testing.T) {
	if os.Getenv("SBX_ORACLE") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI is set but SBX_ORACLE is not: the live oracle must run in CI (no silent skips)")
		}
		t.Skip("set SBX_ORACLE=1 on Linux to run the bash oracle live")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("the oracle must run on Linux")
	}
	cmd := exec.Command(filepath.Join(writeBase, "oracle.sh"))
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(writeBase, "golden-write.tsv"))
	if string(b) != string(out) {
		t.Error("golden-write.tsv differs from the live oracle: regenerate it")
	}
}
