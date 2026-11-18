package gate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var scanBase = filepath.Join("testdata", "scan")

// scanBlocks runs every case through the Go port and returns the golden-format text.
func scanBlocks(t *testing.T) string {
	t.Helper()
	abs, _ := filepath.Abs(scanBase)
	// EvalSymlinks: on macOS /var is a symlink and the port resolves the repo path as realpath does.
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	fx := filepath.Join(tmp, "fx")
	if out, err := exec.Command(filepath.Join(abs, "setup.sh"), fx).CombinedOutput(); err != nil {
		t.Fatalf("setup.sh: %v\n%s", err, out)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	t.Setenv("PATH", filepath.Join(abs, "stub")+":"+os.Getenv("PATH"))
	t.Setenv("STUB_ROOT", fx)
	rows := readTSV(t, filepath.Join(scanBase, "cases.tsv"), 6)
	var sb strings.Builder
	for _, r := range rows {
		id, repo, ov, uc, acc, scn := r[0], r[1], r[2], r[3], r[4], r[5]
		e := ScanEnv{Home: filepath.Join(fx, "home"), TmpDir: filepath.Join(fx, "tmp"), CacheDir: filepath.Join(fx, "cache"),
			UserConfig: filepath.Join(fx, "uc", "none.yaml")}
		if uc != "-" {
			e.UserConfig = filepath.Join(fx, "uc", uc+".yaml")
		}
		if ov != "-" {
			e.SandboxOverlay = filepath.Join(fx, "ov", ov)
		}
		a := ""
		if acc != "-" {
			a = filepath.Join(fx, "acc", acc)
		}
		logf := filepath.Join(fx, "log", id)
		os.WriteFile(logf, nil, 0o644)
		t.Setenv("STUB_LOG", logf)
		t.Setenv("STUB_SCEN", filepath.Join(abs, "scen", scn))
		lines := ScanRepoSecrets(e, filepath.Join(fx, repo), a, nil)
		fmt.Fprintf(&sb, "### %s\n", id)
		for _, l := range lines {
			sb.WriteString(l + "\n")
		}
		sb.WriteString("--- stub\n")
		b, _ := os.ReadFile(logf)
		sb.Write(b)
	}
	return strings.ReplaceAll(sb.String(), fx, "<T>")
}

func TestScanGolden(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join(scanBase, "golden-scan.txt"))
	if err != nil {
		t.Fatalf("%v (generate the golden file; see go/README.md)", err)
	}
	got := scanBlocks(t)
	split := func(s string) map[string]string {
		m := map[string]string{}
		for _, blk := range strings.Split(s, "### ")[1:] {
			i := strings.IndexByte(blk, '\n')
			m[blk[:i]] = blk[i+1:]
		}
		return m
	}
	want, have := split(string(golden)), split(got)
	var bad []string
	for id, w := range want {
		if have[id] != w {
			bad = append(bad, fmt.Sprintf("%s\n--- oracle\n%s--- port\n%s", id, w, have[id]))
		}
	}
	t.Logf("scan_repo_secrets: %d cases, %d divergences", len(want), len(bad))
	if len(have) != len(want) {
		t.Errorf("case count: oracle %d, port %d", len(want), len(have))
	}
	if len(bad) > 0 {
		n := len(bad)
		if n > 3 {
			bad = bad[:3]
		}
		t.Errorf("%d divergence(s), first %d:\n%s", n, len(bad), strings.Join(bad, "\n=====\n"))
	}
}

func TestScanLiveOracle(t *testing.T) {
	requireLiveOracle(t)
	cmd := exec.Command(filepath.Join(scanBase, "oracle.sh"))
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(scanBase, "golden-scan.txt"))
	if string(b) != string(out) {
		t.Error("golden-scan.txt differs from the live oracle: regenerate it")
	}
}

func TestBashGlob(t *testing.T) {
	yes := [][2]string{{"*.egg-info", "pkg.egg-info"}, {"*", ""}, {"a?c", "abc"}, {"[ab]x", "bx"}, {"[!a]x", "bx"}, {"[^a]x", "bx"}, {"[a-c]", "b"}, {"a\\*", "a*"}, {"[", "["}, {"[]a]", "]"}}
	no := [][2]string{{"*.egg-info", "egg-info"}, {"a?c", "ac"}, {"[ab]x", "cx"}, {"[!a]x", "ax"}, {"[a-c]", "d"}, {"a\\*", "ab"}, {"vendor", "vendor2"}}
	for _, c := range yes {
		if !bashGlob(c[0], c[1]) {
			t.Errorf("glob %q should match %q", c[0], c[1])
		}
	}
	for _, c := range no {
		if bashGlob(c[0], c[1]) {
			t.Errorf("glob %q should not match %q", c[0], c[1])
		}
	}
}
