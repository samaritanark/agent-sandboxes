package gate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

var maskedBase = filepath.Join("testdata", "masked")

// maskedRepos copies every config into <tmp>/<name>/.sandbox/config.yaml (the layout the bash uses).
func maskedRepos(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	cfgs, _ := filepath.Glob(filepath.Join(maskedBase, "cfgs", "*.yaml"))
	if len(cfgs) == 0 {
		t.Fatal("no configs: generate the corpus (see go/README.md)")
	}
	for _, f := range cfgs {
		n := strings.TrimSuffix(filepath.Base(f), ".yaml")
		if err := os.MkdirAll(filepath.Join(tmp, n, ".sandbox"), 0o755); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(f)
		if err := os.WriteFile(filepath.Join(tmp, n, ".sandbox", "config.yaml"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return tmp
}

func TestIsPathMaskedBuiltins(t *testing.T) {
	repo := t.TempDir() // no config
	yes := []string{".env", ".env.local", ".npmrc", "clouds.yaml", "kubeconfig", ".kube", ".kube/config", ".kube/a/b", "x-openrc.sh", "-openrc.sh"}
	no := []string{"", "a/.env", ".envx", ".kubex", "a/x-openrc.sh", "x-openrc.shx", "kubeconfig/x", ".kube2/x"}
	for _, p := range yes {
		if !IsPathMasked(repo, p) {
			t.Errorf("%q should be masked", p)
		}
	}
	for _, p := range no {
		if IsPathMasked(repo, p) {
			t.Errorf("%q should not be masked", p)
		}
	}
}

func TestExtractYAMLListQuirks(t *testing.T) {
	f := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(f, []byte("masked_paths:\n- a.txt # c\n-n\n  -n\n- \"b c/\"\nnext:\n  - z\n"), 0o644)
	got := ExtractYAMLList(f, "masked_paths")
	if fmt.Sprint(got) != "[a.txt n b c/]" {
		t.Fatalf("got %q", got)
	}
	if ExtractYAMLList(filepath.Join(t.TempDir(), "nope"), "masked_paths") != nil {
		t.Fatal("missing file must yield no items")
	}
}

func TestMaskedGolden(t *testing.T) {
	repos := maskedRepos(t)
	rows := readTSV(t, filepath.Join(maskedBase, "golden-masked.tsv"), 3)
	var bad []string
	for _, r := range rows {
		got := 1
		if IsPathMasked(filepath.Join(repos, r[0]), r[1]) {
			got = 0
		}
		if want, _ := strconv.Atoi(r[2]); got != want {
			bad = append(bad, fmt.Sprintf("cfg=%s path=%q oracle=%d port=%d", r[0], r[1], want, got))
		}
	}
	t.Logf("is_path_masked: %d cases, %d divergences", len(rows), len(bad))
	reportBad(t, bad)
}

func TestListsGolden(t *testing.T) {
	repos := maskedRepos(t)
	want := map[string][]string{}
	for _, r := range readTSV(t, filepath.Join(maskedBase, "golden-lists.tsv"), 2) {
		want[r[0]] = append(want[r[0]], r[1])
	}
	cfgs, _ := filepath.Glob(filepath.Join(maskedBase, "cfgs", "*.yaml"))
	var bad []string
	for _, f := range cfgs {
		n := strings.TrimSuffix(filepath.Base(f), ".yaml")
		got := ExtractYAMLList(filepath.Join(repos, n, ".sandbox", "config.yaml"), "masked_paths")
		if fmt.Sprintf("%q", got) != fmt.Sprintf("%q", orEmpty(want[n])) {
			bad = append(bad, fmt.Sprintf("cfg=%s oracle=%q port=%q", n, want[n], got))
		}
	}
	t.Logf("extract_yaml_list_from_file: %d configs, %d divergences", len(cfgs), len(bad))
	reportBad(t, bad)
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func TestMaskedLiveOracle(t *testing.T) {
	requireLiveOracle(t)
	root, _ := filepath.Abs(filepath.Join("..", "..", ".."))
	for _, mode := range []struct{ name, golden string }{{"masked", "golden-masked.tsv"}, {"lists", "golden-lists.tsv"}} {
		cmd := exec.Command(filepath.Join(maskedBase, "oracle.sh"), mode.name)
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("oracle %s: %v (root %s)", mode.name, err, root)
		}
		b, _ := os.ReadFile(filepath.Join(maskedBase, mode.golden))
		if string(b) != string(out) {
			t.Errorf("%s: golden file differs from the live oracle: regenerate it", mode.name)
		}
	}
}

// ---- shared helpers for the differential tests ----

func readTSV(t *testing.T, path string, n int) [][]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (generate the golden files; see go/README.md)", err)
	}
	var rows [][]string
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if l == "" {
			continue
		}
		p := strings.SplitN(l, "\t", n)
		if len(p) != n {
			t.Fatalf("%s: malformed row %q", path, l)
		}
		rows = append(rows, p)
	}
	return rows
}

func reportBad(t *testing.T, bad []string) {
	t.Helper()
	if len(bad) == 0 {
		return
	}
	n := len(bad)
	if n > 15 {
		bad = bad[:15]
	}
	t.Errorf("%d divergence(s) from the oracle, first %d:\n  %s", n, len(bad), strings.Join(bad, "\n  "))
}

func requireLiveOracle(t *testing.T) {
	t.Helper()
	if os.Getenv("SBX_ORACLE") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI is set but SBX_ORACLE is not: the live oracle must run in CI (no silent skips)")
		}
		t.Skip("set SBX_ORACLE=1 on Linux to run the bash oracle live")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("the oracle must run on Linux")
	}
}
