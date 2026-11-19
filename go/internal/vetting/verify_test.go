package vetting

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var verifyBase = filepath.Join("testdata", "verify")

func verifyOutput(t *testing.T) string {
	t.Helper()
	abs, _ := filepath.Abs(verifyBase)
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	fx := filepath.Join(tmp, "fx")
	if out, err := exec.Command(filepath.Join(abs, "setup.sh"), fx).CombinedOutput(); err != nil {
		t.Fatalf("setup.sh: %v\n%s", err, out)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	var sb strings.Builder
	for _, r := range tsvRows(t, filepath.Join(verifyBase, "cases.tsv")) {
		id, repo, uc, ov, home := r[0], r[1], r[2], r[3], r[4]
		os.RemoveAll(filepath.Join(fx, "markers"))
		os.MkdirAll(filepath.Join(fx, "markers"), 0o755)
		c := Ctx{Now: func() int64 { return 0 }, TagPrefix: "agent-vetted/"}
		c.Home = filepath.Join(fx, "home-"+home)
		c.UserConfig = filepath.Join(fx, uc+".yaml")
		if ov != "-" {
			c.SandboxOverlay = filepath.Join(fx, "ov", ov)
		}
		c.TrustRootDefault = c.Home + "/.sandbox/vetting/allowed_signers"
		var line string
		if strings.HasPrefix(repo, "REL:") {
			cwd, _ := os.Getwd()
			os.Chdir(fx)
			line = c.StatusRepo(strings.TrimPrefix(repo, "REL:"))
			os.Chdir(cwd)
		} else {
			line = c.StatusRepo(filepath.Join(fx, repo))
		}
		ents, _ := os.ReadDir(filepath.Join(fx, "markers"))
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		sort.Strings(names)
		m := strings.Join(names, " ")
		if m != "" {
			m += " "
		}
		fmt.Fprintf(&sb, "### %s\n%s\nmarkers=%s\n", id, line, m)
	}
	return strings.ReplaceAll(sb.String(), fx, "<T>")
}

func TestVerifyGolden(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join(verifyBase, "golden-verify.txt"))
	if err != nil {
		t.Fatalf("%v (generate the golden file; see go/README.md)", err)
	}
	split := func(s string) map[string]string {
		m := map[string]string{}
		for _, blk := range strings.Split(s, "### ")[1:] {
			i := strings.IndexByte(blk, '\n')
			m[blk[:i]] = blk[i+1:]
		}
		return m
	}
	want, have := split(string(golden)), split(verifyOutput(t))
	var bad []string
	for id, w := range want {
		if have[id] != w {
			bad = append(bad, fmt.Sprintf("%s\n--- oracle\n%s--- port\n%s", id, w, have[id]))
		}
	}
	t.Logf("vetting_status_repo: %d cases, %d divergences", len(want), len(bad))
	if len(have) != len(want) {
		t.Errorf("case count: oracle %d, port %d", len(want), len(have))
	}
	if n := len(bad); n > 0 {
		if n > 4 {
			bad = bad[:4]
		}
		t.Errorf("%d divergence(s), first %d:\n%s", n, len(bad), strings.Join(bad, "\n=====\n"))
	}
}

func TestVerifyLiveOracle(t *testing.T) {
	if os.Getenv("SBX_ORACLE") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI is set but SBX_ORACLE is not: the live oracle must run in CI (no silent skips)")
		}
		t.Skip("set SBX_ORACLE=1 on Linux to run the bash oracle live")
	}
	cmd := exec.Command(filepath.Join(verifyBase, "oracle.sh"))
	cmd.Env = append(os.Environ(), "LC_ALL=C.UTF-8")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(verifyBase, "golden-verify.txt"))
	if string(b) != string(out) {
		t.Error("golden-verify.txt differs from the live oracle: regenerate it")
	}
}
