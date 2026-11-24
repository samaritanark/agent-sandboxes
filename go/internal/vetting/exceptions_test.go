package vetting

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
)

var excBase = filepath.Join("testdata", "exc")

func excOutput(t *testing.T) string {
	t.Helper()
	abs, _ := filepath.Abs(excBase)
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	fx := filepath.Join(tmp, "fx")
	if out, err := exec.Command(filepath.Join(abs, "setup.sh"), fx).CombinedOutput(); err != nil {
		t.Fatalf("setup.sh: %v\n%s", err, out)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	var sb strings.Builder
	for _, r := range tsvRowsN(t, filepath.Join(excBase, "cases.tsv"), 6) {
		kind, id, repo, uc, acc, honor := r[0], r[1], r[2], r[3], r[4], r[5]
		os.RemoveAll(filepath.Join(fx, "markers"))
		os.MkdirAll(filepath.Join(fx, "markers"), 0o755)
		c := Ctx{Now: func() int64 { return 0 }, TagPrefix: "agent-vetted/"}
		c.Home = filepath.Join(fx, "home")
		c.UserConfig = filepath.Join(fx, uc+".yaml")
		c.TrustRootDefault = c.Home + "/.sandbox/vetting/allowed_signers"
		rp := filepath.Join(fx, repo)
		fmt.Fprintf(&sb, "### %s\n", id)
		if kind == "exc" {
			if acc == "EMPTY" {
				acc = ""
			}
			if honor == "EMPTY" {
				honor = ""
			}
			fmt.Fprintf(&sb, "vaf=%s\n", joinBar2(c.VettedAcceptedFingerprints(rp, acc)))
			fmt.Fprintf(&sb, "granted=%s\n", joinBar2(c.RepoGrantedAllowedDomains(honor, rp)))
			fmt.Fprintf(&sb, "vrad=%s\n", joinBar2(c.VettedRepoAllowedDomains(rp)))
			fmt.Fprintf(&sb, "domains=%s\n", joinBar2(CommittedAllowedDomains(rp)))
			fmt.Fprintf(&sb, "ci_head=%s\n", joinBar2(CommittedIgnoreFingerprints(rp, "")))
			fmt.Fprintf(&sb, "ci_tag=%s\n", joinBar2(CommittedIgnoreFingerprints(rp, "agent-vetted/t1")))
			fmt.Fprintf(&sb, "ci_prev=%s\n", joinBar2(CommittedIgnoreFingerprints(rp, "HEAD~1")))
			fmt.Fprintf(&sb, "ci_bad=%s\n", joinBar2(CommittedIgnoreFingerprints(rp, "nonexistent")))
			fmt.Fprintf(&sb, "legacy=%s\n", joinBar2(CommittedLegacyAcceptedSecrets(rp)))
			fmt.Fprintf(&sb, "load=%s\n", joinBar2(config.LoadRepoIgnoreFingerprints(rp)))
		} else {
			fmt.Fprintf(&sb, "state=%s\n", c.SSHSigningKeyState(rp))
			rc := 1
			if c.SigningConfigured(rp) {
				rc = 0
			}
			fmt.Fprintf(&sb, "configured_rc=%d\n", rc)
		}
		ents, _ := os.ReadDir(filepath.Join(fx, "markers"))
		m := ""
		for _, e := range ents {
			m += e.Name() + " "
		}
		fmt.Fprintf(&sb, "markers=%s\n", m)
	}
	return strings.ReplaceAll(sb.String(), fx, "<T>")
}

// joinBar2 renders a list as the oracle does: each item followed by '|'.
func joinBar2(xs []string) string {
	var sb strings.Builder
	for _, x := range xs {
		sb.WriteString(x + "|")
	}
	return sb.String()
}

func TestExceptionsGolden(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join(excBase, "golden-exc.txt"))
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
	want, have := split(string(golden)), split(excOutput(t))
	var bad []string
	for id, w := range want {
		if have[id] != w {
			bad = append(bad, fmt.Sprintf("%s\n--- oracle\n%s--- port\n%s", id, w, have[id]))
		}
	}
	t.Logf("exceptions and signing-key state: %d cases, %d divergences", len(want), len(bad))
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

func TestExceptionsLiveOracle(t *testing.T) {
	if os.Getenv("SBX_ORACLE") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI is set but SBX_ORACLE is not: the live oracle must run in CI (no silent skips)")
		}
		t.Skip("set SBX_ORACLE=1 on Linux to run the bash oracle live")
	}
	cmd := exec.Command(filepath.Join(excBase, "oracle.sh"))
	cmd.Env = append(os.Environ(), "LC_ALL=C.UTF-8")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(excBase, "golden-exc.txt"))
	if string(b) != string(out) {
		t.Error("golden-exc.txt differs from the live oracle: regenerate it")
	}
}
