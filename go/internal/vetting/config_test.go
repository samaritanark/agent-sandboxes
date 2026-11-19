package vetting

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var cfgBase = filepath.Join("testdata", "config")

const fakeNow = 1800000000

func tsvRows(t *testing.T, path string) [][]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows [][]string
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		rows = append(rows, strings.Split(l, "\t"))
	}
	return rows
}

func joinBar(ss []string) string { return strings.Join(ss, "|") }

// configOutput renders everything the oracle prints, from the Go port.
func configOutput(t *testing.T) string {
	t.Helper()
	abs, _ := filepath.Abs(cfgBase)
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	fx := filepath.Join(tmp, "fx")
	if out, err := exec.Command(filepath.Join(abs, "setup.sh"), fx).CombinedOutput(); err != nil {
		t.Fatalf("setup.sh: %v\n%s", err, out)
	}
	var sb strings.Builder
	now := func() int64 { return fakeNow }
	for _, r := range tsvRows(t, filepath.Join(cfgBase, "cases.tsv")) {
		id, u, o, home := r[0], r[1], r[2], r[3]
		var warn bytes.Buffer
		c := Ctx{Now: now, Stderr: &warn}
		c.Home = filepath.Join(fx, "home-"+home)
		c.UserConfig = filepath.Join(fx, "uc", "none.yaml")
		if u != "-" {
			c.UserConfig = filepath.Join(fx, "uc", u+".yaml")
		}
		if o != "-" {
			c.SandboxOverlay = filepath.Join(fx, "ov", o)
		}
		c.TrustRootDefault = c.Home + "/.sandbox/vetting/allowed_signers"
		c.TagPrefix = "agent-vetted/"
		fmt.Fprintf(&sb, "### %s\n", id)
		emit := func(name, val string) {
			fmt.Fprintf(&sb, "%s=%s\n", name, val)
			if w := strings.TrimSuffix(warn.String(), "\n"); w != "" {
				fmt.Fprintf(&sb, "%s.warn=%s\n", name, w)
			}
			warn.Reset()
		}
		emit("posture", c.ResolvePosture())
		emit("max_commits", c.MaxCommitsBehind())
		emit("max_age", c.MaxAgeDays())
		emit("require_head", c.ExceptionsRequireHead())
		emit("clean_worktree", c.RequireCleanWorktree())
		emit("from_commit", c.ExceptionsFromCommit())
		emit("forbid_unvetted", c.ForbidUnvettedOverride())
		emit("trust_root", c.TrustRoot())
		emit("trust_roots", joinBar(c.TrustRoots()))
		emit("trust_format", c.TrustFormat())
		emit("signing_key", c.SigningKey())
	}
	sb.WriteString("### ages\n")
	c := Ctx{Now: func() int64 { return fakeNow }}
	for _, e := range []string{"", "abc", "0", "00", "010", "1", "1799999999", "1800000000", "1800000001", "1700000000", "1000000000", "1.5", "-1",
		"18446744073709551616", "9223372036854775807", "9223372036854775808", "1799913600", "1799913601", "1799827200"} {
		fmt.Fprintf(&sb, "[%s]=%s\n", e, c.AgeDays(e))
	}
	sb.WriteString("### signers\n")
	unesc := strings.NewReplacer(`\n`, "\n", `\r`, "\r", `\t`, "\t")
	for _, r := range tsvRows(t, filepath.Join(cfgBase, "signer.tsv")) {
		o := ""
		if len(r) > 1 {
			o = r[1]
		}
		got := strings.TrimRight(ExtractSigner(unesc.Replace(o), r[0]), "\n")
		fmt.Fprintf(&sb, "%s %s=%s\n", r[0], o, got)
	}
	return strings.ReplaceAll(sb.String(), fx, "<T>")
}

func TestConfigGolden(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join(cfgBase, "golden-config.txt"))
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
	want, have := split(string(golden)), split(configOutput(t))
	var bad []string
	for id, w := range want {
		if have[id] != w {
			bad = append(bad, fmt.Sprintf("%s\n--- oracle\n%s--- port\n%s", id, w, have[id]))
		}
	}
	t.Logf("vetting config: %d sections/cases, %d divergences", len(want), len(bad))
	if len(have) != len(want) {
		t.Errorf("section count: oracle %d, port %d", len(want), len(have))
	}
	if n := len(bad); n > 0 {
		if n > 3 {
			bad = bad[:3]
		}
		t.Errorf("%d divergence(s), first %d:\n%s", n, len(bad), strings.Join(bad, "\n=====\n"))
	}
}

func TestConfigLiveOracle(t *testing.T) {
	if os.Getenv("SBX_ORACLE") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI is set but SBX_ORACLE is not: the live oracle must run in CI (no silent skips)")
		}
		t.Skip("set SBX_ORACLE=1 on Linux to run the bash oracle live")
	}
	cmd := exec.Command(filepath.Join(cfgBase, "oracle.sh"))
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(cfgBase, "golden-config.txt"))
	if string(b) != string(out) {
		t.Error("golden-config.txt differs from the live oracle: regenerate it")
	}
}
