package vetting

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var vgateBase = filepath.Join("testdata", "gate")

func inList(x, list string) bool {
	for _, y := range strings.Split(list, ",") {
		if x == y {
			return true
		}
	}
	return false
}

func vgateOutput(t *testing.T) string {
	t.Helper()
	abs, _ := filepath.Abs(vgateBase)
	var sb strings.Builder
	clock := Ctx{Now: func() int64 { return 1800000000 }}
	for _, r := range tsvRowsN(t, filepath.Join(vgateBase, "cases.tsv"), 13) {
		id, scn, repos, posture, accept, drift, forbid, cap, agecap, roots, tty, sign, attest := r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11], r[12]
		var outb, errb, logb bytes.Buffer
		combined := tty != "-"
		d := GateDeps{Out: &outb, Err: &errb, TTY: combined}
		if combined {
			d.Err = &outb
			d.Stdin = bufio.NewReader(strings.NewReader(ttyInput(tty)))
		}
		d.Status = func(repo string) string {
			b, err := os.ReadFile(filepath.Join(abs, "scen", scn, filepath.Base(repo)))
			if err != nil {
				return ""
			}
			return strings.TrimRight(string(b), "\n")
		}
		d.RecordOverride = func(m, w string, rs []string) {
			logb.WriteString("override")
			for _, a := range append([]string{m, w}, rs...) {
				fmt.Fprintf(&logb, " [%s]", a)
			}
			logb.WriteString("\n")
		}
		d.SigningConfigured = func(repo string) bool {
			fmt.Fprintf(&logb, "signing? %s\n", filepath.Base(repo))
			return inList(filepath.Base(repo), sign)
		}
		d.InlineAttest = func(repo, sha string) bool {
			fmt.Fprintf(&logb, "attest %s %s\n", filepath.Base(repo), sha)
			return inList(filepath.Base(repo), attest)
		}
		d.Cfg = GateConfig{ForbidOverride: forbid, TrustRoot: "/trust/default", AgeDays: clock.AgeDays}
		if roots == "some" {
			d.Cfg.TrustRoots = []string{"/trust/a", "/trust/b"}
		}
		if cap != "-" {
			d.Cfg.Cap = cap
		}
		if agecap != "-" {
			d.Cfg.AgeCap = agecap
		}
		var repoList []string
		for _, n := range strings.Split(repos, ",") {
			repoList = append(repoList, "/work/"+n)
		}
		if posture == "EMPTY" {
			posture = ""
		}
		if accept == "EMPTY" {
			accept = ""
		}
		rc, summary := d.VettingGateRepos(posture, accept, drift, repoList)
		fmt.Fprintf(&sb, "### %s\n", id)
		if combined {
			sb.WriteString("--- tty\n")
			sb.Write(outb.Bytes())
		} else {
			sb.WriteString("--- stdout\n")
			sb.Write(outb.Bytes())
			sb.WriteString("--- stderr\n")
			sb.Write(errb.Bytes())
		}
		sb.WriteString("--- log\n")
		sb.Write(logb.Bytes())
		fmt.Fprintf(&sb, "--- meta\nrc=%d\nsummary=%s\n", rc, summary)
	}
	return sb.String()
}

// ttyInput is what the pty runner types: one line per reply; EOF ends the input there.
func ttyInput(replies string) string {
	var sb strings.Builder
	for _, r := range strings.Split(replies, "|") {
		if r == "EOF" {
			break
		}
		sb.WriteString(r + "\n")
	}
	return sb.String()
}

func tsvRowsN(t *testing.T, path string, n int) [][]string {
	t.Helper()
	var rows [][]string
	for _, r := range tsvRows(t, path) {
		for len(r) < n {
			r = append(r, "")
		}
		rows = append(rows, r)
	}
	return rows
}

func TestVettingGateGolden(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join(vgateBase, "golden-gate.txt"))
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
	want, have := split(string(golden)), split(vgateOutput(t))
	var bad []string
	for id, w := range want {
		if have[id] != w {
			bad = append(bad, fmt.Sprintf("%s\n--- oracle\n%s--- port\n%s", id, w, have[id]))
		}
	}
	t.Logf("vetting_gate_repos: %d cases, %d divergences", len(want), len(bad))
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

func TestVettingGateLiveOracle(t *testing.T) {
	if os.Getenv("SBX_ORACLE") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI is set but SBX_ORACLE is not: the live oracle must run in CI (no silent skips)")
		}
		t.Skip("set SBX_ORACLE=1 on Linux to run the bash oracle live")
	}
	cmd := exec.Command(filepath.Join(vgateBase, "oracle.sh"))
	cmd.Env = append(os.Environ(), "LC_ALL=C.UTF-8")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(vgateBase, "golden-gate.txt"))
	if string(b) != string(out) {
		t.Error("golden-gate.txt differs from the live oracle: regenerate it")
	}
}
