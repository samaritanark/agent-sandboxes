package gate

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

var gateBase = filepath.Join("testdata", "gate")

func gateBlocks(t *testing.T) string {
	t.Helper()
	abs, _ := filepath.Abs(gateBase)
	scanDir := filepath.Join(abs, "..", "scan")
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	fx := filepath.Join(tmp, "fx")
	if out, err := exec.Command(filepath.Join(scanDir, "setup.sh"), fx).CombinedOutput(); err != nil {
		t.Fatalf("setup.sh: %v\n%s", err, out)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	t.Setenv("STUB_ROOT", fx)
	origPath := os.Getenv("PATH")
	rows := readTSV(t, filepath.Join(gateBase, "cases.tsv"), 11)
	var sb strings.Builder
	for _, r := range rows {
		id, repos, accept, trusted, unv, vec, tty, legacy, accfix, scen, pathMode := r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10]
		if pathMode == "stub" {
			t.Setenv("PATH", filepath.Join(scanDir, "stub")+":"+origPath)
		} else {
			t.Setenv("PATH", "/usr/bin:/bin")
		}
		stubLog := filepath.Join(fx, "log", "stub-"+id)
		os.WriteFile(stubLog, nil, 0o644)
		t.Setenv("STUB_LOG", stubLog)
		t.Setenv("STUB_SCEN", filepath.Join(abs, "scen", scen))

		var logb bytes.Buffer
		var outb, errb bytes.Buffer
		combined := tty != "-"
		d := GateDeps{Out: &outb, Err: &errb, IsTTY: combined}
		if combined {
			d.Err = &outb
			reply := tty + "\n"
			if tty == "EOF" {
				reply = ""
			}
			d.Stdin = bufio.NewReader(strings.NewReader(reply))
		}
		d.VettedAcceptedFingerprints = func(repo, unvetted string) string {
			fmt.Fprintf(&logb, "vaf %s %s\n", bashBasename(repo), unvetted)
			if accfix != "-" {
				b, _ := os.ReadFile(filepath.Join(fx, "acc", accfix))
				return string(b)
			}
			return ""
		}
		d.ExceptionsFromCommit = func() bool { return vec == "true" }
		d.RecordOverride = func(m, w string, rs []string) {
			logb.WriteString("override")
			for _, a := range append([]string{m, w}, rs...) {
				fmt.Fprintf(&logb, " [%s]", a)
			}
			logb.WriteString("\n")
		}
		d.LoadRepoAcceptedSecrets = func(string) string {
			switch legacy {
			case "yes":
				return "x:y:1:h\n"
			case "nl":
				return "\n\n"
			}
			return ""
		}
		d.Warn = func(m string) { fmt.Fprintf(&logb, "warn %s\n", m) }
		e := ScanEnv{Home: filepath.Join(fx, "home"), TmpDir: filepath.Join(fx, "tmp"), CacheDir: filepath.Join(fx, "cache"),
			UserConfig: filepath.Join(fx, "uc", "none.yaml")}
		d.Scan = func(repo, af string) []string { return ScanRepoSecrets(e, repo, af, nil) }

		var repoList []string
		if repos != "-" {
			for _, n := range strings.Split(repos, ",") {
				repoList = append(repoList, filepath.Join(fx, n))
			}
		}
		rc, summary := SecretGateRepos(d, accept, trusted, unv, repoList)

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
		sb.WriteString("--- stub\n")
		b, _ := os.ReadFile(stubLog)
		sb.Write(b)
		fmt.Fprintf(&sb, "--- meta\nrc=%d\nsummary=%s\n", rc, summary)
	}
	return strings.ReplaceAll(sb.String(), fx, "<T>")
}

func splitBlocks(s string) map[string]string {
	m := map[string]string{}
	for _, blk := range strings.Split(s, "### ")[1:] {
		i := strings.IndexByte(blk, '\n')
		m[blk[:i]] = blk[i+1:]
	}
	return m
}

func TestGateGolden(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join(gateBase, "golden-gate.txt"))
	if err != nil {
		t.Fatalf("%v (generate the golden file; see go/README.md)", err)
	}
	want, have := splitBlocks(string(golden)), splitBlocks(gateBlocks(t))
	var bad []string
	for id, w := range want {
		if have[id] != w {
			bad = append(bad, fmt.Sprintf("%s\n--- oracle\n%s--- port\n%s", id, w, have[id]))
		}
	}
	t.Logf("secret_gate_repos: %d cases, %d divergences", len(want), len(bad))
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

func TestGateLiveOracle(t *testing.T) {
	requireLiveOracle(t)
	cmd := exec.Command(filepath.Join(gateBase, "oracle.sh"))
	cmd.Env = append(os.Environ(), "LC_ALL=C.UTF-8")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(gateBase, "golden-gate.txt"))
	if string(b) != string(out) {
		t.Error("golden-gate.txt differs from the live oracle: regenerate it")
	}
}

func TestBashQuoteQ(t *testing.T) {
	for in, want := range map[string]string{
		"": "''", "plain": "plain", "a b": `a\ b`, "~x": `\~x`, "a~b": "a~b", "a:~b": `a:\~b`, "#x": `\#x`, "a#b": "a#b",
		"it's": `it\'s`, "a\tb": `$'a\tb'`, "\x7f": `$'\177'`, "é": "é", "é\t": "$'é\\t'", "a\xc3": `$'a\303'`, "\x1b[0m": `$'\E[0m'`,
		"x,y": `x\,y`, "back\\s": `back\\s`, "\u0085": `$'\302\205'`,
	} {
		if got := bashQuoteQ(in); got != want {
			t.Errorf("bashQuoteQ(%q) = %s, want %s", in, got, want)
		}
	}
}
