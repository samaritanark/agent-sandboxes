package vetting

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/gate"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
)

var attBase = filepath.Join("testdata", "attest")

var attNoise = regexp.MustCompile(`^(error|fatal|hint|warning): |^Couldn.t load|^Load key|^No such file|^ssh-keygen|^Failed |^gpg: |^Error loading|^Signing file|^Write failed|^usage: `)

func filterNoise(b []byte) string {
	var out []string
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if !attNoise.MatchString(l) {
			out = append(out, l)
		}
	}
	s := strings.Join(out, "\n")
	if s != "" {
		s += "\n"
	}
	return s
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	if out, err := exec.Command("cp", "-a", src, dst).CombinedOutput(); err != nil {
		t.Fatalf("cp: %v %s", err, out)
	}
}

func attestOutput(t *testing.T) string {
	t.Helper()
	abs, _ := filepath.Abs(attBase)
	scanStub := filepath.Join(abs, "..", "..", "..", "gate", "testdata", "scan", "stub")
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	fx := filepath.Join(tmp, "fx")
	if out, err := exec.Command(filepath.Join(abs, "setup.sh"), fx).CombinedOutput(); err != nil {
		t.Fatalf("setup.sh: %v\n%s", err, out)
	}
	origPath := os.Getenv("PATH")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	t.Setenv("GIT_COMMITTER_DATE", "@1800000000 +0000")
	t.Setenv("SSH_AUTH_SOCK", "") // an agent's keys would make signing succeed where it should fail
	os.Unsetenv("SSH_AUTH_SOCK")
	t.Setenv("STUB_ROOT", fx)
	t.Setenv("STUB_LOG", filepath.Join(fx, "stub.log"))
	var sb strings.Builder
	for _, r := range tsvRowsN(t, filepath.Join(attBase, "cases.tsv"), 10) {
		id, fn, repo, uc, yesArg, msg, home, tty, scen, pathMode := r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9]
		run := filepath.Join(fx, "run")
		os.RemoveAll(run)
		os.MkdirAll(run, 0o755)
		os.RemoveAll(filepath.Join(fx, "markers"))
		os.MkdirAll(filepath.Join(fx, "markers"), 0o755)
		os.Remove(filepath.Join(fx, "stub.log"))
		if _, err := os.Stat(filepath.Join(fx, "tpl", repo)); err == nil {
			copyDir(t, filepath.Join(fx, "tpl", repo), filepath.Join(run, repo))
		}
		copyDir(t, filepath.Join(fx, "home-"+home), filepath.Join(run, "home"))
		b, _ := os.ReadFile(filepath.Join(fx, "uc-"+uc+".yaml"))
		os.WriteFile(filepath.Join(run, "uc.yaml"), b, 0o644)
		os.Chmod(filepath.Join(run, "uc.yaml"), 0o644)
		t.Setenv("STUB_SCEN", filepath.Join(abs, "scen", scen))
		if pathMode == "stub" {
			t.Setenv("PATH", scanStub+":"+origPath)
		} else {
			t.Setenv("PATH", "/usr/bin:/bin") // a host-installed betterleaks must not leak in
		}
		if fn == "assist" {
			t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(run, "home", ".gitconfig"))
		} else {
			t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
		}

		var outb, errb, logb bytes.Buffer
		combined := tty != "-"
		a := Attester{Out: &outb, Err: &errb, TTYIn: combined, TTYBoth: combined}
		if combined {
			a.Err = &outb
			a.Stdin = bufio.NewReader(strings.NewReader(ttyInput(tty)))
		}
		a.Home = filepath.Join(run, "home")
		a.UserConfig = filepath.Join(run, "uc.yaml")
		a.TrustRootDefault = a.Home + "/.sandbox/vetting/allowed_signers"
		a.TagPrefix = "agent-vetted/"
		a.Now = func() int64 { return 0 }
		a.Warn = func(m string) { fmt.Fprintf(&logb, "warn %s\n", m) }
		e := config.Env{Home: a.Home, TmpDir: "/tmp", UserConfig: a.UserConfig, CacheDir: filepath.Join(fx, "cache")}
		a.Scan = func(repoPath, af string) []string { return gate.ScanRepoSecrets(e, repoPath, af, nil) }
		rp := filepath.Join(run, repo)
		rc := 0
		switch fn {
		case "attest":
			switch msg {
			case "NONE":
				rc = a.AttestRepo(rp, "", "")
			case "-":
				rc = a.AttestRepo(rp, "", yesArg)
			default:
				rc = a.AttestRepo(rp, msg, yesArg)
			}
		case "ack":
			real, err := physicalDir(rp)
			ok := false
			if err == nil {
				ok = a.AcknowledgeExceptions(real, rp, yesArg)
			}
			if !ok {
				rc = 1
			}
		case "inline":
			head := ""
			if real, err := physicalDir(rp); err == nil {
				h, _ := vgit(real, "rev-parse", "HEAD")
				head = trimNL(h)
			}
			if !a.InlineAttest(rp, head) {
				rc = 1
			}
		case "assist":
			rc = a.SigningSetupAssist(rp)
		}

		fmt.Fprintf(&sb, "### %s\n", id)
		if combined {
			sb.WriteString("--- tty\n" + filterNoise(outb.Bytes()))
		} else {
			sb.WriteString("--- stdout\n" + filterNoise(outb.Bytes()) + "--- stderr\n" + filterNoise(errb.Bytes()))
		}
		sb.WriteString("--- log\n" + logb.String())
		fmt.Fprintf(&sb, "--- meta\nrc=%d\n", rc)
		ps, _ := exec.Command(filepath.Join(abs, "poststate.sh"), rp).Output()
		sb.WriteString("--- post\n" + string(ps))
		sb.WriteString("--- markers\n")
		ents, _ := os.ReadDir(filepath.Join(fx, "markers"))
		for _, en := range ents {
			sb.WriteString(en.Name() + "\n")
		}
		sb.WriteString("--- gitconfig\n")
		if gc, err := os.ReadFile(filepath.Join(run, "home", ".gitconfig")); err == nil {
			sb.Write(gc)
		}
		sb.WriteString("--- usercfg\n")
		if uc, err := os.ReadFile(filepath.Join(run, "uc.yaml")); err == nil {
			sb.Write(uc)
		}
		sb.WriteString("--- stat\n")
		if st, err := os.Stat(filepath.Join(run, "uc.yaml")); err == nil {
			fmt.Fprintf(&sb, "%o\n", st.Mode().Perm())
		}
	}
	return keyRe.ReplaceAllString(strings.ReplaceAll(sb.String(), fx, "<T>"), "ssh-$1 <KEY>")
}

var keyRe = regexp.MustCompile(`ssh-(ed25519|rsa) AAAA[A-Za-z0-9+/=]+`)

func TestAttestGolden(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join(attBase, "golden-attest.txt"))
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
	want, have := split(string(golden)), split(attestOutput(t))
	var bad []string
	for id, w := range want {
		if have[id] != w {
			bad = append(bad, fmt.Sprintf("%s\n--- oracle\n%s--- port\n%s", id, w, have[id]))
		}
	}
	t.Logf("attestation: %d cases, %d divergences", len(want), len(bad))
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

func TestAttestLiveOracle(t *testing.T) {
	if os.Getenv("SBX_ORACLE") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI is set but SBX_ORACLE is not: the live oracle must run in CI (no silent skips)")
		}
		t.Skip("set SBX_ORACLE=1 on Linux to run the bash oracle live")
	}
	cmd := exec.Command(filepath.Join(attBase, "oracle.sh"))
	cmd.Env = append(os.Environ(), "LC_ALL=C.UTF-8")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(attBase, "golden-attest.txt"))
	if string(b) != string(out) {
		t.Error("golden-attest.txt differs from the live oracle: regenerate it")
	}
}
