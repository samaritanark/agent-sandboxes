package cli

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

// The differential tests compare against the bash oracle, so they run with every fix off; each fix
// has its own test (fixes_test.go) that turns it on.
func TestMain(m *testing.M) {
	deviation.SetLegacy(true)
	os.Exit(m.Run())
}

func dec64(t *testing.T, f string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(f, "="))
	if err != nil {
		t.Fatalf("bad base64 %q: %v", f, err)
	}
	return string(b)
}

func enc64(s string) string { return "=" + base64.StdEncoding.EncodeToString([]byte(s)) }

// fixtureEnv is the environment the oracle gives bin/sandbox: ver is none or full, home the case's
// home directory, root the repository (the oracle's copied install), envs its extra variables.
func fixtureEnv(ver, home, root string, envs []string) Env {
	e := Env{Root: "<ROOT>", LogsDir: home + "/logs", Runtime: "<RT>", Now: func() int64 { return 1800000000 }}
	if ver == "full" {
		e.Version = VersionInfo{"v3.0.0-test", "0123456789ab", "2026-11-24", "2026-11-25", "clean"}
	}
	e.Home = home
	e.UserConfig = home + "/.sandbox/config.yaml"
	e.CacheDir = home + "/.sandbox/cache/leakscan"
	e.OrgBlockList = root + "/config/blocked-destinations.yaml"
	for _, kv := range envs {
		k, v, _ := strings.Cut(strings.ReplaceAll(kv, "<HOME>", home), "=")
		switch k {
		case "SANDBOX_OVERLAY":
			e.SandboxOverlay = v
		case "USER_SANDBOX_CONFIG":
			e.UserConfig = v
		case "BLOCKED_DESTINATIONS_CONFIG":
			e.OrgBlockList = v
		}
	}
	return e
}

// buildTree materializes a tree spec (see oracle.sh) under home.
func buildTree(t *testing.T, home, spec string) {
	for _, line := range strings.Split(spec, "\n") {
		w := strings.Fields(line)
		if len(w) == 0 {
			continue
		}
		k, p := dec64(t, w[0]), dec64(t, w[1])
		full := home + "/" + p
		parent := full[:strings.LastIndex(full, "/")]
		switch k {
		case "f":
			os.MkdirAll(parent, 0o755)
			os.WriteFile(full, []byte(dec64(t, w[2])), 0o666)
		case "d":
			os.MkdirAll(full, 0o755)
		case "l":
			os.MkdirAll(parent, 0o755)
			os.Symlink(dec64(t, w[2]), full)
		case "g":
			os.MkdirAll(full, 0o755)
			cmd := exec.Command("git", "init", "-q", "-b", "main", full)
			cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null")
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git init %s: %v %s", full, err, b)
			}
		case "c":
			for _, a := range [][]string{{"add", "-A"}, {"commit", "-q", "-m", "c"}} {
				cmd := exec.Command("git", append([]string{"-C", full}, a...)...)
				cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x",
					"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x",
					"GIT_AUTHOR_DATE=@1700000000 +0000", "GIT_COMMITTER_DATE=@1700000000 +0000")
				if b, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("git %v in %s: %v %s", a, full, err, b)
				}
			}
		case "v":
			os.Chmod(home+"/.testkey/k", 0o600)
			head, err := exec.Command("git", "-C", full, "rev-parse", "HEAD").Output()
			if err != nil {
				t.Fatalf("rev-parse in %s: %v", full, err)
			}
			cmd := exec.Command("git", "-C", full, "-c", "gpg.format=ssh", "-c", "user.signingkey="+home+"/.testkey/k",
				"tag", "-s", "-m", "vetted for agent use", "agent-vetted/"+strings.TrimSpace(string(head)))
			cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x",
				"GIT_COMMITTER_DATE=@1700000100 +0000")
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("signed tag in %s: %v %s", full, err, b)
			}
		case "L":
			origin, dst := home+"/"+dec64(t, w[2]), home+"/.sandbox/overlays/"+p
			cmd := exec.Command("git", "clone", "-q", origin, dst)
			cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null")
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("clone %s: %v %s", origin, err, b)
			}
			head, _ := exec.Command("git", "-C", dst, "rev-parse", "HEAD").Output()
			os.MkdirAll(home+"/.sandbox", 0o755)
			f, _ := os.OpenFile(home+"/.sandbox/config.yaml", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o666)
			fmt.Fprintf(f, "overlay: %s\nlink_url: %s\nlink_ref: main\nlink_commit: %s\n", dst, origin, strings.TrimSpace(string(head)))
			f.Close()
		case "r":
			os.RemoveAll(full)
		case "p":
			os.MkdirAll(parent, 0o755)
			if err := syscall.Mkfifo(full, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// listing is the oracle's sorted listing of home.
func listing(home string) string {
	var paths []string
	filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err != nil || p == home {
			return nil
		}
		if d.Name() == ".git" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		paths = append(paths, "./"+strings.TrimPrefix(p, home+"/"))
		return nil
	})
	sort.Strings(paths)
	var b strings.Builder
	for _, rel := range paths {
		p := filepath.Join(home, rel)
		st, _ := os.Lstat(p)
		q := bashcompat.QuoteQ(rel)
		switch {
		case st.Mode()&os.ModeSymlink != 0:
			l, _ := os.Readlink(p)
			fmt.Fprintf(&b, "l %s -> %s\n", q, l)
		case st.IsDir():
			fmt.Fprintf(&b, "d %s %o\n", q, st.Mode().Perm())
		case st.Mode()&os.ModeNamedPipe != 0:
			fmt.Fprintf(&b, "p %s\n", q)
		default:
			data, _ := os.ReadFile(p)
			data = []byte(strings.ReplaceAll(string(data), home, "<HOME>"))
			fmt.Fprintf(&b, "f %s %o %s\n", q, st.Mode().Perm(), base64.StdEncoding.EncodeToString(data))
		}
	}
	return b.String()
}

func TestCLIGolden(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
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
	cases, golden := read("cases.tsv", 6), read("golden-cli.tsv", 5)
	if len(cases) != len(golden) {
		t.Fatalf("%d cases but %d golden lines: regenerate the golden file", len(cases), len(golden))
	}
	root, _ := filepath.Abs(filepath.Join("..", "..", ".."))
	dir := t.TempDir()
	var bad []string
	for i, row := range cases {
		var args []string
		home := filepath.Join(dir, row[0], "home")
		if a := dec64(t, row[2]); a != "" {
			args = strings.Split(strings.TrimSuffix(a, "\x00"), "\x00")
			for j := range args {
				args[j] = strings.ReplaceAll(args[j], "<HOME>", home)
			}
		}
		os.MkdirAll(home, 0o755)
		buildTree(t, home, dec64(t, row[3]))
		var envs []string
		if e := dec64(t, row[5]); e != "" {
			envs = strings.Split(e, "\n")
		}
		// The process environment the oracle gives bin/sandbox: a fixed PATH, and with STUB=1 the
		// gate's stub scanner first on it.
		path := "/usr/bin:/bin"
		for _, kv := range envs {
			if kv == "STUB=1" {
				path = filepath.Join(root, "go/internal/gate/testdata/scan/stub") + ":" + path
				t.Setenv("STUB_SCEN", home+"/scen")
				t.Setenv("STUB_LOG", filepath.Join(dir, row[0], "stub.log"))
				t.Setenv("STUB_ROOT", home)
			}
		}
		t.Setenv("PATH", path)
		t.Setenv("HOME", home) // git and ssh-keygen read the case's home, as under the oracle
		t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
		t.Setenv("GIT_COMMITTER_NAME", "t")
		t.Setenv("GIT_COMMITTER_EMAIL", "t@x")
		t.Setenv("GIT_COMMITTER_DATE", "@1700000200 +0000")
		os.Chmod(home+"/.testkey/k", 0o600)
		t.Setenv("GIT_CONFIG_GLOBAL", "")
		os.Unsetenv("GIT_CONFIG_GLOBAL")
		os.Unsetenv("SSH_AUTH_SOCK")
		// The tree is built with the test's own environment; the command then runs in the case's.
		env := fixtureEnv(row[1], home, root, envs)
		env.SandboxRoot = "/nonexistent-sandbox-root" // the oracle's install copy, outside every case home
		env.Stdin = strings.NewReader(dec64(t, row[4]))
		var out, errb bytes.Buffer
		rc := Run(args, env, &out, &errb)
		norm := func(s string) string {
			return strings.NewReplacer(home, "<HOME>", root, "<ROOT>").Replace(s)
		}
		got := fmt.Sprintf("%s\t%d\t%s\t%s\t%s", row[0], rc, enc64(norm(out.String())), enc64(norm(errb.String())), enc64(listing(home)))
		if want := strings.Join(golden[i], "\t"); got != want {
			w, g := golden[i], strings.Split(got, "\t")
			bad = append(bad, fmt.Sprintf("%s %s %q\n    oracle: rc=%s out=%q err=%q\n%s\n    port:   rc=%s out=%q err=%q\n%s",
				row[0], row[1], args, w[1], dec64(t, w[2]), dec64(t, w[3]), dec64(t, w[4]), g[1], dec64(t, g[2]), dec64(t, g[3]), dec64(t, g[4])))
		}
		os.RemoveAll(filepath.Join(dir, row[0]))
	}
	t.Logf("bin/sandbox: %d cases, %d divergences", len(cases), len(bad))
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
