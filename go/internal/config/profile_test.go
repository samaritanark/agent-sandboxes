package config

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

var profileBase = filepath.Join("testdata", "profile")

const absentArg = "=AA==" // one NUL byte: no config file / SANDBOX_VERSION unset

// bashReadLines is `while IFS= read -r d` over s: a final line without a newline is not read.
func bashReadLines(s string) []string {
	parts := strings.Split(s, "\n")
	return parts[:len(parts)-1]
}

func runProfileCase(t *testing.T, dir string, row []string) string {
	t.Helper()
	id, op := row[0], row[1]
	var a [5]string
	for i := range a {
		if row[2+i] != absentArg {
			a[i] = dec64(t, row[2+i])
		}
	}
	c := filepath.Join(dir, id)
	defer os.RemoveAll(c)
	home := c + "/a/b/home"
	os.MkdirAll(home, 0o755)
	e := Env{Home: home, UserConfig: home + "/none.yaml"}
	layout := func(l, nm string) {
		ov := home + "/ov"
		file := func(p, body string) {
			os.MkdirAll(p[:strings.LastIndex(p, "/")], 0o755) // dirname, not filepath.Dir: keep ".."
			os.WriteFile(p, []byte(body), 0o644)
		}
		for _, ch := range l {
			switch ch {
			case 'E':
				e.SandboxOverlay = ov
			case 'C':
				file(home+"/uc.yaml", "overlay: "+ov+"\n")
				e.UserConfig = home + "/uc.yaml"
			case 'T':
				file(home+"/uc.yaml", "overlay: ~/ov\n")
				e.UserConfig = home + "/uc.yaml"
			case 'U':
				file(home+"/.sandbox/profiles/"+nm+".yaml", "tier: 1\n")
			case 'u':
				os.MkdirAll(home+"/.sandbox/profiles/"+nm+".yaml", 0o755)
			case 'O':
				file(ov+"/profiles/"+nm+".yaml", "tier: 2\n")
			case 'o':
				os.MkdirAll(ov+"/profiles/"+nm+".yaml", 0o755)
			case 'B':
				file(ov+"/blocked-destinations.yaml", "blocked_domains: []\n")
			case 'b':
				os.MkdirAll(ov+"/blocked-destinations.yaml", 0o755)
			}
		}
	}
	rc, out, errOut := 0, "", ""
	bool2rc := func(ok bool) int {
		if ok {
			return 0
		}
		return 1
	}
	switch op {
	case "valid":
		rc = bool2rc(IsValidProfileName(a[0]))
	case "numeric":
		rc = bool2rc(IsNumericProfile(a[0]))
	case "find":
		layout(a[0], a[1])
		p, ok := FindProfilePath(e, a[1])
		if rc = bool2rc(ok); ok {
			out = p + "\n"
		}
	case "obdf":
		layout(a[0], "x")
		if p := OverlayBlockedDestinationsFile(e); p != "" {
			out = p + "\n"
		} else {
			rc = 1 // `[[ -f ]] && echo` as the last command
			if ResolveOverlayPath(e) == "" {
				rc = 0 // `|| return 0`
			}
		}
	case "minver":
		os.MkdirAll(c+"/ov", 0o755)
		if row[2] != absentArg {
			os.WriteFile(c+"/ov/config.yaml", []byte(a[0]), 0o644)
		}
		unmet, warns := OverlayMinVersionUnmet(c+"/ov", a[1])
		if unmet != "" {
			out = unmet + "\n"
			rc = 0
		}
		for _, w := range warns {
			errOut += "WARN: " + w + "\n"
		}
	case "vge":
		rc = bool2rc(VersionGE(a[0], a[1]))
	case "render":
		y, err := RenderProfileYAML(a[0], a[1], a[2], a[3], bashReadLines(a[4]))
		if err != nil {
			rc, errOut = 1, err.Error()+"\n"
		}
		out = y
	case "upd":
		out = UserProfilesDir(e) + "\n"
	default:
		t.Fatalf("%s: unknown op %q", id, op)
	}
	r := func(s string) string { return enc64([]byte(strings.ReplaceAll(s, c, "<C>"))) }
	return fmt.Sprintf("%s\t%d\t%s\t%s", id, rc, r(out), r(errOut))
}

func TestProfileGolden(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	cases := readRows(t, filepath.Join(profileBase, "cases.tsv"), 7)
	golden := readRows(t, filepath.Join(profileBase, "golden-profile.tsv"), 4)
	if len(cases) != len(golden) {
		t.Fatalf("%d cases but %d golden lines: regenerate the golden file", len(cases), len(golden))
	}
	dir := t.TempDir()
	var bad []string
	for i, row := range cases {
		want := strings.Join(golden[i], "\t")
		if got := runProfileCase(t, dir, row); got != want {
			var args []string
			for _, f := range row[2:] {
				args = append(args, fmt.Sprintf("%q", dec64(t, f)))
			}
			w, g := strings.Split(want, "\t"), strings.Split(got, "\t")
			bad = append(bad, fmt.Sprintf("%s %s %s\n    oracle: rc=%s out=%q err=%q\n    port:   rc=%s out=%q err=%q",
				row[0], row[1], strings.Join(args, " "), w[1], dec64(t, w[2]), dec64(t, w[3]), g[1], dec64(t, g[2]), dec64(t, g[3])))
		}
	}
	t.Logf("profile and version_ge: %d cases, %d divergences", len(cases), len(bad))
	if len(bad) > 0 {
		n := len(bad)
		if n > 15 {
			bad = bad[:15]
		}
		t.Errorf("%d divergence(s) from the oracle, first %d:\n  %s", n, len(bad), strings.Join(bad, "\n  "))
	}
}

func TestProfileLiveOracle(t *testing.T) {
	if os.Getenv("SBX_ORACLE") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI is set but SBX_ORACLE is not: the live oracle must run in CI (no silent skips)")
		}
		t.Skip("set SBX_ORACLE=1 on Linux to run the bash oracle live")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("the oracle must run on Linux")
	}
	cmd := exec.Command(filepath.Join(profileBase, "oracle.sh"))
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(profileBase, "golden-profile.tsv"))
	if string(b) != string(out) {
		t.Error("golden-profile.tsv differs from the live oracle: regenerate it")
	}
}
