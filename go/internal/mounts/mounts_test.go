package mounts

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

var base = filepath.Join("testdata")

func TestMain(m *testing.M) {
	deviation.SetLegacy(true)
	os.Exit(m.Run())
}

func dec(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "="))
	if err != nil {
		t.Fatalf("bad base64 %q", s)
	}
	return string(b)
}

func rows(t *testing.T, name string, n int) [][]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(base, name))
	if err != nil {
		t.Fatalf("%v (generate it; see go/README.md)", err)
	}
	var out [][]string
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		p := strings.Split(l, "\t")
		if len(p) != n {
			t.Fatalf("%s: malformed row %q", name, l)
		}
		out = append(out, p)
	}
	return out
}

// render prints the plan as v2's build_volume_mounts_block (tier 2, no agent home, no infra
// kubeconfig) and _readonly_workspace_entries did, so the oracle's output can be compared.
func render(repos []string) string {
	var b strings.Builder
	total := len(repos)
	for i, r := range repos {
		name := "workspace"
		if total > 1 {
			name = fmt.Sprintf("workspace-%d", i)
		}
		fmt.Fprintf(&b, "        - name: %s\n          mountPath: %s\n", name, MountPath(r, total))
	}
	b.WriteString("        - name: tmp\n          mountPath: /tmp\n")
	for i, r := range repos {
		mp := MountPath(r, total)
		for _, m := range Masks(i, r) {
			switch {
			case m.Kind == MaskFile:
				fmt.Fprintf(&b, "        - name: overlay-empty-file\n          mountPath: %s/%s\n          readOnly: true\n", mp, m.Rel)
			case m.Kube:
				name := "overlay-kube-dir"
				if total > 1 {
					name = fmt.Sprintf("overlay-kube-dir-%d", i)
				}
				fmt.Fprintf(&b, "        - name: %s\n          mountPath: %s/%s\n", name, mp, m.Rel)
			default:
				fmt.Fprintf(&b, "        - name: overlay-mask-dir-%d-%d\n          mountPath: %s/%s\n", i, m.Index, mp, m.Rel)
			}
		}
	}
	for i, r := range repos {
		for _, m := range Readonly(i, r) {
			fmt.Fprintf(&b, "        - name: ro-ws-%d-%d\n          mountPath: %s/%s\n          readOnly: true\n", i, m.Index, MountPath(r, total), m.Rel)
		}
	}
	b.WriteString("        - name: gitconfig\n          mountPath: /home/agent/.gitconfig\n          readOnly: true\n")
	for i, r := range repos {
		fmt.Fprintf(&b, "### readonly %s\n", bashcompat.Basename(r))
		for _, m := range Readonly(i, r) {
			kind := "File"
			if m.Kind == ReadonlyDir {
				kind = "Directory"
			}
			fmt.Fprintf(&b, "%d\t%s\t%s\n", m.Index, m.Rel, kind)
		}
	}
	for _, r := range repos {
		for _, m := range Mismatches(r) {
			fmt.Fprintf(&b, "### mismatch %s|%s|%s\n", m.Path, m.Expected, m.Actual)
		}
	}
	return b.String()
}

func build(t *testing.T, home, spec string) {
	for _, line := range strings.Split(spec, "\n") {
		if line == "" {
			continue
		}
		w := strings.Split(line, " ")
		k, p := dec(t, w[0]), home+"/"+dec(t, w[1])
		switch k {
		case "f":
			os.MkdirAll(filepath.Dir(p), 0o755)
			os.WriteFile(p, []byte(dec(t, w[2])), 0o644)
		case "d":
			os.MkdirAll(p, 0o755)
		case "l":
			os.MkdirAll(filepath.Dir(p), 0o755)
			os.Symlink(dec(t, w[2]), p)
		case "p":
			os.MkdirAll(filepath.Dir(p), 0o755)
			syscall.Mkfifo(p, 0o644)
		}
	}
}

func TestMountsGolden(t *testing.T) {
	cases := rows(t, "cases.tsv", 3)
	golden := rows(t, "golden-mounts.tsv", 3)
	if len(cases) != len(golden) {
		t.Fatalf("%d cases but %d golden lines: regenerate the golden file", len(cases), len(golden))
	}
	dir := t.TempDir()
	var bad []string
	for i, row := range cases {
		home := filepath.Join(dir, row[0])
		os.MkdirAll(home, 0o755)
		build(t, home, dec(t, row[2]))
		var repos []string
		for _, r := range strings.Split(dec(t, row[1]), "\x00") {
			repos = append(repos, home+"/"+r)
		}
		got := strings.ReplaceAll(render(repos), home, "<HOME>")
		if want := dec(t, golden[i][1]); got != want || dec(t, golden[i][2]) != "" {
			bad = append(bad, fmt.Sprintf("%s repos=%q\n    oracle: %q (stderr %q)\n    port:   %q", row[0], dec(t, row[1]), want, dec(t, golden[i][2]), got))
		}
		os.RemoveAll(home)
	}
	t.Logf("mounts: %d cases, %d divergences", len(cases), len(bad))
	if len(bad) > 0 {
		n := len(bad)
		if n > 6 {
			bad = bad[:6]
		}
		t.Errorf("%d divergence(s) from the oracle, first %d:\n  %s", n, len(bad), strings.Join(bad, "\n  "))
	}
}

func TestMountsLiveOracle(t *testing.T) {
	if os.Getenv("SBX_ORACLE") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI is set but SBX_ORACLE is not: the live oracle must run in CI (no silent skips)")
		}
		t.Skip("set SBX_ORACLE=1 on Linux to run the bash oracle live")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("the oracle must run on Linux")
	}
	cmd := exec.Command(filepath.Join(base, "oracle.sh"))
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(base, "golden-mounts.tsv"))
	if string(b) != string(out) {
		t.Error("golden-mounts.tsv differs from the live oracle: regenerate it")
	}
}
