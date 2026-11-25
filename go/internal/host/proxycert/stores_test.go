package proxycert

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var storesBase = filepath.Join("testdata", "stores")

func unb64(t *testing.T, s string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "="))
	if err != nil {
		t.Fatalf("bad base64 %q", s)
	}
	return string(b)
}

func tsv(t *testing.T, name string, n int) [][]string {
	b, err := os.ReadFile(filepath.Join(storesBase, name))
	if err != nil {
		t.Fatal(err)
	}
	var out [][]string
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		p := strings.Split(l, "\t")
		if len(p) != n {
			t.Fatalf("%s: malformed row", name)
		}
		out = append(out, p)
	}
	return out
}

func TestLinuxStoreGolden(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures use symlinks")
	}
	cases := tsv(t, "cases.tsv", 3)
	golden := tsv(t, "golden-stores.tsv", 4)
	if len(cases) != len(golden) {
		t.Fatalf("%d cases, %d golden lines", len(cases), len(golden))
	}
	dir := t.TempDir()
	bad := 0
	for i, row := range cases {
		h := filepath.Join(dir, row[0])
		os.MkdirAll(filepath.Join(h, "U"), 0o755)
		os.MkdirAll(filepath.Join(h, "E"), 0o755)
		for _, line := range strings.Split(unb64(t, row[2]), "\n") {
			if line == "" {
				continue
			}
			w := strings.Split(line, " ")
			k, p := unb64(t, w[0]), filepath.Join(h, unb64(t, w[1]))
			switch k {
			case "f":
				os.MkdirAll(filepath.Dir(p), 0o755)
				os.WriteFile(p, []byte(unb64(t, w[2])), 0o644)
			case "d":
				os.MkdirAll(p, 0o755)
			case "l":
				os.MkdirAll(filepath.Dir(p), 0o755)
				os.Symlink(unb64(t, w[2]), p)
			}
		}
		files := append(Glob(filepath.Join(h, "U", "*.crt")), Glob(filepath.Join(h, "E", "*.pem"))...)
		out, ok := LinuxStore(files, filepath.Join(h, "B"), Matcher(unb64(t, row[1])))
		rc := "1"
		if ok {
			rc = "0"
		}
		got := fmt.Sprintf("%s\t%s\t=%s\t=%s", row[0], rc, base64.StdEncoding.EncodeToString(out), base64.StdEncoding.EncodeToString([]byte(Describe(out))))
		if want := strings.Join(golden[i], "\t"); got != want {
			bad++
			if bad <= 5 {
				g := strings.Split(got, "\t")
				t.Errorf("%s vendor=%q\n  oracle rc=%s pem=%q\n         describe=%q\n  port   rc=%s pem=%q\n         describe=%q", row[0], unb64(t, row[1]),
					golden[i][1], unb64(t, golden[i][2]), unb64(t, golden[i][3]), g[1], unb64(t, g[2]), unb64(t, g[3]))
			}
		}
	}
	t.Logf("trust stores: %d cases, %d divergences", len(cases), bad)
}

func TestLinuxStoreLiveOracle(t *testing.T) {
	if os.Getenv("SBX_ORACLE") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI is set but SBX_ORACLE is not: the live oracle must run in CI (no silent skips)")
		}
		t.Skip("set SBX_ORACLE=1 on Linux to run the bash oracle live")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the oracle runs on Linux (OpenSSL 3)")
	}
	cmd := exec.Command(filepath.Join(storesBase, "oracle.sh"))
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(storesBase, "golden-stores.tsv"))
	if string(out) != string(b) {
		t.Error("golden-stores.tsv differs from the live oracle: regenerate it")
	}
}
