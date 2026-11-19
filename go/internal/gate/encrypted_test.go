package gate

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const (
	sealedTok = "ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z"
	plainTok  = "ghp_bC4eF6gH8iJ0kL2mN4oP6qR8sT0uV2wX4yZ6a"
)

func fx(name string) string { return filepath.Join("testdata", "encrypted", "fixtures", name) }

// colspan mirrors colspan_of in tests/test-secret-gate.sh: betterleaks reports StartColumn and
// EndColumn one past the real 1-based positions.
func colspan(t *testing.T, file string, line int, tok string) (string, string) {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	ls := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	i := strings.Index(ls[line-1], tok)
	if i < 0 {
		t.Fatalf("token not on %s:%d", file, line)
	}
	return strconv.Itoa(i + 2), strconv.Itoa(i + len(tok) + 1)
}

// TestBashSuiteAssertions mirrors test_finding_is_encrypted in tests/test-secret-gate.sh.
func TestBashSuiteAssertions(t *testing.T) {
	type tc struct {
		name    string
		file    string
		line    string
		tok     string // when set, the span of this token on that line is passed
		want    bool
		noSpan  bool
		comment string
	}
	cases := []tc{
		{"SealedSecret encryptedData value exempt", "sealed.yaml", "8", "", true, true, ""},
		{"encryptedData value exempt (template fixture)", "tmpl.yaml", "7", "", true, true, ""},
		{"plaintext in spec.template not exempt", "tmpl.yaml", "10", "", false, true, ""},
		{"top-level encryptedData exempt (nested fixture)", "nested.yaml", "7", "", true, true, ""},
		{"nested spec.encryptedData not exempt", "nested.yaml", "11", "", false, true, ""},
		{"embedded (extraObjects) SealedSecret value exempt", "extra.yaml", "8", "", true, true, ""},
		{"mixed extraObjects: real SealedSecret value exempt", "mixed-extra.yaml", "6", "", true, true, ""},
		{"sibling plaintext list element not exempt", "mixed-extra.yaml", "11", "", false, true, ""},
		{"multi-doc SealedSecret value exempt", "multi.yaml", "7", "", true, true, ""},
		{"sibling plaintext Secret doc not exempt", "multi.yaml", "14", "", false, true, ""},
		{"SOPS ENC[...] value exempt", "sops.yaml", "6", sealedTok, true, false, ""},
		{"SOPS value not exempt without a column span", "sops.yaml", "6", "", false, true, ""},
		{"SOPS ENC value exempt (leak fixture)", "sopsleak.yaml", "6", sealedTok, true, false, ""},
		{"unencrypted SOPS key not exempt", "sopsleak.yaml", "7", plainTok, false, false, ""},
		{"plaintext outside the envelope not exempt (same-line comment)", "sameline.yaml", "6", plainTok, false, false, ""},
		{"plaintext outside the envelope not exempt (non-YAML)", "config.py", "2", plainTok, false, false, ""},
		{"out-of-range line not exempt", "sealed.yaml", "999", "", false, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sc, ec := "", ""
			if !c.noSpan {
				n, _ := strconv.Atoi(c.line)
				sc, ec = colspan(t, fx(c.file), n, c.tok)
			}
			if got := FindingIsEncrypted(fx(c.file), c.line, sc, ec); got != c.want {
				t.Fatalf("FindingIsEncrypted(%s, %s, %q, %q) = %v, want %v", c.file, c.line, sc, ec, got, c.want)
			}
		})
	}
}

func TestEdgeInputs(t *testing.T) {
	if FindingIsEncrypted("testdata/encrypted/fixtures/does-not-exist", "1", "", "") {
		t.Error("missing file must not be exempt")
	}
	if FindingIsEncrypted(filepath.Join("testdata", "encrypted"), "1", "", "") {
		t.Error("a directory must not be exempt")
	}
	for _, bad := range []string{"", "x", "1x", "-1", "1.5", " 1", "+1", "1e0", "1.0", "0x1"} {
		if FindingIsEncrypted(fx("sealed.yaml"), bad, "", "") {
			t.Errorf("non-numeric line %q must not be exempt", bad)
		}
	}
}

// ---- differential against the bash oracle ----

// oracleRow is one case from a cases TSV: file, line, startcol, endcol (empty = absent).
type oracleRow struct {
	file, line, sc, ec string
	rc                 int
}

func readRows(t *testing.T, path string, wantRC bool) []oracleRow {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("%v (generate the corpus and golden files; see go/README.md)", err)
	}
	defer f.Close()
	var rows []oracleRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		p := strings.Split(sc.Text(), "\t")
		if len(p) < 4 {
			continue
		}
		r := oracleRow{p[0], p[1], p[2], p[3], -1}
		if wantRC {
			if len(p) < 5 {
				t.Fatalf("golden row without a result: %q", sc.Text())
			}
			r.rc, _ = strconv.Atoi(p[4])
		}
		rows = append(rows, r)
	}
	return rows
}

// TestGolden compares the port with the oracle's recorded answers (generated on Linux with mawk).
func TestGolden(t *testing.T) {
	for _, set := range []string{"fixtures", "mutants"} {
		cases := filepath.Join("testdata", "encrypted", "cases-"+set+".tsv")
		golden := filepath.Join("testdata", "encrypted", "golden-"+set+".tsv")
		if _, err := os.Stat(golden); err != nil {
			t.Skipf("no golden file for %s yet", set)
		}
		rows := readRows(t, golden, true)
		var diverge []string
		for _, r := range rows {
			got := 1
			if FindingIsEncrypted(filepath.Join("testdata", "encrypted", r.file), r.line, r.sc, r.ec) {
				got = 0
			}
			if got != r.rc {
				diverge = append(diverge, fmt.Sprintf("%s line=%s sc=%q ec=%q oracle=%d port=%d", r.file, r.line, r.sc, r.ec, r.rc, got))
			}
		}
		t.Logf("%s: %d cases, %d divergences (cases file %s)", set, len(rows), len(diverge), cases)
		if len(diverge) > 0 {
			n := len(diverge)
			if n > 15 {
				diverge = diverge[:15]
			}
			t.Errorf("%d divergence(s) from the oracle, first %d:\n  %s", n, len(diverge), strings.Join(diverge, "\n  "))
		}
	}
}

// TestLiveOracle re-runs the bash on the same cases so a golden file cannot go stale unnoticed.
// It needs Linux with bash and the repo's lib/. Locally it is skipped; in CI it must run.
func TestLiveOracle(t *testing.T) {
	if os.Getenv("SBX_ORACLE") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI is set but SBX_ORACLE is not: the live oracle must run in CI (no silent skips)")
		}
		t.Skip("set SBX_ORACLE=1 on Linux to run the bash oracle live")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("the oracle must run on Linux: the appliance's awk is mawk, which differs from macOS awk")
	}
	root, _ := filepath.Abs(filepath.Join("..", "..", ".."))
	for _, set := range []string{"fixtures", "mutants"} {
		golden := filepath.Join("testdata", "encrypted", "golden-"+set+".tsv")
		if _, err := os.Stat(golden); err != nil {
			continue
		}
		rows := readRows(t, golden, true)
		// Fields are re-delimited with US (0x1f): bash's read collapses adjacent tabs.
		script := `source "$1/lib/filesystem.sh"
us=$'\037'
tr '\t' '\037' < "$3" | while IFS="$us" read -r f l sc ec rc; do
  finding_is_encrypted "$2/$f" "$l" "$sc" "$ec" && echo 0 || echo 1
done`
		cmd := exec.Command("bash", "-c", script, "oracle", root, filepath.Join(root, "go", "internal", "gate", "testdata", "encrypted"), golden)
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("oracle run failed: %v", err)
		}
		got := strings.Fields(string(out))
		if len(got) != len(rows) {
			t.Fatalf("%s: oracle produced %d results for %d cases", set, len(got), len(rows))
		}
		stale := 0
		for i, r := range rows {
			if g, _ := strconv.Atoi(got[i]); g != r.rc {
				stale++
			}
		}
		if stale > 0 {
			t.Errorf("%s: %d of %d golden answers differ from the live oracle: regenerate the golden files", set, stale, len(rows))
		}
	}
}
