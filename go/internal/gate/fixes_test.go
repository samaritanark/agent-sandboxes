package gate

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

func TestFixLiteralPathspec(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	fx := filepath.Join(t.TempDir(), "fx")
	if out, err := exec.Command(filepath.Join("testdata", "accepted", "setup.sh"), fx).CombinedOutput(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	af, repo := filepath.Join(fx, "acc", "exact"), filepath.Join(fx, "repo")
	// "d*" is listed in the ignore file; as a pathspec it matches tracked dir/b.txt.
	if !LeakscanFindingAccepted(af, repo, "d*", "generic-api-key", "3") {
		t.Fatal("legacy: a glob entry should be accepted through pathspec matching")
	}
	defer deviation.Force(deviation.LiteralPathspec)()
	if LeakscanFindingAccepted(af, repo, "d*", "generic-api-key", "3") {
		t.Error("fixed: a glob must not be accepted as a path")
	}
	if !LeakscanFindingAccepted(af, repo, "a.txt", "generic-api-key", "3") {
		t.Error("fixed: a tracked file listed by its real path must still be accepted")
	}
	if LeakscanFindingAccepted(af, repo, "u.txt", "generic-api-key", "3") {
		t.Error("fixed: an untracked file must still be refused")
	}
}

func TestFixTabFieldsExact(t *testing.T) {
	line := "no\ta.txt\t\t3\tREDACTED" // empty rule id
	legacy := bytesSplit(line)
	if legacy[2] != "3" { // the bash shifted the line number into the rule slot
		t.Fatalf("legacy: got %q", legacy)
	}
	defer deviation.Force(deviation.TabFieldsExact)()
	got := bytesSplit(line)
	if got[2] != "" || got[3] != "3" || got[4] != "REDACTED" {
		t.Fatalf("fixed: got %q", got)
	}
}

func bytesSplit(line string) []string { return splitScanLine(line) }

func TestFixRawPathNames(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	fx := filepath.Join(t.TempDir(), "fx")
	if out, err := exec.Command(filepath.Join("testdata", "scan", "setup.sh"), fx).CombinedOutput(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	e := config.Env{Home: filepath.Join(fx, "home"), UserConfig: filepath.Join(fx, "none.yaml")}
	repo := filepath.Join(fx, "r-base")
	if strings.Contains(LeakscanConfig(e, repo), "ünï") {
		t.Fatal("legacy: a non-ASCII dependency directory is not expected in the allowlist")
	}
	defer deviation.Force(deviation.RawPathNames)()
	if !strings.Contains(LeakscanConfig(e, repo), "ünï/\\.venv") {
		t.Errorf("fixed: ünï/.venv should be excluded:\n%s", LeakscanConfig(e, repo))
	}
}

func TestFixStrictReportShape(t *testing.T) {
	multi := []byte("null\n[]")
	if !reportIsArray(multi) {
		t.Fatal("legacy: the last value being an array passes")
	}
	rows := func(b []byte) int { return len(reportRows(b, []string{"File"}, nil)) }
	two := []byte(`[{"File":"a"}]` + "\n" + `[{"File":"b"}]`)
	if rows(two) != 2 {
		t.Fatal("legacy: all values are read")
	}
	defer deviation.Force(deviation.StrictReportShape)()
	if reportIsArray(multi) {
		t.Error("fixed: two values must fail the check")
	}
	if !reportIsArray([]byte("[]")) || reportIsArray([]byte("null")) || reportIsArray(nil) {
		t.Error("fixed: exactly one array passes; null and empty do not")
	}
	if rows(two) != 1 {
		t.Error("fixed: only the first value is read")
	}
}

func TestFixQuoteRepoInMaskAdd(t *testing.T) {
	entries := []string{"/work/my repo\ta.txt\tr\t1\tR"}
	render := func() string {
		var b bytes.Buffer
		PrintMaskAddCommands(&b, entries)
		return b.String()
	}
	if !strings.Contains(render(), "--repo /work/my repo a.txt") {
		t.Fatalf("legacy: got %q", render())
	}
	defer deviation.Force(deviation.QuoteRepoInMaskAdd)()
	if !strings.Contains(render(), `--repo /work/my\ repo a.txt`) {
		t.Errorf("fixed: got %q", render())
	}
}

func TestFixExactColumns(t *testing.T) {
	f := filepath.Join(t.TempDir(), "s.yaml")
	// ENC[ opens at column 4 ('['), so the first column inside the envelope is 5.
	os.WriteFile(f, []byte("a: ENC[AES256_GCM,data:abc,tag:zz]\n"), 0o644)
	line := "a: ENC[AES256_GCM,data:abc,tag:zz]"
	start := strings.Index(line, "AES256") + 1 // 1-based column of the first character after '['
	end := start + len("AES256_GCM") - 1
	sc, ec := itoa(start), itoa(end)
	if FindIsEnc(f, sc, ec) {
		t.Fatal("legacy: a span starting right after '[' is treated as not inside")
	}
	defer deviation.Force(deviation.ExactColumns)()
	if !FindIsEnc(f, sc, ec) {
		t.Error("fixed: a span inside the envelope, starting right after '[', is inside")
	}
	// a span that touches the closing bracket is still not inside
	last := len(line)
	if FindIsEnc(f, itoa(start), itoa(last)) {
		t.Error("fixed: a span reaching the closing ']' is not inside")
	}
}

func FindIsEnc(f, sc, ec string) bool { return FindingIsEncrypted(f, "1", sc, ec) }
func itoa(n int) string               { return strconv.Itoa(n) }
