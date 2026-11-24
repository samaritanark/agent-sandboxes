package tier

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// answers is what the oracle prints for input q (a bash printf %q word) and its value t.
func answers(q, t string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "### %s\n", q)
	rc, errs := 0, ""
	if err := Validate(t); err != nil {
		rc, errs = 1, err.Error()
	}
	fmt.Fprintf(&b, "validate rc=%d err=%s\n", rc, bashQ(errs))
	d := strings.Join(Domains(t), ",")
	if d != "" {
		d += ","
	}
	fmt.Fprintf(&b, "domains=%s\nretention=%d\ndescription=%s\n", d, RetentionDays(t), Description(t))
	return b.String()
}

// bashQ is bash's printf %q for the strings this test produces (C locale).
func bashQ(s string) string {
	if s == "" {
		return "''"
	}
	if strings.ContainsAny(s, "\n\t") {
		return "$'" + strings.NewReplacer(`\`, `\\`, "'", `\'`, "\n", `\n`, "\t", `\t`).Replace(s) + "'"
	}
	var b strings.Builder
	for _, r := range s {
		if !(r == '_' || r == '-' || r == '.' || r == '/' || r == ',' || r == ':' || r == '@' || r == '%' || r == '+' || r == '=' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// unq turns an inputs.txt word back into its value (the forms used there only).
func unq(q string) string {
	switch {
	case strings.HasPrefix(q, "$'"):
		v, _ := strconv.Unquote(`"` + strings.TrimSuffix(strings.TrimPrefix(q, "$'"), "'") + `"`)
		return v
	case strings.HasPrefix(q, "'"):
		return strings.Trim(q, "'")
	}
	return q
}

func TestTierGolden(t *testing.T) {
	in, err := os.ReadFile(filepath.Join("testdata", "inputs.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var got strings.Builder
	for _, q := range strings.Split(strings.TrimSuffix(string(in), "\n"), "\n") {
		got.WriteString(answers(q, unq(q)))
	}
	want, err := os.ReadFile(filepath.Join("testdata", "golden-tier.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != string(want) {
		t.Errorf("port differs from the oracle:\n--- oracle\n%s\n--- port\n%s", want, got.String())
	}
}

func TestTierLiveOracle(t *testing.T) {
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
	b, _ := os.ReadFile(filepath.Join("testdata", "golden-tier.txt"))
	if string(b) != string(out) {
		t.Error("golden-tier.txt differs from the live oracle: regenerate it")
	}
}
