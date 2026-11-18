package gate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

var acceptedBase = filepath.Join("testdata", "accepted")

func acceptedFixture(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "fx")
	cmd := exec.Command(filepath.Join(acceptedBase, "setup.sh"), d)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("setup.sh: %v\n%s", err, out)
	}
	return d
}

func TestAcceptedGolden(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	fx := acceptedFixture(t)
	rows := readTSV(t, filepath.Join(acceptedBase, "golden-accepted.tsv"), 5)
	var bad []string
	for _, r := range rows {
		af := filepath.Join(fx, "acc", r[0])
		if r[0] == "ABSENT" {
			af = ""
		}
		got := 1
		if LeakscanFindingAccepted(af, filepath.Join(fx, "repo"), r[1], r[2], r[3]) {
			got = 0
		}
		if want, _ := strconv.Atoi(r[4]); got != want {
			bad = append(bad, fmt.Sprintf("acc=%s path=%q rule=%q line=%q oracle=%d port=%d", r[0], r[1], r[2], r[3], want, got))
		}
	}
	t.Logf("_leakscan_finding_accepted: %d cases, %d divergences", len(rows), len(bad))
	reportBad(t, bad)
}

func TestAcceptedLiveOracle(t *testing.T) {
	requireLiveOracle(t)
	cmd := exec.Command(filepath.Join(acceptedBase, "oracle.sh"))
	cmd.Env = append(os.Environ(), "LC_ALL=C", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(acceptedBase, "golden-accepted.tsv"))
	if string(b) != string(out) {
		t.Error("golden-accepted.tsv differs from the live oracle: regenerate it")
	}
}
