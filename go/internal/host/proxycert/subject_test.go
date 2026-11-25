package proxycert

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOneLineGolden(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "subjects.pem"))
	if err != nil {
		t.Fatal(err)
	}
	g, _ := os.ReadFile(filepath.Join("testdata", "golden-subjects.txt"))
	golden := strings.Split(strings.TrimSuffix(string(g), "\n"), "\n")
	var i int
	for len(b) > 0 {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		want := strings.Split(golden[i], "\t")
		var got [2]string
		if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
			s, e1 := OneLine(c.RawSubject)
			is, e2 := OneLine(c.RawIssuer)
			if e1 == nil && e2 == nil {
				got = [2]string{s, is}
			}
		}
		if got[0] != want[0] || got[1] != want[1] {
			t.Errorf("certificate %d: subject %q issuer %q; openssl %q %q", i+1, got[0], got[1], want[0], want[1])
		}
		i++
	}
	if i != len(golden) {
		t.Fatalf("%d certificates, %d golden lines", i, len(golden))
	}
}

func TestOneLineLiveOracle(t *testing.T) {
	if os.Getenv("SBX_ORACLE") == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("CI is set but SBX_ORACLE is not: the live oracle must run in CI (no silent skips)")
		}
		t.Skip("set SBX_ORACLE=1 on Linux to run the oracle live")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the oracle runs on Linux (OpenSSL 3)")
	}
	cmd := exec.Command(filepath.Join("testdata", "oracle.sh"))
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join("testdata", "golden-subjects.txt"))
	if string(out) != string(b) {
		t.Error("golden-subjects.txt differs from the live oracle: regenerate it")
	}
}
