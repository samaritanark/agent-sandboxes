package link

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

func TestFixDefaultRepoSensitiveTightened(t *testing.T) {
	const home = "/home/u"
	newly := []string{"/home", "/", "/var/run/docker.sock", "/run/containerd", "/dev/sda", "/private/etc/hosts", "/ETC", "/Home/U"}
	for _, p := range newly[2:] {
		if DefaultRepoIsSensitive(home, p) {
			t.Fatalf("legacy: %q already refused", p)
		}
	}
	if DefaultRepoIsSensitive(home, "/home") || DefaultRepoIsSensitive(home+"/", "/home/u") {
		t.Fatal("legacy: /home and a trailing-slash HOME should pass")
	}
	defer deviation.Force(deviation.DefaultRepoSensitiveTightened)()
	for _, p := range newly {
		if !DefaultRepoIsSensitive(home, p) {
			t.Errorf("fixed: %q not refused", p)
		}
	}
	if !DefaultRepoIsSensitive(home+"/", "/home/u") {
		t.Error("fixed: a HOME with a trailing slash must still match")
	}
	for _, p := range []string{"~/repos/x", "/home/u/repos/x", "/srv/repos/x", "/opt/work", "/var/lib/x", "/homework"} {
		if DefaultRepoIsSensitive(home, p) {
			t.Errorf("fixed: %q refused", p)
		}
	}
}

func TestFixStrictSymlinkScan(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "profiles"), 0o755)
	os.WriteFile(filepath.Join(dir, "profiles", "dev.yaml"), []byte("tier: 1\n"), 0o644)
	os.Symlink("/etc/passwd", filepath.Join(dir, "evil\nname"))
	x := Ctx{Env: config.Env{Home: dir}}
	if !x.ValidateShape(dir).OK {
		t.Fatal("legacy: the newline-named escaping symlink should be missed")
	}
	defer deviation.Force(deviation.StrictSymlinkScan)()
	if v := x.ValidateShape(dir); v.OK || !strings.Contains(strings.Join(v.Stderr, "\n"), "symlink escapes overlay: evil\nname") {
		t.Errorf("fixed: %q", v.Stderr)
	}
}

func TestFixZeroSignerCount(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("vetting_trust_root: s.txt\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "s.txt"), []byte("# none\n"), 0o644)
	x := Ctx{Env: config.Env{Home: dir}}
	if v := x.ValidateShape(dir); !strings.Contains(v.Stderr[len(v.Stderr)-1], "(0\n0 signer(s))") {
		t.Fatalf("legacy: %q", v.Stderr)
	}
	defer deviation.Force(deviation.ZeroSignerCount)()
	if v := x.ValidateShape(dir); !strings.Contains(v.Stderr[len(v.Stderr)-1], "(0 signer(s))") {
		t.Errorf("fixed: %q", v.Stderr)
	}
}
