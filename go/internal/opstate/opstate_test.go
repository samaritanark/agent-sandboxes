package opstate

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBuildAndReceive(t *testing.T) {
	state := t.TempDir()
	w := func(p, c string) {
		os.MkdirAll(filepath.Dir(filepath.Join(state, p)), 0o755)
		os.WriteFile(filepath.Join(state, p), []byte(c), 0o644)
	}
	w("config.yaml", "vetting: required\n")
	w("profiles/dev.yaml", "tier: 2\n")
	w("profiles/nested/x.yaml", "x\n")
	w("vetting/allowed_signers", "op ssh-ed25519 AAAA\n")
	w("secrets/GH_TOKEN", "never pushed")
	w("logs/ses-1/session.json", "{}")
	w("profiles/big.yaml", strings.Repeat("x", MaxFile+1))
	if runtime.GOOS != "windows" {
		os.Symlink("/etc/passwd", filepath.Join(state, "profiles", "link.yaml"))
	}
	tarb, warnings, err := Build(state)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && len(warnings) != 2 {
		t.Errorf("warnings %q", warnings)
	}
	var names []string
	tr := tar.NewReader(bytes.NewReader(tarb))
	for h, err := tr.Next(); err == nil; h, err = tr.Next() {
		names = append(names, h.Name)
	}
	if strings.Join(names, ",") != "config.yaml,profiles/dev.yaml,profiles/nested/x.yaml,vetting/allowed_signers" {
		t.Errorf("pushed %v", names)
	}

	dest := filepath.Join(t.TempDir(), "operator")
	os.MkdirAll(filepath.Join(dest, "logs"), 0o700)
	os.WriteFile(filepath.Join(dest, "logs", "keep"), []byte("vm state"), 0o600)
	os.MkdirAll(filepath.Join(dest, "extra-ca-certs"), 0o700)
	os.WriteFile(filepath.Join(dest, "extra-ca-certs", "old.crt"), []byte("stale"), 0o600) // removed on the host since
	if err := Receive(bytes.NewReader(tarb), dest); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "profiles", "nested", "x.yaml")); string(b) != "x\n" {
		t.Error("nested profile missing")
	}
	if _, err := os.Stat(filepath.Join(dest, "extra-ca-certs")); !os.IsNotExist(err) {
		t.Error("an item gone from the host stayed in the VM")
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "logs", "keep")); string(b) != "vm state" {
		t.Error("unmanaged VM state was touched")
	}
	if _, err := os.Stat(filepath.Join(dest, "secrets")); !os.IsNotExist(err) {
		t.Error("secrets reached the VM")
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(filepath.Join(dest, "config.yaml"))
		if st.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", st.Mode())
		}
	}
	ents, _ := os.ReadDir(dest)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".incoming-") {
			t.Error("staging left behind")
		}
	}
}

func tarOf(entries ...*tar.Header) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, h := range entries {
		tw.WriteHeader(h)
		if h.Typeflag == tar.TypeReg {
			tw.Write(make([]byte, h.Size))
		}
	}
	tw.Close()
	return b.Bytes()
}

func TestReceiveRefusals(t *testing.T) {
	reg := func(n string, size int64) *tar.Header {
		return &tar.Header{Name: n, Typeflag: tar.TypeReg, Size: size, Mode: 0o600}
	}
	for name, archive := range map[string][]byte{
		"traversal":   tarOf(reg("profiles/../../etc/x", 1)),
		"absolute":    tarOf(reg("/etc/x", 1)),
		"unmanaged":   tarOf(reg("secrets/GH_TOKEN", 1)),
		"symlink":     tarOf(&tar.Header{Name: "profiles/l", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}),
		"hard link":   tarOf(&tar.Header{Name: "profiles/l", Typeflag: tar.TypeLink, Linkname: "config.yaml"}),
		"directory":   tarOf(&tar.Header{Name: "profiles/d/", Typeflag: tar.TypeDir}),
		"too big":     tarOf(reg("profiles/x", MaxFile+1)),
		"repeated":    tarOf(reg("config.yaml", 1), reg("config.yaml", 1)),
		"file as dir": tarOf(reg("config.yaml/x", 1)),
		"garbage":     []byte("not a tar archive at all, really not"),
	} {
		dest := t.TempDir()
		if err := Receive(bytes.NewReader(archive), dest); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if ents, _ := os.ReadDir(dest); len(ents) != 0 {
			t.Errorf("%s: wrote %v", name, ents)
		}
	}
}
