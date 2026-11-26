package brokerkey

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("modes")
	}
	f := File{Path: filepath.Join(t.TempDir(), "state", "broker.key")}
	if _, err := f.Load(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("absent: %v", err)
	}
	k1, created, err := Get(f)
	if err != nil || !created || len(k1) != 32 {
		t.Fatalf("%x %v %v", k1, created, err)
	}
	if st, _ := os.Stat(f.Path); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	if st, _ := os.Stat(filepath.Dir(f.Path)); st.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", st.Mode())
	}
	k2, created, err := Get(f)
	if err != nil || created || !bytes.Equal(k1, k2) {
		t.Fatalf("second Get: %v %v", created, err)
	}
	os.Chmod(f.Path, 0o640)
	if _, _, err := Get(f); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("a group-readable key: %v", err)
	}
	os.Chmod(f.Path, 0o600)
	os.WriteFile(f.Path, []byte("short"), 0o600)
	if _, _, err := Get(f); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Errorf("a damaged key: %v", err)
	}
	os.Remove(f.Path)
	os.Symlink("/etc/hosts", f.Path)
	if _, _, err := Get(f); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a symlink was read as the key: %v", err)
	}
}

// forgetful saves nothing, as security -i can when its command fails yet it exits 0.
type forgetful struct{}

func (forgetful) Where() string         { return "nowhere" }
func (forgetful) Weak() bool            { return false }
func (forgetful) Load() ([]byte, error) { return nil, ErrNoKey }
func (forgetful) Save(key []byte) error { return nil }

// stale keeps answering with a key other than the one saved.
type stale struct{ saved bool }

func (*stale) Where() string { return "stale" }
func (*stale) Weak() bool    { return false }
func (s *stale) Load() ([]byte, error) {
	if !s.saved {
		return nil, ErrNoKey
	}
	return bytes.Repeat([]byte{7}, 32), nil
}
func (s *stale) Save([]byte) error { s.saved = true; return nil }

func TestGetChecksTheKeyStuck(t *testing.T) {
	if k, _, err := Get(forgetful{}); err == nil || k != nil {
		t.Errorf("a key that did not stick was returned: %v", err)
	}
	if k, _, err := Get(&stale{}); err == nil || k != nil {
		t.Errorf("a key other than the one read back was returned: %v", err)
	}
}

// TestKeychain runs security under a temporary HOME whose login keychain is a throwaway file, and
// checks that this is the default keychain before writing: security falls back to the user's
// real default keychain when it is given a keychain path that does not exist.
func TestKeychain(t *testing.T) {
	if _, err := os.Stat("/usr/bin/security"); err != nil || runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	kc := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
	os.MkdirAll(filepath.Dir(kc), 0o700)
	if out, err := exec.Command("/usr/bin/security", "create-keychain", "-p", "test", kc).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	defer exec.Command("/usr/bin/security", "delete-keychain", kc).Run()
	out, err := exec.Command("/usr/bin/security", "default-keychain").Output()
	if err != nil || !strings.Contains(string(out), home) {
		t.Skipf("the throwaway keychain is not the default under the test HOME (%q); not touching the real one", out)
	}
	k := Keychain{Account: "/Users/some one/.sandbox"}
	if _, err := k.Load(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("absent: %v", err)
	}
	k1, created, err := Get(k)
	if err != nil || !created {
		t.Fatalf("%v %v", created, err)
	}
	k2, created, err := Get(k)
	if err != nil || created || !bytes.Equal(k1, k2) {
		t.Fatalf("second Get: %v %v", created, err)
	}
	other := Keychain{Account: "/Users/other/.sandbox"}
	if _, err := other.Load(); !errors.Is(err, ErrNoKey) {
		t.Errorf("another state directory shares the key: %v", err)
	}
	if out, _ := exec.Command("/usr/bin/security", "find-generic-password", "-a", k.Account, "-s", KeychainService, kc).Output(); !strings.Contains(string(out), "acct") {
		t.Error("the item is not in the throwaway keychain")
	}
	if err := (Keychain{Account: `a"b`}).Save(k1); err == nil {
		t.Error("a quote in the account")
	}
}

// TestKeychainToolFails: only security's "not found" means there is no key yet. Any other failure
// (a locked keychain, a denied prompt) must not make Get mint a new key over the old one.
func TestKeychainToolFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh")
	}
	tool := filepath.Join(t.TempDir(), "security")
	os.WriteFile(tool, []byte("#!/bin/sh\necho 'User interaction is not allowed.' >&2\nexit 36\n"), 0o755)
	k := Keychain{Account: "a", Tool: tool}
	if _, err := k.Load(); err == nil || errors.Is(err, ErrNoKey) {
		t.Errorf("a locked keychain read as no key: %v", err)
	}
	if _, _, err := Get(k); err == nil {
		t.Errorf("Get went on: %v", err)
	}
}
