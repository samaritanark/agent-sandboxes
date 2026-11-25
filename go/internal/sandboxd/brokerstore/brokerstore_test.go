package brokerstore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, KeySize) }

func TestSealOpen(t *testing.T) {
	blob, err := Seal(key(1), "github", []byte("ghp_secret"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("ghp_secret")) {
		t.Fatal("plaintext in the entry")
	}
	if v, err := Open(key(1), "github", blob); err != nil || string(v) != "ghp_secret" {
		t.Fatalf("%q %v", v, err)
	}
	flipped := append([]byte(nil), blob...)
	flipped[len(flipped)-3] ^= 1
	for name, try := range map[string]func() ([]byte, error){
		"another key":       func() ([]byte, error) { return Open(key(2), "github", blob) },
		"another reference": func() ([]byte, error) { return Open(key(1), "gitlab", blob) },
		"a flipped byte":    func() ([]byte, error) { return Open(key(1), "github", flipped) },
		"truncated":         func() ([]byte, error) { return Open(key(1), "github", blob[:10]) },
		"short key":         func() ([]byte, error) { return Open(key(1)[:16], "github", blob) },
	} {
		if v, err := try(); err == nil {
			t.Errorf("%s opened: %q", name, v)
		} else if strings.Contains(err.Error(), "ghp") {
			t.Errorf("%s: a value in the error", name)
		}
	}
	if _, err := Seal(key(1), "../x", []byte("v")); err == nil {
		t.Error("a path as a reference")
	}
}

func TestStore(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "broker")}
	blob, _ := Seal(key(1), "npm", []byte("npm_x"))
	if err := s.Put("npm", blob); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("bad", []byte("plaintext value")); err == nil {
		t.Error("an unsealed entry stored")
	}
	if err := s.Put("../../etc/x", blob); err == nil {
		t.Error("a path escaped the store")
	}
	if st, _ := os.Stat(filepath.Join(s.Dir, "npm.sealed")); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	if st, _ := os.Stat(s.Dir); st.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", st.Mode())
	}
	got, _ := s.Get("npm")
	if v, err := Open(key(1), "npm", got); err != nil || string(v) != "npm_x" {
		t.Errorf("%q %v", v, err)
	}
	if l, _ := s.List(); len(l) != 1 || l[0] != "npm" {
		t.Errorf("list %v", l)
	}
	if err := s.Delete("npm"); err != nil || s.Delete("npm") != nil {
		t.Error(err)
	}
	b := []byte("secret")
	Wipe(b)
	if !bytes.Equal(b, make([]byte, 6)) {
		t.Error("not wiped")
	}
}
