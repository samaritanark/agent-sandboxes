package brokerstore

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, KeySize) }

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
