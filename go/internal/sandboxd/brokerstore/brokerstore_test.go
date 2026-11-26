package brokerstore

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
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

// TestBindings: the bindings entries of the second form carry, by reference; the first form has
// none listed.
func TestBindings(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "broker")}
	old, _ := Seal(key(1), "anthropic", []byte("tok"))
	bound, _ := brokerseal.SealBound(key(1), "secret.GH", []byte("v"), brokerseal.Binding{Hosts: []string{"api.github.com"}, Inject: "bearer"})
	withheld, _ := brokerseal.SealBound(key(1), "secret.W", []byte("v"), brokerseal.Binding{})
	s.Put("anthropic", old)
	s.Put("secret.GH", bound)
	s.Put("secret.W", withheld)
	b, err := s.Bindings()
	if err != nil || len(b) != 2 || b["secret.GH"].Inject != "bearer" || len(b["secret.W"].Hosts) != 0 {
		t.Errorf("%+v %v", b, err)
	}
	if _, ok := b["anthropic"]; ok {
		t.Error("the first form listed")
	}
}
