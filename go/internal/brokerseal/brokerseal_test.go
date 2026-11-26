package brokerseal

import (
	"bytes"
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

func TestNewKey(t *testing.T) {
	a, err1 := NewKey()
	b, err2 := NewKey()
	if err1 != nil || err2 != nil || len(a) != KeySize || bytes.Equal(a, b) {
		t.Fatalf("%x %x %v %v", a, b, err1, err2)
	}
	blob, _ := Seal(a, "r", nil)
	if len(blob) != MinSealed || !LooksSealed(blob) || LooksSealed(blob[:MinSealed-1]) {
		t.Errorf("an empty value's entry is %d bytes", len(blob))
	}
}

func TestSecretRef(t *testing.T) {
	r := SecretRef("GH_TOKEN")
	if r != "secret.GH_TOKEN" || !ValidRef(r) {
		t.Fatal(r)
	}
	if n, ok := SecretName(r); !ok || n != "GH_TOKEN" {
		t.Error(n, ok)
	}
	for _, r := range []string{"secret.", "claude-oauth", "secretGH"} {
		if _, ok := SecretName(r); ok {
			t.Errorf("%s taken for a secret", r)
		}
	}
}
