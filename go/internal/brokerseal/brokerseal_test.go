package brokerseal

import (
	"bytes"
	"encoding/binary"
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

// TestSealBound: an entry of the second form opens only with the binding it was sealed with, which
// anyone can read from it without the key.
func TestSealBound(t *testing.T) {
	b := Binding{Hosts: []string{"uploads.github.com", "API.github.com", "api.github.com"}, Inject: "bearer"}
	blob, err := SealBound(key(1), "secret.GH", []byte("ghp_x"), b)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("ghp_x")) || !LooksSealed(blob) {
		t.Fatal("not sealed")
	}
	want := `{"hosts":["api.github.com","uploads.github.com"],"inject":"bearer"}`
	if !bytes.Contains(blob, []byte(want)) {
		t.Errorf("binding not canonical in %q", blob)
	}
	if p, bound, err := Peek(blob); err != nil || !bound || strings.Join(p.Hosts, ",") != "api.github.com,uploads.github.com" || p.Inject != "bearer" {
		t.Errorf("peek %+v %v %v", p, bound, err)
	}
	v, got, bound, err := OpenBound(key(1), "secret.GH", blob)
	if err != nil || !bound || string(v) != "ghp_x" || len(got.Hosts) != 2 {
		t.Fatalf("%q %+v %v %v", v, got, bound, err)
	}
	if v, err := Open(key(1), "secret.GH", blob); err != nil || string(v) != "ghp_x" {
		t.Errorf("Open: %q %v", v, err)
	}
	if _, err := Open(key(1), "secret.OTHER", blob); err == nil {
		t.Error("opened under another reference")
	}
	// the binding rewritten in clear (another host of the same length): the entry no longer opens
	evil := bytes.Replace(blob, []byte("uploads.github.com"), []byte("uploads.evilhub.io"), 1)
	if _, bound, err := Peek(evil); err != nil || !bound {
		t.Fatalf("the rewritten binding should still parse: %v", err)
	}
	if _, err := Open(key(1), "secret.GH", evil); err == nil {
		t.Error("opened with a rewritten binding")
	}
	// a binding that is not in canonical form is refused before any key is tried
	shuffled := bytes.Replace(blob, []byte(`"api.github.com","uploads.github.com"`), []byte(`"uploads.github.com","api.github.com"`), 1)
	if _, _, err := Peek(shuffled); err == nil || LooksSealed(shuffled) {
		t.Error("a non-canonical binding read")
	}
	// one binding has one encoding: the same binding spaced differently is refused
	raw := []byte(want)
	spaced := []byte(`{"hosts": ["api.github.com","uploads.github.com"],"inject":"bearer"}`)
	respaced := append(append(binary.BigEndian.AppendUint16([]byte(magic2), uint16(len(spaced))), spaced...), blob[len(magic2)+2+len(raw):]...)
	if _, _, err := Peek(respaced); err == nil {
		t.Error("a non-canonical encoding read")
	}
	big := append(binary.BigEndian.AppendUint16([]byte(magic2), maxBinding+1), bytes.Repeat([]byte(" "), maxBinding+64)...)
	if _, _, err := Peek(big); err == nil || !strings.Contains(err.Error(), "length") {
		t.Errorf("an oversized binding: %v", err)
	}
	for name, bad := range map[string][]byte{
		"short":     []byte(magic2),
		"long len":  append([]byte(magic2), 0xff, 0xff),
		"unknown":   append(append([]byte(magic2), 0, 11), `{"x":true}`...),
		"truncated": blob[:len(blob)-20],
	} {
		if _, err := Open(key(1), "secret.GH", bad); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	// the first form carries no binding
	old, _ := Seal(key(1), "secret.GH", []byte("v"))
	if _, bound, err := Peek(old); err != nil || bound {
		t.Errorf("first form: %v %v", bound, err)
	}
	if _, _, bound, err := OpenBound(key(1), "secret.GH", old); err != nil || bound {
		t.Errorf("first form open: %v %v", bound, err)
	}
	// the zero binding is a withheld secret, sealed as such
	w, err := SealBound(key(1), "secret.W", []byte("v"), Binding{})
	if p, bound, _ := Peek(w); err != nil || !bound || len(p.Hosts) != 0 || p.Readable {
		t.Errorf("withheld: %+v %v", p, err)
	}
}

func TestBindingRules(t *testing.T) {
	for _, c := range []struct {
		b  Binding
		ok bool
	}{
		{Binding{}, true},
		{Binding{Readable: true}, true},
		{Binding{Hosts: []string{"api.x.com"}, Inject: "header:X-Api-Key"}, true},
		{Binding{Hosts: []string{"api.x.com"}, Inject: "query:token"}, true},
		{Binding{Hosts: []string{"api.x.com"}, Inject: "basic"}, true},
		{Binding{Hosts: []string{"api.x.com"}}, false},
		{Binding{Inject: "bearer"}, false},
		{Binding{Hosts: []string{"api.x.com"}, Inject: "bearer", Readable: true}, false},
		{Binding{Hosts: []string{"*.x.com"}, Inject: "bearer"}, false},
		{Binding{Hosts: []string{"localhost"}, Inject: "bearer"}, false},
		{Binding{Hosts: []string{"a..b"}, Inject: "bearer"}, false},
		{Binding{Hosts: []string{"api.x.com"}, Inject: "cookie"}, false},
		{Binding{Hosts: []string{"api.x.com"}, Inject: "header:a b"}, false},
		{Binding{Hosts: strings.Split("a.x,b.x,c.x,d.x,e.x,f.x,g.x,h.x,i.x,j.x,k.x,l.x,m.x,n.x,o.x,p.x,q.x", ","), Inject: "bearer"}, false},
	} {
		if err := c.b.Canonical().Validate(); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c.b, err)
		}
		if _, err := SealBound(key(1), "secret.T", nil, c.b); (err == nil) != c.ok {
			t.Errorf("seal %+v: %v", c.b, err)
		}
	}
	if err := (Binding{Hosts: []string{"b.x", "a.x"}, Inject: "bearer"}).Validate(); err == nil {
		t.Error("unsorted hosts valid")
	}
	if err := (Binding{Hosts: []string{"a.x", "a.x"}, Inject: "bearer"}).Validate(); err == nil {
		t.Error("repeated hosts valid")
	}
	b := Binding{Hosts: []string{"a.x.com", "b.x.com"}, Inject: "bearer"}
	for _, c := range []struct {
		hosts    []string
		inject   string
		readable bool
		ok       bool
	}{
		{[]string{"a.x.com"}, "bearer", false, true},
		{[]string{"B.X.com", "a.x.com"}, "bearer", false, true},
		{[]string{"c.x.com"}, "bearer", false, false},
		{[]string{"a.x.com", "c.x.com"}, "bearer", false, false},
		{[]string{"a.x.com"}, "basic", false, false},
		{nil, "bearer", false, false},
		{nil, "", true, false},
	} {
		if err := b.Allows(c.hosts, c.inject, c.readable); (err == nil) != c.ok {
			t.Errorf("Allows(%v, %q, %v): %v", c.hosts, c.inject, c.readable, err)
		}
	}
	if (Binding{Readable: true}).Allows(nil, "", true) != nil || (Binding{Readable: true}).Allows([]string{"a.x.com"}, "bearer", false) == nil {
		t.Error("readable")
	}
	if (Binding{}).Allows([]string{"a.x.com"}, "", false) == nil {
		t.Error("withheld allows")
	}
}
