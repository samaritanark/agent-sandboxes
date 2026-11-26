// Package brokerseal is the broker store's entry format (design 5.9.2, D-32), shared by the host,
// which makes the key and seals entries, and the VM, which stores them and opens them only in the
// short-lived handover helper. An entry is AES-256-GCM under the store key with the credential's
// reference as associated data, so an entry moved under another name does not open. Callers wipe
// what they open (Open returns a []byte for that reason). Standard library only: the host binary
// depends on it.
package brokerseal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// KeySize is the store key's length (AES-256).
const KeySize = 32

const magic = "SBXB1"

// MinSealed is the length of the shortest entry (an empty value).
const MinSealed = len(magic) + 12 + 16

var refRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// ValidRef reports whether ref may name a credential.
func ValidRef(ref string) bool { return refRE.MatchString(ref) }

// SecretPrefix begins the reference of an operator secret (`sandbox secret set NAME`), so the
// operator's names cannot collide with the broker's own credentials (agent tokens and the like).
const SecretPrefix = "secret."

// SecretRef is the store reference of operator secret name.
func SecretRef(name string) string { return SecretPrefix + name }

// SecretName is the operator secret a reference names, if it names one.
func SecretName(ref string) (string, bool) {
	n, ok := strings.CutPrefix(ref, SecretPrefix)
	return n, ok && n != ""
}

// NewKey makes a store key.
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

func aead(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("brokerseal: the key must be 32 bytes")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func ad(ref string) []byte { return []byte("sandbox-broker-v1:" + ref) }

// Seal encrypts value as ref's entry.
func Seal(key []byte, ref string, value []byte) ([]byte, error) {
	if !ValidRef(ref) {
		return nil, fmt.Errorf("brokerseal: invalid reference %q", ref)
	}
	g, err := aead(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte(magic), nonce...)
	return g.Seal(out, nonce, value, ad(ref)), nil
}

// Open decrypts ref's entry. A changed byte, another key, or another reference fails.
func Open(key []byte, ref string, blob []byte) ([]byte, error) {
	g, err := aead(key)
	if err != nil {
		return nil, err
	}
	n := len(magic) + g.NonceSize()
	if !LooksSealed(blob) {
		return nil, fmt.Errorf("brokerseal: %s is not a store entry", ref)
	}
	v, err := g.Open(nil, blob[len(magic):n], blob[n:], ad(ref))
	if err != nil {
		return nil, fmt.Errorf("brokerseal: %s does not open with this key", ref)
	}
	return v, nil
}

// LooksSealed reports whether blob has an entry's shape (it says nothing about the key).
func LooksSealed(blob []byte) bool {
	return len(blob) >= MinSealed && string(blob[:len(magic)]) == magic
}

// Wipe zeroes a buffer that held a key or a value.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
