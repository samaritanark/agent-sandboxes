// Package brokerstore is the broker's credential store in the VM (design 5.9.2, D-32): one file
// per credential under /var/lib/sandbox/broker/, sealed with AES-256-GCM under a key that lives in
// the operator's host keychain and reaches the VM only in memory. The credential's reference is the
// associated data, so an entry moved under another name does not open. Nothing here keeps a key or
// a value; callers wipe what they open (Open returns a []byte for that reason).
package brokerstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Dir is where the store lives in the VM.
const Dir = "/var/lib/sandbox/broker"

// KeySize is the store key's length (AES-256).
const KeySize = 32

const magic = "SBXB1"

var refRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func aead(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("brokerstore: the key must be 32 bytes")
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
	if !refRE.MatchString(ref) {
		return nil, fmt.Errorf("brokerstore: invalid reference %q", ref)
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
	if len(blob) < n+g.Overhead() || string(blob[:len(magic)]) != magic {
		return nil, fmt.Errorf("brokerstore: %s is not a store entry", ref)
	}
	v, err := g.Open(nil, blob[len(magic):n], blob[n:], ad(ref))
	if err != nil {
		return nil, fmt.Errorf("brokerstore: %s does not open with this key", ref)
	}
	return v, nil
}

// Store is the directory of entries.
type Store struct{ Dir string }

func (s Store) path(ref string) (string, error) {
	if !refRE.MatchString(ref) {
		return "", fmt.Errorf("brokerstore: invalid reference %q", ref)
	}
	return filepath.Join(s.Dir, ref+".sealed"), nil
}

// Put stores an entry already sealed (the host seals; the VM never sees the plaintext to store it).
// The entry must at least look like one.
func (s Store) Put(ref string, sealed []byte) error {
	p, err := s.path(ref)
	if err != nil {
		return err
	}
	if len(sealed) < len(magic)+12+16 || string(sealed[:len(magic)]) != magic {
		return errors.New("brokerstore: not a sealed entry")
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Get reads ref's sealed entry.
func (s Store) Get(ref string) ([]byte, error) {
	p, err := s.path(ref)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

// Delete removes ref's entry; a missing one is not an error.
func (s Store) Delete(ref string) error {
	p, err := s.path(ref)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// List names the stored references.
func (s Store) List() ([]string, error) {
	ents, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if ref, ok := strings.CutSuffix(e.Name(), ".sealed"); ok && refRE.MatchString(ref) && e.Type().IsRegular() {
			out = append(out, ref)
		}
	}
	return out, nil
}

// Wipe zeroes a buffer that held a key or a value.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
