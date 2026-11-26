// Package brokerstore is the broker's credential store in the VM (design 5.9.2, D-32): one file
// per credential under /var/lib/sandbox/broker/, sealed with AES-256-GCM under a key that lives in
// the operator's host keychain and reaches the VM only in memory. The entry format is package
// brokerseal's. Nothing here keeps a key or a value.
package brokerstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
)

// Dir is where the store lives in the VM.
const Dir = "/var/lib/sandbox/broker"

// KeySize is the store key's length (AES-256).
const KeySize = brokerseal.KeySize

// Seal, Open, and Wipe are the entry format's (package brokerseal), which the host shares.
var (
	Seal = brokerseal.Seal
	Open = brokerseal.Open
	Wipe = brokerseal.Wipe
)

// Store is the directory of entries.
type Store struct{ Dir string }

func (s Store) path(ref string) (string, error) {
	if !brokerseal.ValidRef(ref) {
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
	if !brokerseal.LooksSealed(sealed) {
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
		if ref, ok := strings.CutSuffix(e.Name(), ".sealed"); ok && brokerseal.ValidRef(ref) && e.Type().IsRegular() {
			out = append(out, ref)
		}
	}
	return out, nil
}
