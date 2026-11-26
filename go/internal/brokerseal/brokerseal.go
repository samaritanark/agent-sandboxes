// Package brokerseal is the broker store's entry format (design 5.9.2, D-32), shared by the host,
// which makes the key and seals entries, and the VM, which stores them and opens them only in the
// short-lived handover helper. An entry is AES-256-GCM under the store key with the credential's
// reference as associated data, so an entry moved under another name does not open. Callers wipe
// what they open (Open returns a []byte for that reason). Standard library only: the host binary
// depends on it.
package brokerseal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
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

// ad2 is the second form's associated data: the reference and the binding's encoding.
func ad2(ref string, binding []byte) []byte {
	return append([]byte("sandbox-broker-v2:"+ref+"\x00"), binding...)
}

// The second form (owner decision, 2026-11-26, ninth round): an operator secret's entry carries
// its binding, in clear so the VM can plan a launch without the key, and authenticated with the
// value, so an entry opens only with the binding the host sealed. magic2, a 2-byte big-endian
// length, the binding's canonical JSON, then the nonce and the ciphertext as in the first form.
const magic2 = "SBXB2"

// maxBinding bounds a binding's encoding.
const maxBinding = 4096

// Binding is what the operator allowed a secret (`sandbox secret set NAME --bind HOST --inject
// KIND`, or `--allow-readable`): the hosts the broker may send it to and how, or that the agent may
// read it. Neither (the zero Binding) means the secret is withheld from every session.
type Binding struct {
	Hosts    []string `json:"hosts,omitempty"`
	Inject   string   `json:"inject,omitempty"`
	Readable bool     `json:"readable,omitempty"`
}

var (
	injectRE = regexp.MustCompile(`^(bearer|basic|header:[A-Za-z0-9-]{1,64}|query:[A-Za-z0-9_.-]{1,64})$`)
	labelRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// MaxHosts bounds a binding's hosts.
const MaxHosts = 16

// ValidHost reports whether h is one exact lower-case DNS name with at least two labels.
func ValidHost(h string) bool {
	if len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if !labelRE.MatchString(l) {
			return false
		}
	}
	return true
}

// ValidInject reports whether k is an injection the broker knows.
func ValidInject(k string) bool { return injectRE.MatchString(k) }

// Canonical is b with its hosts lower-cased, sorted, and without repeats.
func (b Binding) Canonical() Binding {
	var hs []string
	for _, h := range b.Hosts {
		hs = append(hs, strings.ToLower(h))
	}
	slices.Sort(hs)
	b.Hosts = slices.Compact(hs)
	return b
}

// Validate checks a canonical binding: exact hosts and an injection together, or readable alone.
func (b Binding) Validate() error {
	switch {
	case b.Readable && (len(b.Hosts) > 0 || b.Inject != ""):
		return errors.New("a secret the agent may read is not also brokered")
	case len(b.Hosts) > MaxHosts:
		return fmt.Errorf("more than %d hosts", MaxHosts)
	case (len(b.Hosts) == 0) != (b.Inject == ""):
		return errors.New("a brokered secret needs both its hosts and its injection")
	case b.Inject != "" && !ValidInject(b.Inject):
		return fmt.Errorf("unknown injection %q (bearer, basic, header:NAME, or query:NAME)", b.Inject)
	}
	for i, h := range b.Hosts {
		if !ValidHost(h) {
			return fmt.Errorf("%q is not one exact host name", h)
		}
		if i > 0 && h <= b.Hosts[i-1] {
			return errors.New("the hosts are not in canonical order")
		}
	}
	return nil
}

// Allows checks one use of the secret against its binding: brokered toward hosts (each one the
// binding names) with injection inject, or (hosts nil, inject "") read by the agent.
func (b Binding) Allows(hosts []string, inject string, readable bool) error {
	if readable {
		if !b.Readable {
			return errors.New("the secret is not marked readable (sandbox secret set NAME --allow-readable)")
		}
		return nil
	}
	if len(b.Hosts) == 0 {
		return errors.New("the secret is bound to no host (sandbox secret set NAME --bind HOST)")
	}
	if len(hosts) == 0 || inject != b.Inject {
		return fmt.Errorf("the secret is bound with injection %q, not %q", b.Inject, inject)
	}
	for _, h := range hosts {
		if !slices.Contains(b.Hosts, strings.ToLower(h)) {
			return fmt.Errorf("the secret is not bound to %s", h)
		}
	}
	return nil
}

// header splits a second-form entry: its binding, the binding's encoding, and the rest. The
// encoding must be the binding's canonical one.
func header(blob []byte) (Binding, []byte, []byte, error) {
	rest := blob[len(magic2):]
	if len(rest) < 2 {
		return Binding{}, nil, nil, errors.New("short entry")
	}
	n := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if n > maxBinding || len(rest) < n {
		return Binding{}, nil, nil, errors.New("bad binding length")
	}
	raw := rest[:n]
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b Binding
	if err := dec.Decode(&b); err != nil {
		return Binding{}, nil, nil, fmt.Errorf("bad binding: %w", err)
	}
	if enc, err := json.Marshal(b); err != nil || !bytes.Equal(enc, raw) {
		return Binding{}, nil, nil, errors.New("binding not in canonical form")
	}
	if err := b.Validate(); err != nil {
		return Binding{}, nil, nil, err
	}
	return b, raw, rest[n:], nil
}

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

// SealBound encrypts value as ref's entry of the second form, carrying binding b, which must be
// valid once made canonical.
func SealBound(key []byte, ref string, value []byte, b Binding) ([]byte, error) {
	if !ValidRef(ref) {
		return nil, fmt.Errorf("brokerseal: invalid reference %q", ref)
	}
	b = b.Canonical()
	if err := b.Validate(); err != nil {
		return nil, fmt.Errorf("brokerseal: %s: %w", ref, err)
	}
	raw, err := json.Marshal(b)
	if err != nil || len(raw) > maxBinding {
		return nil, fmt.Errorf("brokerseal: %s: the binding is too large", ref)
	}
	g, err := aead(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := binary.BigEndian.AppendUint16([]byte(magic2), uint16(len(raw)))
	out = append(append(out, raw...), nonce...)
	return g.Seal(out, nonce, value, ad2(ref, raw)), nil
}

// Open decrypts ref's entry, either form. A changed byte, another key, or another reference fails.
func Open(key []byte, ref string, blob []byte) ([]byte, error) {
	v, _, _, err := OpenBound(key, ref, blob)
	return v, err
}

// OpenBound decrypts ref's entry and returns the binding sealed with it (bound is false for an
// entry of the first form, which carries none).
func OpenBound(key []byte, ref string, blob []byte) (v []byte, b Binding, bound bool, err error) {
	g, err := aead(key)
	if err != nil {
		return nil, Binding{}, false, err
	}
	if !LooksSealed(blob) {
		return nil, Binding{}, false, fmt.Errorf("brokerseal: %s is not a store entry", ref)
	}
	body, data := blob[len(magic):], ad(ref)
	if bytes.HasPrefix(blob, []byte(magic2)) {
		var raw []byte
		if b, raw, body, err = header(blob); err != nil {
			return nil, Binding{}, false, fmt.Errorf("brokerseal: %s: %w", ref, err)
		}
		bound, data = true, ad2(ref, raw)
	}
	n := g.NonceSize()
	if len(body) < n+g.Overhead() {
		return nil, Binding{}, false, fmt.Errorf("brokerseal: %s is not a store entry", ref)
	}
	v, err = g.Open(nil, body[:n], body[n:], data)
	if err != nil {
		return nil, Binding{}, false, fmt.Errorf("brokerseal: %s does not open with this key", ref)
	}
	return v, b, bound, nil
}

// LooksSealed reports whether blob has an entry's shape, either form (it says nothing about the
// key).
func LooksSealed(blob []byte) bool {
	if bytes.HasPrefix(blob, []byte(magic2)) {
		_, _, body, err := header(blob)
		return err == nil && len(body) >= 12+16
	}
	return len(blob) >= MinSealed && string(blob[:len(magic)]) == magic
}

// Peek reads the binding an entry of the second form carries, without the key: for showing and
// planning only, as nothing checks it until the entry is opened.
func Peek(blob []byte) (b Binding, bound bool, err error) {
	if !bytes.HasPrefix(blob, []byte(magic2)) {
		if !LooksSealed(blob) {
			return Binding{}, false, errors.New("brokerseal: not a store entry")
		}
		return Binding{}, false, nil
	}
	b, _, _, err = header(blob)
	return b, err == nil, err
}

// Wipe zeroes a buffer that held a key or a value.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
