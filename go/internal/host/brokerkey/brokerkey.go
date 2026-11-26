// Package brokerkey keeps the broker store's key on the host (design 5.9.2, D-32): the macOS
// keychain, Windows Credential Manager, or, where neither exists (headless Linux), a 0600 file
// under ~/.sandbox that `sandbox doctor` reports as weaker. The host makes the key once, pushes it
// to sandboxd at VM start, and seals credentials with it; the VM never writes it to its disk, so
// a stolen or backed-up state disk does not open the store.
package brokerkey

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
)

// ErrNoKey is Load's answer when no key has been made yet.
var ErrNoKey = errors.New("no broker key yet")

// Keeper is one place the key can live.
type Keeper interface {
	Where() string // for messages and doctor, e.g. "the macOS keychain"
	Weak() bool    // a plain file, readable by anything that reads the home directory
	Load() ([]byte, error)
	Save(key []byte) error
}

// Get returns the store key, making and saving one the first time; created reports that. A new
// key is read back before it is used, so a key that did not stick is never pushed.
func Get(k Keeper) (key []byte, created bool, err error) {
	key, err = k.Load()
	switch {
	case err == nil && len(key) == brokerseal.KeySize:
		return key, false, nil
	case err == nil:
		brokerseal.Wipe(key)
		return nil, false, fmt.Errorf("the broker key in %s is damaged", k.Where())
	case !errors.Is(err, ErrNoKey):
		return nil, false, fmt.Errorf("cannot read the broker key from %s: %w", k.Where(), err)
	}
	key, err = brokerseal.NewKey()
	if err != nil {
		return nil, false, err
	}
	if err := k.Save(key); err != nil {
		brokerseal.Wipe(key)
		return nil, false, fmt.Errorf("cannot store the broker key in %s: %w", k.Where(), err)
	}
	back, err := k.Load()
	defer brokerseal.Wipe(back)
	if err != nil || subtle.ConstantTimeCompare(back, key) != 1 {
		brokerseal.Wipe(key)
		return nil, false, fmt.Errorf("the broker key did not stick in %s (%v)", k.Where(), err)
	}
	return key, true, nil
}

// File keeps the key in a 0600 file. Load refuses a file anyone else may read.
type File struct{ Path string }

func (f File) Where() string { return f.Path }
func (f File) Weak() bool    { return true }

func (f File) Load() ([]byte, error) {
	st, err := os.Lstat(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if permsOpen(st) {
		return nil, fmt.Errorf("its mode is %v; it must be readable by you only (chmod 600 %s)", st.Mode().Perm(), f.Path)
	}
	return os.ReadFile(f.Path)
}

func (f File) Save(key []byte) error {
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return err
	}
	tmp := f.Path + ".tmp"
	os.Remove(tmp)
	w, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = w.Write(key)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, f.Path)
}

// Keychain keeps the key as a generic password in a macOS keychain, through /usr/bin/security
// (no cgo). The key is written through `security -i`, which reads the command on its stdin, so the
// key never appears in an argument list; reading it back prints it on security's stdout only. It
// uses the user's default keychain, never a named file: security falls back to the default one,
// silently, when a named file does not exist.
type Keychain struct {
	Account string // the install's state directory, so two homes keep two keys
	Tool    string // empty is /usr/bin/security
}

// KeychainService names the item.
const KeychainService = "agent-sandboxes broker key"

func (k Keychain) tool() string {
	if k.Tool != "" {
		return k.Tool
	}
	return "/usr/bin/security"
}

func (k Keychain) Where() string { return "the macOS keychain" }

func (k Keychain) Weak() bool { return false }

// quotable is what may go inside one of security -i's double-quoted words.
func quotable(s string) bool { return !strings.ContainsAny(s, "\"\\\n\r") }

func (k Keychain) Load() ([]byte, error) {
	args := []string{"find-generic-password", "-a", k.Account, "-s", KeychainService, "-w"}
	var out, errb bytes.Buffer
	cmd := exec.Command(k.tool(), args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	defer brokerseal.Wipe(out.Bytes())
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 44 { // errSecItemNotFound
		return nil, ErrNoKey
	}
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.String()))
	}
	raw := bytes.TrimSpace(out.Bytes())
	key := make([]byte, hex.DecodedLen(len(raw)))
	if _, err := hex.Decode(key, raw); err != nil {
		return nil, errors.New("the keychain item is not a broker key")
	}
	return key, nil
}

func (k Keychain) Save(key []byte) error {
	if !quotable(k.Account) {
		return errors.New("the state directory's path cannot be used as a keychain account")
	}
	line := fmt.Sprintf("add-generic-password -U -a \"%s\" -s \"%s\" -l \"%s\" -w %x", k.Account, KeychainService, KeychainService, key)
	in := []byte(line + "\n")
	defer brokerseal.Wipe(in)
	var errb bytes.Buffer
	cmd := exec.Command(k.tool(), "-q", "-i")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(in), &errb, &errb
	// security -i exits 0 even when its command fails; Get reads the key back to know.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.String()))
	}
	if s := strings.TrimSpace(errb.String()); s != "" {
		return errors.New(s)
	}
	return nil
}
