package sshx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// KeyPair is an ed25519 key in OpenSSH format.
type KeyPair struct {
	Private string
	Public  string // one line, "ssh-ed25519 AAAA... comment"
}

// GenerateKey runs ssh-keygen into a private temporary directory and returns the pair; nothing is
// left on disk. The comment must be one plain word.
func GenerateKey(ctx context.Context, keygen, comment string) (KeyPair, error) {
	if comment == "" || strings.ContainsAny(comment, " \t\r\n") {
		return KeyPair{}, errors.New("key comment must be one word")
	}
	dir, err := os.MkdirTemp("", "sandbox-key-")
	if err != nil {
		return KeyPair{}, err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return KeyPair{}, err
	}
	p := filepath.Join(dir, "key")
	out, err := exec.CommandContext(ctx, keygen, "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", p).CombinedOutput()
	if err != nil {
		return KeyPair{}, fmt.Errorf("ssh-keygen: %v: %s", err, strings.TrimSpace(string(out)))
	}
	priv, err := os.ReadFile(p)
	if err != nil {
		return KeyPair{}, err
	}
	pub, err := os.ReadFile(p + ".pub")
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{Private: string(priv), Public: strings.TrimSpace(string(pub))}, nil
}

// DefaultKeygen is ssh-keygen beside the ssh client.
func DefaultKeygen(ssh string) string {
	dir, base := filepath.Split(ssh)
	return filepath.Join(dir, strings.Replace(base, "ssh", "ssh-keygen", 1))
}
