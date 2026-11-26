//go:build !linux && !darwin

package attachclient

import "errors"

// HungUp is the status Attach returns when the client's own connection went away.
const HungUp = 129

// Attach needs a Unix terminal.
func Attach(string, string, []string) (int, error) {
	return 1, errors.New("attach needs a Unix terminal")
}
