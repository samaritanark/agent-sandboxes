//go:build !darwin

package app

import "os"

// removeAll is os.RemoveAll (remove_darwin.go clears macOS file flags first when it must).
func removeAll(p string) error { return os.RemoveAll(p) }
