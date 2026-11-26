//go:build !darwin && !windows

package brokerkey

import "path/filepath"

// Default is a 0600 file in the state directory: headless Linux has no keychain the host binary
// can rely on (design 5.9.2), and doctor says so.
func Default(stateDir string) Keeper { return File{Path: filepath.Join(stateDir, "broker.key")} }
