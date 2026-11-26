package app

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// removeAll is os.RemoveAll, then, if that fails, again after clearing the file flags (uchg) that
// macOS keeps on some files (git pack files under v2's agent homes and overlays carry it), which
// the owner may clear and which otherwise stop the removal partway.
func removeAll(p string) error {
	err := os.RemoveAll(p)
	if err == nil {
		return nil
	}
	filepath.WalkDir(p, func(q string, d fs.DirEntry, err error) error {
		if err == nil {
			syscall.Chflags(q, 0)
		}
		return nil
	})
	syscall.Chflags(p, 0)
	return os.RemoveAll(p)
}
