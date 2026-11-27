//go:build !windows

package syncproto

import (
	"io/fs"
	"syscall"
)

// fileIdent is the file's inode (and change time), so a replaced file never matches the cache.
func fileIdent(st fs.FileInfo) uint64 {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return uint64(s.Ino)*1_000_003 ^ uint64(ctimeNs(s))
	}
	return 0
}

// identKnown says fileIdent sees the inode and change time, so a saved cache can be trusted.
const identKnown = true
