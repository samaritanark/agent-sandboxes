//go:build windows

package syncproto

import "io/fs"

func fileIdent(st fs.FileInfo) uint64 { return 0 }

// identKnown says fileIdent sees the inode and change time; here it does not, so a cache is
// kept for one run only.
const identKnown = false
