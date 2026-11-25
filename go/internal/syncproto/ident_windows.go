//go:build windows

package syncproto

import "io/fs"

func fileIdent(st fs.FileInfo) uint64 { return 0 }
