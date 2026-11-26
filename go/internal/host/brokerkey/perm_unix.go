//go:build !windows

package brokerkey

import "io/fs"

func permsOpen(st fs.FileInfo) bool { return st.Mode().Perm()&0o077 != 0 }
