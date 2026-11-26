package brokerkey

import "io/fs"

// Windows keeps the key in Credential Manager; a file keeper there is only for tests.
func permsOpen(fs.FileInfo) bool { return false }
