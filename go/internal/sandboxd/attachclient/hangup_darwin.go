package attachclient

import "os"

// waitHangup never returns on macOS, where sandboxd only builds for development.
func waitHangup(*os.File) { select {} }
