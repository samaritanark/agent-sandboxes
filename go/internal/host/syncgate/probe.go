package syncgate

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ProbeHost finds out how the file system holding dir matches names: it creates a temporary file
// whose name has an upper-case letter and a precomposed é, and checks whether the lower-case and
// the decomposed spellings find it. On failure it assumes the most aliasing (safe for the gate).
func ProbeHost(dir string) Host {
	h := Host{Windows: runtime.GOOS == "windows"}
	f, err := os.CreateTemp(dir, ".sandbox-probe-Qé-")
	if err != nil {
		return Host{CaseInsensitive: true, NormInsensitive: true, Windows: h.Windows}
	}
	name := f.Name()
	f.Close()
	defer os.Remove(name)
	base := filepath.Base(name)
	lower := strings.Replace(base, "Q", "q", 1)
	decomposed := strings.Replace(base, "é", "é", 1)
	if _, err := os.Stat(filepath.Join(dir, lower)); err == nil {
		h.CaseInsensitive = true
	}
	if _, err := os.Stat(filepath.Join(dir, decomposed)); err == nil {
		h.NormInsensitive = true
	}
	return h
}
