package syncgate

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/yamllist"
)

// The team overlay's additions to the exec-vector list (rule 2; OQ-07, owner decision 2026-11-27):
// an overlay may add paths whose VM-origin changes are held for `sandbox sync review`, never
// remove a built-in one. The host reads them itself, from the overlay on the host, like
// masked_paths: (RepoMaskedPaths), so the VM cannot change the list it is held to.

// OverlayExecVectors is the exec_vectors: list of the operator's overlay: the overlay named by
// SANDBOX_OVERLAY, else by overlay: in the user config (USER_SANDBOX_CONFIG, else
// ~/.sandbox/config.yaml), the policy layer's resolve_overlay_path. No overlay, or an overlay with
// no config.yaml, is an empty list; a config.yaml that cannot be read is an error, so the caller
// fails closed.
func OverlayExecVectors(home string, getenv func(string) string) ([]string, error) {
	ov := getenv("SANDBOX_OVERLAY")
	if ov == "" {
		uc := getenv("USER_SANDBOX_CONFIG")
		if uc == "" {
			uc = filepath.Join(home, ".sandbox", "config.yaml")
		}
		b, err := readSmall(uc)
		if err != nil {
			return nil, err
		}
		ov = yamlScalar(b, "overlay")
	}
	if ov == "" {
		return nil, nil
	}
	if strings.HasPrefix(ov, "~") {
		ov = home + ov[1:]
	}
	b, err := readSmall(filepath.Join(ov, "config.yaml"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range yamllist.Extract(b, "exec_vectors", false) {
		if e = strings.Trim(e, "/ \t"); e != "" {
			out = append(out, e)
		}
	}
	return out, nil
}

// readSmall reads a configuration file of at most 1 MiB; a missing one is empty.
func readSmall(p string) ([]byte, error) {
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	const max = 1 << 20
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", p, max)
	}
	return b, nil
}

var (
	scalarTrailComment = regexp.MustCompile(`[[:space:]]+#.*$`)
)

// yamlScalar is extract_yaml_scalar_from_file on data: the value of the first top-level
// "<key>:" line, an inline " # comment" and every quote character removed, trimmed.
func yamlScalar(data []byte, key string) string {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if !strings.HasPrefix(line, key+":") {
			continue
		}
		v := strings.TrimLeft(line[len(key)+1:], " \t")
		if loc := scalarTrailComment.FindStringIndex(v); loc != nil {
			v = v[:loc[0]]
		}
		v = strings.NewReplacer(`"`, "", `'`, "").Replace(v)
		return strings.Trim(v, " \t")
	}
	return ""
}

// overlayExec reports whether a path is under one of the overlay's exec vectors: a bare name is
// a file or directory of that name at any depth; a name with a slash is that path from the
// repository root, and everything under it.
func overlayExec(keys []string, h Host, vectors []string) bool {
	for _, v := range vectors {
		parts := strings.Split(v, "/")
		if len(parts) == 1 {
			for _, k := range keys {
				if k == h.key(v) {
					return true
				}
			}
			continue
		}
		if len(parts) > len(keys) {
			continue
		}
		match := true
		for i, p := range parts {
			if keys[i] != h.key(p) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
