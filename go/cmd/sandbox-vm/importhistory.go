package main

// The VM half of the v2 history import (design 11, step 12): `sandbox __import-history AGENT TIER
// KEY` reads a tar of an agent's conversation history from the host and adds it to the agent's
// history for that tier and repository set (cli: AgentHistoryStore/<agent>/tier<N>/<key>). Only
// directories and regular files are taken, each beneath the history directory (an os.Root: no path
// or link leaves it), owned by the agent's user; a file already there is kept, so the import can
// run again.

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"
)

// Import limits.
const (
	maxImportFile  = 256 << 20
	maxImportTotal = 4 << 30
)

// importHistory adds the tar on r to agent's history and returns how many files it wrote.
func importHistory(historyStore, agent, tierArg, key string, uid int, r io.Reader) (int, error) {
	tier, err := strconv.Atoi(tierArg)
	if err != nil {
		return 0, fmt.Errorf("bad tier %q", tierArg)
	}
	dir, err := historyDir(historyStore, agent, tier, key, uid)
	if err != nil {
		return 0, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	tr := tar.NewReader(r)
	var total int64
	n := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		if name == "." || strings.HasPrefix(name, "/") || name == ".." || strings.HasPrefix(name, "../") || strings.ContainsRune(name, 0) {
			return n, fmt.Errorf("refused entry %q", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := mkdirAllOwned(root, name, uid); err != nil {
				return n, err
			}
		case tar.TypeReg:
			if h.Size < 0 || h.Size > maxImportFile || total+h.Size > maxImportTotal {
				return n, fmt.Errorf("%s: too large", h.Name)
			}
			total += h.Size
			if d := path.Dir(name); d != "." {
				if err := mkdirAllOwned(root, d, uid); err != nil {
					return n, err
				}
			}
			f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if errors.Is(err, fs.ErrExist) {
				continue // kept: the import may run again
			}
			if err != nil {
				return n, err
			}
			_, err = io.Copy(f, io.LimitReader(tr, h.Size))
			if err == nil {
				err = f.Chown(uid, -1)
			}
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return n, err
			}
			n++
		default:
			// links, devices, and the rest are not history
		}
	}
}

// mkdirAllOwned makes dir (and its parents) beneath root, each new one owned by uid.
func mkdirAllOwned(root *os.Root, dir string, uid int) error {
	parts := strings.Split(dir, "/")
	for i := range parts {
		p := strings.Join(parts[:i+1], "/")
		err := root.Mkdir(p, 0o700)
		if err == nil {
			if err := root.Lchown(p, uid, -1); err != nil {
				return err
			}
			continue
		}
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
		if st, err := root.Lstat(p); err != nil || !st.IsDir() {
			return fmt.Errorf("%s is not a directory", p)
		}
	}
	return nil
}
