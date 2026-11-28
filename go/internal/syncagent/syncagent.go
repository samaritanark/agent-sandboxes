// Package syncagent is the in-VM side of the sync engine: it serves syncproto requests on one
// workspace copy, confined to it with os.Root, until its input ends. It runs in the VM as the
// sync user (design 5.6.2 rule 5) and is never reachable from a microVM. It decides nothing about
// policy: the host engine and gate do. Host-to-VM changes carry the fingerprint the host last
// synced, and a path that changed in the VM since is reported as a conflict, not overwritten.
package syncagent

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/syncproto"
)

// Serve answers requests from r on w for the tree at dir.
func Serve(dir string, r io.Reader, w io.Writer) error {
	return ServeCached(dir, "", r, w)
}

// cacheSaveEvery is how often the fingerprint cache is written while a session runs (and at its end).
const cacheSaveEvery = 30 * time.Second

// ServeCached is Serve with the fingerprint cache kept in cacheFile across runs, so a launch's
// scan reads only the files that changed since the last one. cacheFile must be out of the tree's
// reach (the agent in the microVM sees only dir); "" keeps the cache for this run only.
func ServeCached(dir, cacheFile string, r io.Reader, w io.Writer) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	cache := &syncproto.FPCache{}
	parts := &partial{}
	defer parts.drop(root)
	var saved time.Time
	if cacheFile != "" {
		cache.LoadFile(cacheFile)
		defer func() { cache.SaveFile(cacheFile) }() // failing costs only time
	}
	for {
		h, body, err := syncproto.Read(r)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		reply, rbody := handle(root, cache, parts, h, body)
		if err := syncproto.Write(w, reply, rbody); err != nil {
			return err
		}
		if cacheFile != "" && h.Op == syncproto.OpScan && reply.Err == "" && time.Since(saved) >= cacheSaveEvery {
			if cache.SaveFile(cacheFile) == nil {
				saved = time.Now()
			}
		}
	}
}

func validPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) || strings.ContainsRune(p, '\\') {
		return false
	}
	for _, c := range strings.Split(p, "/") {
		if c == "" || c == "." || c == ".." {
			return false
		}
	}
	return true
}

// fingerprint of p, not following a final symlink; data is the file's bytes when it is a file.
func fingerprint(root *os.Root, p string) (string, []byte, error) {
	st, err := root.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	switch {
	case st.Mode()&fs.ModeSymlink != 0:
		t, err := root.Readlink(p)
		return syncproto.Fingerprint("link", nil, false, t), nil, err
	case st.IsDir():
		return "dir", nil, nil
	case st.Mode().IsRegular():
		if st.Size() > syncproto.MaxBody {
			// fingerprinted without being held; never sent to the host (OpRead says TooLarge)
			f, err := root.Open(p)
			if err != nil {
				return "", nil, err
			}
			defer f.Close()
			fp, _, err := syncproto.FingerprintReader(f, st.Mode()&0o111 != 0)
			return fp, nil, err
		}
		b, err := root.ReadFile(p)
		return syncproto.Fingerprint("file", b, st.Mode()&0o111 != 0, ""), b, err
	}
	return "other", nil, nil
}

func handle(root *os.Root, cache *syncproto.FPCache, parts *partial, h syncproto.Header, body []byte) (syncproto.Header, []byte) {
	fail := func(f string, a ...interface{}) (syncproto.Header, []byte) {
		return syncproto.Header{Err: fmt.Sprintf(f, a...)}, nil
	}
	if h.Op == syncproto.OpScan {
		entries, err := scan(root, cache, h.Large)
		if err != nil {
			return fail("scan: %v", err)
		}
		return syncproto.Header{Entries: entries}, nil
	}
	if !validPath(h.Path) {
		return fail("invalid path %q", h.Path)
	}
	if h.Op == syncproto.OpWritePart {
		return parts.write(root, h, body)
	}
	cur, data, err := fingerprint(root, h.Path)
	if err != nil {
		return fail("%v", err)
	}
	switch h.Op {
	case syncproto.OpRead:
		r := syncproto.Header{FP: cur}
		if strings.HasPrefix(cur, "link:") {
			r.Target = strings.TrimPrefix(cur, "link:")
		}
		if strings.HasPrefix(cur, "file:") && data == nil {
			r.TooLarge = true // larger than a message: the host's gate would refuse it anyway
		}
		return r, data
	case syncproto.OpWrite, syncproto.OpSymlink, syncproto.OpDelete:
		if cur != h.Base {
			return syncproto.Header{Conflict: true, FP: cur}, nil
		}
		if err := apply(root, h, body, cur); err != nil {
			return fail("%s %s: %v", h.Op, h.Path, err)
		}
		fp, _, _ := fingerprint(root, h.Path)
		return syncproto.Header{FP: fp}, nil
	}
	return fail("unknown operation %q", h.Op)
}

// apply makes one change: parents as plain directories (a symlinked parent is refused), contents
// through a temporary file renamed into place.
func apply(root *os.Root, h syncproto.Header, body []byte, cur string) error {
	if err := plainParents(root, h.Path); err != nil {
		return err
	}
	if h.Op == syncproto.OpDelete {
		if cur == "dir" {
			return errors.New("refusing to delete a directory")
		}
		err := root.Remove(h.Path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if cur == "dir" {
		return errors.New("a directory is in the way")
	}
	if dir := path.Dir(h.Path); dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path.Join(path.Dir(h.Path), ".sandbox-sync-incoming")
	root.Remove(tmp)
	if h.Op == syncproto.OpSymlink {
		if err := root.Symlink(h.Target, tmp); err != nil {
			return err
		}
	} else {
		mode := fs.FileMode(0o644)
		if h.Exec {
			mode = 0o755
		}
		if err := root.WriteFile(tmp, body, mode); err != nil {
			return err
		}
		if err := root.Chmod(tmp, mode); err != nil {
			return err
		}
	}
	if err := root.Rename(tmp, h.Path); err != nil {
		root.Remove(tmp)
		return err
	}
	return nil
}

// plainParents refuses a path with a parent that exists as anything but a plain directory.
func plainParents(root *os.Root, p string) error {
	parts := strings.Split(p, "/")
	for i := 1; i < len(parts); i++ {
		d := strings.Join(parts[:i], "/")
		st, err := root.Lstat(d)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil || !st.IsDir() {
			return fmt.Errorf("%s is not a plain directory", d)
		}
	}
	return nil
}

// scan lists every file and symlink under the root (directories are implied), sorted. Without
// large, a file larger than MaxBody is "other" (an older host neither sends nor expects it).
func scan(root *os.Root, cache *syncproto.FPCache, large bool) ([]syncproto.Entry, error) {
	var out []syncproto.Entry
	err := fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable: left out
		}
		if p == "." || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(p, ".sandbox-sync-incoming") || strings.HasSuffix(p, largeTmp) {
			return nil
		}
		fp := syncproto.ObjectFP
		if !syncproto.IsObjectPath(p) { // objects are content-addressed: their name is their identity
			// the entry's stat data, which ReadDir took with fstatat on the directory it opened in
			// the root (no symlink followed): a second root.Lstat would resolve the whole path again
			st, err := d.Info()
			if err != nil {
				return nil
			}
			if f, ok := cache.Get(p, st); ok {
				fp = f
			} else {
				if fp, _, err = fingerprint(root, p); err != nil {
					return nil
				}
				cache.Put(p, st, fp)
			}
			if !large && st.Mode().IsRegular() && st.Size() > syncproto.MaxBody {
				fp = "other"
			}
		}
		out = append(out, syncproto.Entry{Path: p, FP: fp})
		if len(out) > syncproto.MaxEntries {
			return errors.New("too many files")
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, err
}
