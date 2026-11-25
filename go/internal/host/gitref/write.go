package gitref

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"strings"
)

// ObjectID is git's id of an object of kind with body content.
func (r *Repo) ObjectID(kind string, body []byte) string {
	var h hash.Hash = sha1.New()
	if r.HashLen == 64 {
		h = sha256.New()
	}
	fmt.Fprintf(h, "%s %d\x00", kind, len(body))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// mkdirNoLinks creates dir (under base, which must exist) one component at a time, refusing a
// symlink at any step.
func mkdirNoLinks(base, rel string) (string, error) {
	p := base
	for _, c := range strings.Split(filepath.ToSlash(rel), "/") {
		if c == "" || c == "." || c == ".." {
			return "", fmt.Errorf("bad path component in %q", rel)
		}
		p = filepath.Join(p, c)
		st, err := os.Lstat(p)
		switch {
		case errors.Is(err, os.ErrNotExist):
			if err := os.Mkdir(p, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
				return "", err
			}
			if st, err = os.Lstat(p); err != nil {
				return "", err
			}
			fallthrough
		case err == nil:
			if !st.IsDir() {
				return "", fmt.Errorf("%s is not a directory", p)
			}
		default:
			return "", err
		}
	}
	return p, nil
}

// TagHeader is how a tag object for commit and name must begin.
func TagHeader(commit, name string) string {
	return "object " + commit + "\ntype commit\ntag " + name + "\ntagger "
}

// WriteTag stores tag (the exact bytes `git mktag` was given and verified in the VM) as a loose
// object and points refs/tags/<name> at it, as design 5.1.3 step 5 has the host do. The tag must
// name commit, which the caller has checked against Head. A ref already pointing at the same
// object is success; pointing anywhere else is an error, never an overwrite.
func (r *Repo) WriteTag(tag []byte, name, commit string) (string, error) {
	if !r.validHash(commit) {
		return "", errors.New("invalid commit id")
	}
	ref := "refs/tags/" + name
	if !validRef(ref) {
		return "", fmt.Errorf("invalid tag name %q", name)
	}
	if !bytes.HasPrefix(tag, []byte(TagHeader(commit, name))) {
		return "", errors.New("the tag object does not name this commit and tag")
	}
	id := r.ObjectID("tag", tag)
	if err := r.writeObject(id, "tag", tag); err != nil {
		return "", err
	}
	return id, r.writeRef(ref, id)
}

func (r *Repo) writeObject(id, kind string, body []byte) error {
	dir, err := mkdirNoLinks(r.CommonDir, "objects/"+id[:2])
	if err != nil {
		return err
	}
	final := filepath.Join(dir, id[2:])
	if st, err := os.Lstat(final); err == nil {
		if !st.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", final)
		}
		return nil // objects are immutable: the same id is the same content
	}
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	fmt.Fprintf(w, "%s %d\x00", kind, len(body))
	w.Write(body)
	if err := w.Close(); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "tmp_obj_")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(z.Bytes()); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o444); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

// writeRef creates ref with git's lock-file protocol (<ref>.lock created exclusively, then renamed).
func (r *Repo) writeRef(ref, id string) error {
	if cur, err := r.resolveOne(ref); err == nil {
		if cur == id {
			return nil
		}
		return fmt.Errorf("%s already exists and points at %s", ref, cur)
	}
	dir, err := mkdirNoLinks(r.CommonDir, filepath.Dir(ref))
	if err != nil {
		return err
	}
	final := filepath.Join(dir, filepath.Base(ref))
	lock := final + ".lock"
	f, err := os.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("cannot lock %s: %w", ref, err)
	}
	defer os.Remove(lock)
	if _, err := f.WriteString(id + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if _, err := os.Lstat(final); err == nil {
		return fmt.Errorf("%s appeared while it was being written", ref)
	}
	return os.Rename(lock, final)
}
