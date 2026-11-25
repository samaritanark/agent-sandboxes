package syncgate

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

// Applying VM-origin work-tree changes to the host checkout (5.6.2, D-24). Git state under .git
// goes through the ref, index, and object rules instead; a .git path given here is quarantined.

// Op is a change's kind.
type Op int

const (
	OpWrite   Op = iota // a regular file with Data (and Exec)
	OpDelete            // remove a file or symlink
	OpSymlink           // a symlink to Target
)

// Change is one VM-origin change. Base is the host path's fingerprint at the last sync ("" when
// it did not exist then): a host path that no longer matches it changed on both sides.
type Change struct {
	Path   string
	Op     Op
	Data   []byte
	Exec   bool
	Target string
	Base   string
}

// Outcome is what happened to one change.
type Outcome struct {
	Path        string
	Applied     bool
	Quarantined bool
	Reason      string
}

// Applier writes changes into one host repository.
type Applier struct {
	Repo     string // the host work tree
	Host     Host
	Rules    Repo
	MaxFile  int64 // per-file limit (default 64 MiB)
	MaxBatch int64 // per-batch limit (default 512 MiB)
	// Quarantine keeps a withheld change for `sandbox sync review`.
	Quarantine func(c Change, reason string) error
}

// Fingerprint identifies a path's content: "" absent, "file:<sha256>[:x]", "link:<target>",
// "dir", or "other".
func Fingerprint(kind string, data []byte, exec bool, target string) string {
	switch kind {
	case "file":
		s := sha256.Sum256(data)
		f := "file:" + hex.EncodeToString(s[:])
		if exec {
			f += ":x"
		}
		return f
	case "link":
		return "link:" + target
	}
	return kind
}

func (c Change) want() string {
	switch c.Op {
	case OpWrite:
		return Fingerprint("file", c.Data, c.Exec, "")
	case OpSymlink:
		return Fingerprint("link", nil, false, c.Target)
	}
	return ""
}

// current is the host path's fingerprint, read through root without following a final symlink.
func current(root *os.Root, p string, max int64) (string, []byte, error) {
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
		return Fingerprint("link", nil, false, t), nil, err
	case st.IsDir():
		return "dir", nil, nil
	case st.Mode().IsRegular():
		if st.Size() > max {
			return "", nil, fmt.Errorf("host file is larger than %d bytes", max)
		}
		f, err := root.Open(p)
		if err != nil {
			return "", nil, err
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, max+1))
		return Fingerprint("file", b, st.Mode()&0o111 != 0, ""), b, err
	}
	return "other", nil, nil
}

func kindOf(fp string) string {
	k, _, _ := strings.Cut(fp, ":")
	return k
}

// Apply applies a batch. Each change is checked and written on its own (a temporary file renamed
// into place), so an interrupted batch leaves every path either old or new; calling Apply again
// with the same batch resumes it, because a path already holding its new content counts as
// applied. The error is for failures that stop the batch (the repository cannot be opened).
func (a *Applier) Apply(batch []Change) ([]Outcome, error) {
	maxFile, maxBatch := a.MaxFile, a.MaxBatch
	if maxFile == 0 {
		maxFile = 64 << 20
	}
	if maxBatch == 0 {
		maxBatch = 512 << 20
	}
	root, err := os.OpenRoot(a.Repo)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var out []Outcome
	var total int64
	for _, c := range batch {
		o := Outcome{Path: c.Path}
		why := a.check(root, c, maxFile, &total, maxBatch, &o)
		if o.Applied {
			out = append(out, o)
			continue
		}
		if why == "" {
			if err := a.write(root, c); err != nil {
				why = "write failed: " + err.Error()
			} else {
				o.Applied, o.Reason = true, "applied"
			}
		}
		if why != "" {
			o.Reason = why
			if a.Quarantine != nil {
				if err := a.Quarantine(c, why); err != nil {
					return out, fmt.Errorf("cannot quarantine %s: %w", c.Path, err)
				}
			}
			o.Quarantined = true
		}
		out = append(out, o)
	}
	return out, nil
}

// check is every rule a change must pass; it returns why it may not be applied, or "". A change
// whose new content is already in place is marked applied (a resumed batch).
func (a *Applier) check(root *os.Root, c Change, maxFile int64, total *int64, maxBatch int64, o *Outcome) string {
	class, err := Classify(c.Path, a.Host, a.Rules)
	if err != nil {
		return "invalid path: " + err.Error()
	}
	if class != Apply && class != Attributes {
		return fmt.Sprintf("protected path (%s)", class)
	}
	parts := strings.Split(c.Path, "/")
	for i := 1; i < len(parts); i++ {
		dir := strings.Join(parts[:i], "/")
		st, err := root.Lstat(dir)
		if errors.Is(err, fs.ErrNotExist) {
			break // created as a plain directory
		}
		if err != nil {
			return "cannot inspect " + dir + ": " + err.Error()
		}
		if !st.IsDir() {
			return dir + " is not a plain directory on the host (a symlink or a file)"
		}
	}
	cur, host, err := current(root, c.Path, maxFile)
	if err != nil {
		return "cannot read the host path: " + err.Error()
	}
	if want := c.want(); cur == want {
		o.Applied, o.Reason = true, "already in place"
		return ""
	}
	if cur != c.Base {
		return "changed on the host since the last sync (conflict)"
	}
	if k := kindOf(cur); cur != "" && c.Op != OpDelete && k != map[Op]string{OpWrite: "file", OpSymlink: "link"}[c.Op] {
		return fmt.Sprintf("file type change (%s on the host)", k)
	}
	if c.Op == OpDelete && (kindOf(cur) == "dir" || kindOf(cur) == "other") {
		return "deleting a " + kindOf(cur)
	}
	switch c.Op {
	case OpWrite:
		if int64(len(c.Data)) > maxFile {
			return fmt.Sprintf("larger than the %d-byte file limit", maxFile)
		}
		if *total+int64(len(c.Data)) > maxBatch {
			return fmt.Sprintf("over the %d-byte batch limit", maxBatch)
		}
		*total += int64(len(c.Data))
		if class == Attributes {
			if err := CheckAttributes(host, c.Data); err != nil {
				return ".gitattributes: " + err.Error()
			}
		}
	case OpSymlink:
		if why := a.linkTarget(c.Path, c.Target); why != "" {
			return why
		}
	}
	return ""
}

// linkTarget refuses a symlink that leaves the repository or points into git state: the target
// must be relative and, joined to the link's directory, stay inside the work tree and outside
// any .git.
func (a *Applier) linkTarget(p, target string) string {
	if target == "" || strings.ContainsRune(target, 0) || path.IsAbs(target) || strings.ContainsRune(target, '\\') ||
		len(target) > 1 && target[1] == ':' {
		return "symlink target is not a relative path"
	}
	resolved := path.Clean(path.Join(path.Dir(p), target))
	if resolved == ".." || strings.HasPrefix(resolved, "../") || resolved == "." {
		return "symlink resolves outside the repository"
	}
	if c, err := Classify(resolved, a.Host, a.Rules); err != nil || c != Apply && c != Attributes {
		return "symlink points at a protected path"
	}
	return ""
}

func tmpName(p string) string {
	var b [8]byte
	rand.Read(b[:])
	return path.Join(path.Dir(p), ".sandbox-sync-"+hex.EncodeToString(b[:]))
}

// write performs one checked change: parents created as plain directories, content written to a
// temporary file in the same directory and renamed over the path, so a reader sees old or new.
func (a *Applier) write(root *os.Root, c Change) error {
	if dir := path.Dir(c.Path); dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	switch c.Op {
	case OpDelete:
		err := root.Remove(c.Path)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	case OpSymlink:
		tmp := tmpName(c.Path)
		if err := root.Symlink(c.Target, tmp); err != nil {
			return err
		}
		if err := root.Rename(tmp, c.Path); err != nil {
			root.Remove(tmp)
			return err
		}
		return nil
	}
	mode := fs.FileMode(0o644)
	if c.Exec {
		mode = 0o755
	}
	tmp := tmpName(c.Path)
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(c.Data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Chmod(tmp, mode) // the umask may have narrowed it
	}
	if err == nil {
		err = root.Rename(tmp, c.Path)
	}
	if err != nil {
		root.Remove(tmp)
	}
	return err
}
