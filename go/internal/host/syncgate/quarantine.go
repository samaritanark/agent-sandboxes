package syncgate

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The quarantine (5.6.2: withheld changes are quarantined, not dropped): each withheld change is
// kept with its reason under <state>/quarantine/<repo-id>/<entry-id>/ until the operator applies or
// discards it with `sandbox sync review`.

// RepoID is the stable id of a host repository: a hash of its canonical path (5.6.1).
func RepoID(hostPath string) (string, error) {
	p, err := filepath.Abs(hostPath)
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	s := sha256.Sum256([]byte(p))
	return hex.EncodeToString(s[:8]), nil
}

// Held is one quarantined change's record.
type Held struct {
	ID      string    `json:"id"`
	Repo    string    `json:"repo"` // the host repository path
	Path    string    `json:"path"`
	Op      string    `json:"op"` // write, delete, symlink
	Exec    bool      `json:"exec,omitempty"`
	Target  string    `json:"target,omitempty"`
	Base    string    `json:"base"`
	Reason  string    `json:"reason"`
	Session string    `json:"session,omitempty"`
	Time    time.Time `json:"time"`
	SHA256  string    `json:"sha256,omitempty"`
}

var opNames = map[Op]string{OpWrite: "write", OpDelete: "delete", OpSymlink: "symlink"}

// Store is the quarantine of one host.
type Store struct {
	Dir     string // <state>/quarantine
	Session string
	Now     func() time.Time
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Put keeps a withheld change and returns its id.
func (s *Store) Put(repo string, c Change, reason string) (string, error) {
	rid, err := RepoID(repo)
	if err != nil {
		return "", err
	}
	var rb [4]byte
	rand.Read(rb[:])
	t := s.now()
	id := t.Format("20060102T150405Z") + "-" + hex.EncodeToString(rb[:])
	dir := filepath.Join(s.Dir, rid)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	h := Held{ID: id, Repo: repo, Path: c.Path, Op: opNames[c.Op], Exec: c.Exec, Target: c.Target, Base: c.Base,
		Reason: reason, Session: s.Session, Time: t}
	if c.Op == OpWrite {
		sum := sha256.Sum256(c.Data)
		h.SHA256 = hex.EncodeToString(sum[:])
	}
	tmp, err := os.MkdirTemp(dir, ".tmp-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	meta, _ := json.MarshalIndent(h, "", "  ")
	if err := os.WriteFile(filepath.Join(tmp, "meta.json"), meta, 0o600); err != nil {
		return "", err
	}
	if c.Op == OpWrite {
		if err := os.WriteFile(filepath.Join(tmp, "content"), c.Data, 0o600); err != nil {
			return "", err
		}
	}
	return id, os.Rename(tmp, filepath.Join(dir, id))
}

func validEntryID(id string) bool {
	return len(id) == 25 && id[8] == 'T' && id[15] == 'Z' && id[16] == '-' && isHex(id[17:], 8)
}

// List is every held change, oldest first.
func (s *Store) List() ([]Held, error) {
	var out []Held
	repos, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	for _, r := range repos {
		ents, _ := os.ReadDir(filepath.Join(s.Dir, r.Name()))
		for _, e := range ents {
			if !validEntryID(e.Name()) {
				continue
			}
			h, _, err := s.load(filepath.Join(s.Dir, r.Name(), e.Name()))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", e.Name(), err)
			}
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) load(dir string) (Held, Change, error) {
	var h Held
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return h, Change{}, err
	}
	if err := json.Unmarshal(b, &h); err != nil {
		return h, Change{}, err
	}
	c := Change{Path: h.Path, Exec: h.Exec, Target: h.Target, Base: h.Base}
	switch h.Op {
	case "write":
		c.Op = OpWrite
		if c.Data, err = os.ReadFile(filepath.Join(dir, "content")); err != nil {
			return h, c, err
		}
		sum := sha256.Sum256(c.Data)
		if hex.EncodeToString(sum[:]) != h.SHA256 {
			return h, c, errors.New("held content does not match its record")
		}
	case "delete":
		c.Op = OpDelete
	case "symlink":
		c.Op = OpSymlink
	default:
		return h, c, fmt.Errorf("unknown operation %q", h.Op)
	}
	return h, c, nil
}

func (s *Store) find(id string) (string, error) {
	if !validEntryID(id) {
		return "", fmt.Errorf("no held change %q", id)
	}
	m, _ := filepath.Glob(filepath.Join(s.Dir, "*", id))
	if len(m) != 1 {
		return "", fmt.Errorf("no held change %q", id)
	}
	return m[0], nil
}

// Get loads one held change.
func (s *Store) Get(id string) (Held, Change, error) {
	dir, err := s.find(id)
	if err != nil {
		return Held{}, Change{}, err
	}
	return s.load(dir)
}

// Discard drops a held change.
func (s *Store) Discard(id string) error {
	dir, err := s.find(id)
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

// GitRefCommand is, for a held branch update, the git command the operator can run to apply it;
// the host binary never writes refs from review itself (they go through the operator's git).
func GitRefCommand(h Held, data []byte) (string, bool) {
	ref, ok := strings.CutPrefix(h.Path, ".git/")
	if !ok || !strings.HasPrefix(ref, "refs/heads/") || !ValidBranch(ref) {
		return "", false
	}
	if h.Op == "delete" {
		return "git -C " + shellQuote(h.Repo) + " update-ref -d " + ref, true
	}
	id := strings.TrimSpace(string(data))
	if !isHex(id, 40) && !isHex(id, 64) {
		return "", false
	}
	return "git -C " + shellQuote(h.Repo) + " update-ref " + ref + " " + id, true
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// ApplyApproved applies a held change the operator approved: their approval overrides the
// protected-path and conflict rules, but the write still stays inside the repository, never goes
// through a parent symlink, and a symlink target still may not leave the repository. Git state is
// not written here (see GitRefCommand).
func (a *Applier) ApplyApproved(c Change) error {
	parts, err := CleanPath(c.Path, a.Host)
	if err != nil {
		return err
	}
	for _, p := range parts {
		if a.Host.key(p) == a.Host.key(".git") || strings.EqualFold(p, ".git") {
			return errors.New("git state is not applied from review")
		}
	}
	root, err := os.OpenRoot(a.Repo)
	if err != nil {
		return err
	}
	defer root.Close()
	for i := 1; i < len(parts); i++ {
		dir := strings.Join(parts[:i], "/")
		st, err := root.Lstat(dir)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil || !st.IsDir() {
			return fmt.Errorf("%s is not a plain directory on the host", dir)
		}
	}
	if c.Op == OpSymlink {
		resolved := filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(c.Path), c.Target)))
		if filepath.IsAbs(c.Target) || resolved == ".." || strings.HasPrefix(resolved, "../") {
			return errors.New("symlink resolves outside the repository")
		}
	}
	return a.write(root, c)
}
