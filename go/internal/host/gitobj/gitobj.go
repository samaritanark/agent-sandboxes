// Package gitobj reads and verifies git objects on the host without running git (design 5.6.2
// rule 6, N-09): loose objects, pack indexes and packs with delta resolution, verification of a
// VM-origin loose object or pack (every object must hash to the id it claims), and the ancestry
// walk the ref rules use to decide that an update is a fast-forward. Sizes, delta depth, and walk
// length are capped; anything malformed is an error.
package gitobj

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Limits.
const (
	MaxObjectBytes = 512 << 20
	MaxDeltaDepth  = 64
	MaxWalk        = 2_000_000
)

// Kinds, as in a pack header.
var kindNames = map[int]string{1: "commit", 2: "tree", 3: "blob", 4: "tag"}

func hasher(idLen int) hash.Hash {
	if idLen == 32 {
		return sha256.New()
	}
	return sha1.New()
}

// ID is git's id for an object of kind with body.
func ID(kind string, body []byte, idLen int) string {
	h := hasher(idLen)
	fmt.Fprintf(h, "%s %d\x00", kind, len(body))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func validID(s string, idLen int) bool {
	if len(s) != 2*idLen {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

// inflate decompresses a zlib stream, refusing more than max bytes.
func inflate(r io.Reader, max int64) ([]byte, error) {
	z, err := zlib.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer z.Close()
	b, err := io.ReadAll(io.LimitReader(z, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("object too large")
	}
	return b, nil
}

// ParseLoose inflates a loose object file and returns its kind and body.
func ParseLoose(raw []byte) (string, []byte, error) {
	b, err := inflate(bytes.NewReader(raw), MaxObjectBytes+64)
	if err != nil {
		return "", nil, err
	}
	nul := bytes.IndexByte(b, 0)
	if nul < 0 || nul > 32 {
		return "", nil, errors.New("malformed object header")
	}
	kind, size, ok := strings.Cut(string(b[:nul]), " ")
	n, err := strconv.Atoi(size)
	if !ok || err != nil || strconv.Itoa(n) != size || n != len(b)-nul-1 {
		return "", nil, errors.New("malformed object header")
	}
	if kind != "commit" && kind != "tree" && kind != "blob" && kind != "tag" {
		return "", nil, fmt.Errorf("unknown object type %q", kind)
	}
	return kind, b[nul+1:], nil
}

// VerifyLoose checks a VM-origin loose object: it must parse and hash to want (its path).
func VerifyLoose(raw []byte, want string, idLen int) (string, error) {
	kind, body, err := ParseLoose(raw)
	if err != nil {
		return "", err
	}
	if got := ID(kind, body, idLen); got != want {
		return "", fmt.Errorf("object content hashes to %s, not %s", got, want)
	}
	return kind, nil
}

// Store is a repository's object directory.
type Store struct {
	Dir   string // .git/objects
	IDLen int
	packs []*Pack
}

// Open loads the store's pack indexes.
func Open(dir string, idLen int) (*Store, error) {
	s := &Store{Dir: dir, IDLen: idLen}
	ms, _ := filepath.Glob(filepath.Join(dir, "pack", "pack-*.idx"))
	sort.Strings(ms)
	for _, idx := range ms {
		ib, err := os.ReadFile(idx)
		if err != nil {
			return nil, err
		}
		pb, err := os.ReadFile(strings.TrimSuffix(idx, ".idx") + ".pack")
		if err != nil {
			return nil, err
		}
		p, err := LoadPack(pb, ib, idLen)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(idx), err)
		}
		s.packs = append(s.packs, p)
	}
	return s, nil
}

func (s *Store) loosePath(id string) string { return filepath.Join(s.Dir, id[:2], id[2:]) }

// Has reports whether the store holds id, loose or packed.
func (s *Store) Has(id string) bool {
	if !validID(id, s.IDLen) {
		return false
	}
	if st, err := os.Lstat(s.loosePath(id)); err == nil && st.Mode().IsRegular() {
		return true
	}
	raw, _ := hex.DecodeString(id)
	for _, p := range s.packs {
		if _, ok := p.find(raw); ok {
			return true
		}
	}
	return false
}

// Read returns an object's kind and body.
func (s *Store) Read(id string) (string, []byte, error) {
	if !validID(id, s.IDLen) {
		return "", nil, fmt.Errorf("invalid object id %q", id)
	}
	if raw, err := os.ReadFile(s.loosePath(id)); err == nil {
		return ParseLoose(raw)
	}
	b, _ := hex.DecodeString(id)
	for _, p := range s.packs {
		if off, ok := p.find(b); ok {
			return p.readAt(off, 0, s)
		}
	}
	return "", nil, fmt.Errorf("object %s not found", id)
}

// Parents is a commit's parent ids.
func (s *Store) Parents(id string) ([]string, error) {
	kind, body, err := s.Read(id)
	if err != nil {
		return nil, err
	}
	if kind != "commit" {
		return nil, fmt.Errorf("%s is a %s, not a commit", id, kind)
	}
	var ps []string
	for _, l := range strings.Split(string(body), "\n") {
		if l == "" {
			break
		}
		if p, ok := strings.CutPrefix(l, "parent "); ok {
			if !validID(p, s.IDLen) {
				return nil, fmt.Errorf("commit %s has a malformed parent", id)
			}
			ps = append(ps, p)
		}
	}
	return ps, nil
}

// IsAncestor reports whether old is new or an ancestor of new: the fast-forward test of rule 6.
// An object it cannot read, or a walk longer than MaxWalk commits, is an error, never a yes.
func (s *Store) IsAncestor(old, new string) (bool, error) {
	if old == new {
		return true, nil
	}
	seen := map[string]bool{new: true}
	queue := []string{new}
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		ps, err := s.Parents(c)
		if err != nil {
			return false, err
		}
		for _, p := range ps {
			if p == old {
				return true, nil
			}
			if !seen[p] {
				if len(seen) >= MaxWalk {
					return false, errors.New("history too long to walk")
				}
				seen[p] = true
				queue = append(queue, p)
			}
		}
	}
	return false, nil
}
