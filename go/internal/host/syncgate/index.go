package syncgate

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sort"
	"strings"
)

// The index codec of rule 7. The host never copies .git/index; it parses both sides' indexes
// strictly, merges them by entry, and writes a plain version 2 index.

// Limits on an index the gate will read.
const (
	MaxIndexBytes   = 256 << 20
	MaxIndexEntries = 2_000_000
)

// Entry is one index entry. Stat data is not kept: the gate writes it as zeros and git refreshes
// it on first use.
type Entry struct {
	Path         string
	Mode         uint32
	ID           []byte // object id, 20 (SHA-1) or 32 (SHA-256) bytes
	Stage        int    // 0, or 1-3 in a merge conflict
	AssumeValid  bool
	SkipWorktree bool
	IntentToAdd  bool
}

// GitIndex is a parsed index.
type GitIndex struct {
	Version int
	Entries []Entry
}

var errIndex = errors.New("malformed index")

func indexErr(f string, a ...interface{}) error {
	return fmt.Errorf("%w: %s", errIndex, fmt.Sprintf(f, a...))
}

func newHash(idLen int) hash.Hash {
	if idLen == 32 {
		return sha256.New()
	}
	return sha1.New()
}

// validIndexPath is git's verify_path for a path in the index: relative, slash-separated, no
// empty, ".", "..", or ".git" component (in any case), no trailing slash, no NUL.
func validIndexPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") || strings.ContainsRune(p, 0) {
		return false
	}
	for _, c := range strings.Split(p, "/") {
		if c == "" || c == "." || c == ".." || strings.EqualFold(c, ".git") {
			return false
		}
	}
	return true
}

func validMode(m uint32) bool {
	switch m {
	case 0o100644, 0o100755, 0o120000, 0o160000:
		return true
	}
	return false
}

// ParseIndex reads an index strictly: versions 2, 3, and 4; the trailing checksum verified; entry
// count, sizes, and names checked; entries strictly sorted by path and stage, a path either at
// stage 0 or at conflict stages only. Optional extensions (signature starting A-Z) are skipped;
// any required one (split index, sparse directories) is refused.
func ParseIndex(b []byte, idLen int) (*GitIndex, error) {
	if idLen != 20 && idLen != 32 {
		return nil, errors.New("object id length must be 20 or 32")
	}
	if len(b) > MaxIndexBytes {
		return nil, indexErr("larger than %d bytes", MaxIndexBytes)
	}
	if len(b) < 12+idLen {
		return nil, indexErr("too short")
	}
	body, sum := b[:len(b)-idLen], b[len(b)-idLen:]
	h := newHash(idLen)
	h.Write(body)
	if !bytes.Equal(h.Sum(nil), sum) {
		return nil, indexErr("checksum mismatch")
	}
	if string(body[:4]) != "DIRC" {
		return nil, indexErr("bad signature")
	}
	ver := int(binary.BigEndian.Uint32(body[4:8]))
	if ver < 2 || ver > 4 {
		return nil, indexErr("unsupported version %d", ver)
	}
	n := binary.BigEndian.Uint32(body[8:12])
	if n > MaxIndexEntries {
		return nil, indexErr("%d entries is over the limit", n)
	}
	minEntry := 40 + idLen + 2 + 1
	if uint64(n)*uint64(minEntry) > uint64(len(body)-12) {
		return nil, indexErr("%d entries cannot fit", n)
	}
	idx := &GitIndex{Version: ver, Entries: make([]Entry, 0, n)}
	off := 12
	prev := ""
	for i := uint32(0); i < n; i++ {
		start := off
		if off+40+idLen+2 > len(body) {
			return nil, indexErr("truncated entry %d", i)
		}
		mode := binary.BigEndian.Uint32(body[off+24 : off+28])
		id := append([]byte(nil), body[off+40:off+40+idLen]...)
		off += 40 + idLen
		flags := binary.BigEndian.Uint16(body[off : off+2])
		off += 2
		e := Entry{Mode: mode, ID: id, Stage: int(flags>>12) & 3, AssumeValid: flags&0x8000 != 0}
		if flags&0x4000 != 0 {
			if ver < 3 {
				return nil, indexErr("extended flags in a version %d index", ver)
			}
			if off+2 > len(body) {
				return nil, indexErr("truncated entry %d", i)
			}
			ext := binary.BigEndian.Uint16(body[off : off+2])
			off += 2
			if ext&^0x6000 != 0 {
				return nil, indexErr("unknown extended flags %#x", ext)
			}
			e.SkipWorktree, e.IntentToAdd = ext&0x4000 != 0, ext&0x2000 != 0
		}
		var name string
		if ver == 4 {
			strip, used := varint(body[off:])
			if used == 0 || strip > uint64(len(prev)) {
				return nil, indexErr("bad path prefix in entry %d", i)
			}
			off += used
			end := bytes.IndexByte(body[off:], 0)
			if end < 0 {
				return nil, indexErr("unterminated path in entry %d", i)
			}
			name = prev[:len(prev)-int(strip)] + string(body[off:off+end])
			off += end + 1
		} else {
			end := bytes.IndexByte(body[off:], 0)
			if end < 0 {
				return nil, indexErr("unterminated path in entry %d", i)
			}
			name = string(body[off : off+end])
			// padded with 1 to 8 NULs to a multiple of 8 bytes from the entry's start
			entryLen := (off + end - start + 8) &^ 7
			if start+entryLen > len(body) {
				return nil, indexErr("truncated entry %d", i)
			}
			for _, c := range body[off+end : start+entryLen] {
				if c != 0 {
					return nil, indexErr("bad padding in entry %d", i)
				}
			}
			off = start + entryLen
		}
		if l := int(flags & 0x0fff); l != 0x0fff && l != len(name) || l == 0x0fff && len(name) < 0x0fff {
			return nil, indexErr("name length mismatch in entry %d", i)
		}
		if !validIndexPath(name) {
			return nil, indexErr("invalid path %q", name)
		}
		if !validMode(mode) {
			return nil, indexErr("invalid mode %o for %q", mode, name)
		}
		if len(idx.Entries) > 0 {
			p := idx.Entries[len(idx.Entries)-1]
			if c := strings.Compare(p.Path, name); c > 0 || c == 0 && (p.Stage >= e.Stage || p.Stage == 0) {
				return nil, indexErr("entries out of order at %q", name)
			}
		}
		e.Path = name
		prev = name
		idx.Entries = append(idx.Entries, e)
	}
	// Extensions.
	for off < len(body) {
		if off+8 > len(body) {
			return nil, indexErr("truncated extension")
		}
		sig := body[off : off+4]
		size := binary.BigEndian.Uint32(body[off+4 : off+8])
		if uint64(off)+8+uint64(size) > uint64(len(body)) {
			return nil, indexErr("extension %q overruns the index", sig)
		}
		if sig[0] < 'A' || sig[0] > 'Z' {
			return nil, indexErr("required extension %q is not supported", sig)
		}
		off += 8 + int(size)
	}
	return idx, nil
}

// varint is git's offset varint (used for v4 path prefixes); used is 0 on malformed input.
func varint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	c := b[0]
	v := uint64(c & 0x7f)
	i := 1
	for c&0x80 != 0 {
		if i >= len(b) || i > 9 {
			return 0, 0
		}
		v++
		c = b[i]
		v = v<<7 | uint64(c&0x7f)
		i++
	}
	return v, i
}

// WriteIndex writes a plain index: no extensions, stat data zeroed, and the assume-valid and
// skip-worktree flags cleared (rule 7: they hide changes from git status). Intent-to-add is kept,
// since clearing it would stage an empty file where the operator only announced one; it needs
// extended flags, so the index is version 3 when an entry has it and version 2 otherwise. Entries
// are sorted here and must be valid.
func WriteIndex(entries []Entry, idLen int) ([]byte, error) {
	es := append([]Entry(nil), entries...)
	sort.SliceStable(es, func(i, j int) bool {
		if es[i].Path != es[j].Path {
			return es[i].Path < es[j].Path
		}
		return es[i].Stage < es[j].Stage
	})
	ver := uint32(2)
	for _, e := range es {
		if e.IntentToAdd {
			ver = 3
		}
	}
	var b bytes.Buffer
	b.WriteString("DIRC")
	binary.Write(&b, binary.BigEndian, ver)
	binary.Write(&b, binary.BigEndian, uint32(len(es)))
	for i, e := range es {
		if !validIndexPath(e.Path) || !validMode(e.Mode) || len(e.ID) != idLen || e.Stage < 0 || e.Stage > 3 {
			return nil, fmt.Errorf("invalid entry %q", e.Path)
		}
		if i > 0 && es[i-1].Path == e.Path && (es[i-1].Stage == e.Stage || es[i-1].Stage == 0 || e.Stage == 0) {
			return nil, fmt.Errorf("duplicate entry %q", e.Path)
		}
		start := b.Len()
		var stat [40]byte
		binary.BigEndian.PutUint32(stat[24:28], e.Mode)
		b.Write(stat[:])
		b.Write(e.ID)
		l := len(e.Path)
		if l > 0x0fff {
			l = 0x0fff
		}
		flags := uint16(e.Stage)<<12 | uint16(l)
		if e.IntentToAdd {
			flags |= 0x4000
		}
		binary.Write(&b, binary.BigEndian, flags)
		if e.IntentToAdd {
			binary.Write(&b, binary.BigEndian, uint16(0x2000))
		}
		b.WriteString(e.Path)
		pad := (b.Len() - start + 8) &^ 7
		b.Write(make([]byte, start+pad-b.Len()))
	}
	h := newHash(idLen)
	h.Write(b.Bytes())
	b.Write(h.Sum(nil))
	return b.Bytes(), nil
}
