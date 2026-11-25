// Package syncproto is the wire protocol between the host binary's sync engine and the in-VM sync
// agent (design 5.6; the owner chose our own engine, 2026-11-25). Each message is a 4-byte
// big-endian header length, a JSON header, and, when the header says so, a raw body. The host
// treats every reply as hostile: sizes are capped here, and the engine re-validates every path and
// recomputes every fingerprint from the bytes it receives.
package syncproto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Limits.
const (
	MaxHeader  = 64 << 20 // a scan listing of a large tree
	MaxBody    = 64 << 20 // one file
	MaxEntries = 1_000_000
)

// Operations.
const (
	OpScan    = "scan"    // list the tree: Entries
	OpRead    = "read"    // a file's bytes (body) or a link's target
	OpWrite   = "write"   // replace a file with the body, if the path still matches Base
	OpSymlink = "symlink" // replace with a symlink to Target, if the path still matches Base
	OpDelete  = "delete"  // remove, if the path still matches Base
)

// Entry is one path in a scan.
type Entry struct {
	Path string `json:"p"`
	FP   string `json:"f"` // Fingerprint
}

// Header is a request or a reply.
type Header struct {
	Op       string  `json:"op,omitempty"`
	Path     string  `json:"path,omitempty"`
	Target   string  `json:"target,omitempty"`
	Exec     bool    `json:"exec,omitempty"`
	Base     string  `json:"base,omitempty"` // the fingerprint the sender believes the path has
	FP       string  `json:"fp,omitempty"`   // the path's fingerprint (replies)
	Entries  []Entry `json:"entries,omitempty"`
	Err      string  `json:"err,omitempty"`
	Conflict bool    `json:"conflict,omitempty"` // the path no longer matched Base; nothing was changed
	BodyLen  int64   `json:"body,omitempty"`
}

// Fingerprint identifies a path's state: "" absent, "file:<sha256>[:x]", "link:<target>", "dir",
// "other". The sync gate uses the same form.
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

// Write sends a message.
func Write(w io.Writer, h Header, body []byte) error {
	h.BodyLen = int64(len(body))
	j, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if len(j) > MaxHeader || len(body) > MaxBody {
		return errors.New("message too large")
	}
	// one write per message: a stream that treats an empty write as a message (io.Pipe does)
	// must never see one, and a message is never interleaved with another
	msg := make([]byte, 4, 4+len(j)+len(body))
	binary.BigEndian.PutUint32(msg, uint32(len(j)))
	msg = append(append(msg, j...), body...)
	_, err = w.Write(msg)
	return err
}

// Read receives a message.
func Read(r io.Reader) (Header, []byte, error) {
	var h Header
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return h, nil, err
	}
	l := binary.BigEndian.Uint32(n[:])
	if l > MaxHeader {
		return h, nil, fmt.Errorf("header of %d bytes is over the limit", l)
	}
	j := make([]byte, l)
	if _, err := io.ReadFull(r, j); err != nil {
		return h, nil, err
	}
	if err := json.Unmarshal(j, &h); err != nil {
		return h, nil, err
	}
	if h.BodyLen < 0 || h.BodyLen > MaxBody {
		return h, nil, fmt.Errorf("body of %d bytes is over the limit", h.BodyLen)
	}
	if len(h.Entries) > MaxEntries {
		return h, nil, errors.New("too many entries")
	}
	body := make([]byte, h.BodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return h, nil, err
	}
	return h, body, nil
}

// ObjectFP is the fingerprint of any file under .git/objects: git objects and packs are named by
// their content, so a scan reports their presence without reading them (the host verifies what it
// fetches).
const ObjectFP = "object"

// IsObjectPath reports whether p is under .git/objects/ (loose objects and packs, not info/).
func IsObjectPath(p string) bool {
	rest, ok := strings.CutPrefix(p, ".git/objects/")
	return ok && !strings.HasPrefix(rest, "info/")
}
