package syncagent

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/syncproto"
)

// largeTmp is the name a file sent in parts is assembled under, beside its destination.
const largeTmp = ".sandbox-sync-large"

// partial is the one file being received in parts (OpWritePart). Parts come in order on one
// connection; anything out of order drops what was received, and the host starts again.
type partial struct {
	path, tmp, fp string
	exec          bool
	size, written int64
	f             *os.File
}

func (p *partial) drop(root *os.Root) {
	if p.f != nil {
		p.f.Close()
		root.Remove(p.tmp)
	}
	*p = partial{}
}

func (p *partial) write(root *os.Root, h syncproto.Header, body []byte) (syncproto.Header, []byte) {
	fail := func(f string, a ...interface{}) (syncproto.Header, []byte) {
		p.drop(root)
		return syncproto.Header{Err: fmt.Sprintf(f, a...)}, nil
	}
	if h.Size <= syncproto.MaxBody || h.Size > syncproto.MaxLarge || !strings.HasPrefix(h.FP, "file:") {
		return fail("write-part %s: a size of %d is not one sent in parts", h.Path, h.Size)
	}
	if h.Offset == 0 {
		p.drop(root)
		cur, _, err := fingerprint(root, h.Path)
		if err != nil {
			return fail("write-part %s: %v", h.Path, err)
		}
		if cur != h.Base {
			return syncproto.Header{Conflict: true, FP: cur}, nil
		}
		if cur == "dir" {
			return fail("write-part %s: a directory is in the way", h.Path)
		}
		if err := plainParents(root, h.Path); err != nil {
			return fail("write-part %s: %v", h.Path, err)
		}
		if dir := path.Dir(h.Path); dir != "." {
			if err := root.MkdirAll(dir, 0o755); err != nil {
				return fail("write-part %s: %v", h.Path, err)
			}
		}
		tmp := path.Join(path.Dir(h.Path), largeTmp)
		root.Remove(tmp)
		f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fail("write-part %s: %v", h.Path, err)
		}
		*p = partial{path: h.Path, tmp: tmp, fp: h.FP, exec: strings.HasSuffix(h.FP, ":x"), size: h.Size, f: f}
	} else if p.f == nil || h.Path != p.path || h.Offset != p.written || h.Size != p.size || h.FP != p.fp {
		return fail("write-part %s: part at %d is out of order", h.Path, h.Offset)
	}
	if p.written+int64(len(body)) > p.size {
		return fail("write-part %s: more than %d bytes", h.Path, p.size)
	}
	if _, err := p.f.Write(body); err != nil {
		return fail("write-part %s: %v", h.Path, err)
	}
	p.written += int64(len(body))
	if p.written < p.size {
		return syncproto.Header{}, nil
	}
	// the last part: the whole must be what the host fingerprinted, and the path still the base
	if err := p.f.Close(); err != nil {
		return fail("write-part %s: %v", h.Path, err)
	}
	p.f = nil
	defer func() { root.Remove(p.tmp); *p = partial{} }()
	r, err := root.Open(p.tmp)
	if err != nil {
		return syncproto.Header{Err: fmt.Sprintf("write-part %s: %v", h.Path, err)}, nil
	}
	got, _, err := syncproto.FingerprintReader(r, p.exec)
	r.Close()
	if err != nil || got != p.fp {
		return syncproto.Header{Err: fmt.Sprintf("write-part %s: the parts do not make the file the host sent", h.Path)}, nil
	}
	cur, _, err := fingerprint(root, h.Path)
	if err != nil {
		return syncproto.Header{Err: fmt.Sprintf("write-part %s: %v", h.Path, err)}, nil
	}
	if cur != h.Base {
		return syncproto.Header{Conflict: true, FP: cur}, nil
	}
	mode := fs.FileMode(0o644)
	if p.exec {
		mode = 0o755
	}
	if err := root.Chmod(p.tmp, mode); err != nil {
		return syncproto.Header{Err: fmt.Sprintf("write-part %s: %v", h.Path, err)}, nil
	}
	if err := root.Rename(p.tmp, h.Path); err != nil {
		return syncproto.Header{Err: fmt.Sprintf("write-part %s: %v", h.Path, err)}, nil
	}
	fp, _, _ := fingerprint(root, h.Path)
	return syncproto.Header{FP: fp}, nil
}
