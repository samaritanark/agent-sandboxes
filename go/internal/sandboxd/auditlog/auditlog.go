// Package auditlog is the in-VM half of each session's audit trail (design 5.12): append-only JSON
// lines under /var/lib/sandbox/logs/<session>/, which the host pulls (5.1.5). Every record carries
// the session ID and a monotonic sequence number per file, so the host can record any gap as an
// audit_gap event. Files are capped: past the cap one audit_truncated record is written and
// nothing more, so a session cannot fill the VM's disk through its own log.
//
// Records never hold credential values or placeholders, query strings, or headers; the gateway's
// connection log they are made from carries none (envoyconf), and sandboxd's own records name
// bindings by reference and host only.
package auditlog

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// Root is where session logs live in the VM.
const Root = "/var/lib/sandbox/logs"

// MaxFileBytes caps one log file.
const MaxFileBytes = 64 << 20

// The files of a session log.
const (
	Events = "events.jsonl" // sandboxd's records: lifecycle, dependencies, link drops
	Flows  = "flows.jsonl"  // the gateway's connections (replaces v2's Hubble flows.json)
)

var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)

// File is one append-only log file.
type File struct {
	path    string
	session string
	max     int64

	mu        sync.Mutex
	seq       uint64
	size      int64
	truncated bool
	now       func() time.Time
}

// Open opens (creating) a session's log file, continuing its sequence after the last record.
func Open(root, session, name string) (*File, error) {
	if !idRE.MatchString(session) {
		return nil, fmt.Errorf("auditlog: invalid session id %q", session)
	}
	if name != Events && name != Flows {
		return nil, fmt.Errorf("auditlog: unknown file %q", name)
	}
	dir := filepath.Join(root, session)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f := &File{path: filepath.Join(dir, name), session: session, max: MaxFileBytes, now: func() time.Time { return time.Now().UTC() }}
	r, err := os.Open(f.path)
	if err == nil {
		defer r.Close()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var rec struct {
				Seq  uint64 `json:"seq"`
				Type string `json:"type"`
			}
			if json.Unmarshal(sc.Bytes(), &rec) == nil && rec.Seq > f.seq {
				f.seq = rec.Seq
			}
			f.truncated = f.truncated || rec.Type == "audit_truncated"
			f.size += int64(len(sc.Bytes())) + 1
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return f, nil
}

// Append writes one record of type typ with fields. The session, sequence number, time, and type
// are added; a field may not use those names.
func (f *File) Append(typ string, fields map[string]any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.truncated {
		return nil
	}
	rec := map[string]any{}
	for k, v := range fields {
		rec[k] = v
	}
	f.seq++
	rec["seq"], rec["session"], rec["time"], rec["type"] = f.seq, f.session, f.now().Format(time.RFC3339Nano), typ
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if f.size+int64(len(b))+1 > f.max {
		f.truncated = true
		b, _ = json.Marshal(map[string]any{"seq": f.seq, "session": f.session, "time": f.now().Format(time.RFC3339Nano),
			"type": "audit_truncated", "limit_bytes": f.max})
	}
	w, err := os.OpenFile(f.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer w.Close()
	if _, err := w.Write(append(b, '\n')); err != nil {
		return err
	}
	f.size += int64(len(b)) + 1
	return nil
}
