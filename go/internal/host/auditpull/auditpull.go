// Package auditpull is the host half of the session audit trail (design 5.1.5, 5.12): a pull the
// host starts, typed and validated, into a fixed place (~/.sandbox/logs/<session>/). The VM's
// records are untrusted: each line must be one JSON object for the session it was asked about, with
// a sequence number, under a size cap; records the host already holds are never rewritten, and a
// jump in the sequence is recorded on the host as an audit_gap (in gaps.jsonl, which only the host
// writes).
package auditpull

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The VM side's hidden commands (cmd/sandbox-vm) and files (sandboxd/auditlog).
const (
	VMSessions = "__audit-sessions"
	VMRead     = "__audit-read"
	Gaps       = "gaps.jsonl"
	// MaxRead is one round's output; MaxLine one record; MaxFile a host file's size.
	MaxRead = 8 << 20
	MaxLine = 64 << 10
	MaxFile = 256 << 20
)

// Files are the session logs pulled.
var Files = []string{"events.jsonl", "flows.jsonl"}

var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)

// Runner runs a command in the VM and returns its output, at most max bytes.
type Runner func(ctx context.Context, argv []string, max int) ([]byte, error)

// Report is what one pull did.
type Report struct {
	Records int
	Gaps    int
	Refused []string // lines (by session and file) that failed validation
}

// lastSeq is the highest sequence number in a host file.
func lastSeq(path string) (uint64, int64, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	st, _ := f.Stat()
	var last uint64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, MaxLine), MaxLine+1)
	for sc.Scan() {
		var r struct {
			Seq uint64 `json:"seq"`
		}
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.Seq > last {
			last = r.Seq
		}
	}
	return last, st.Size(), nil
}

func appendLine(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Pull fetches every session's new records into dest (~/.sandbox/logs).
func Pull(ctx context.Context, run Runner, vmCommand, dest string, now func() time.Time) (Report, error) {
	var rep Report
	out, err := run(ctx, []string{vmCommand, VMSessions}, 1<<20)
	if err != nil {
		return rep, fmt.Errorf("listing the VM's session logs: %w", err)
	}
	for _, s := range strings.Fields(string(out)) {
		if !idRE.MatchString(s) {
			rep.Refused = append(rep.Refused, "session name "+strconv.Quote(s))
			continue
		}
		dir := filepath.Join(dest, s)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return rep, err
		}
		for _, name := range Files {
			if err := pullFile(ctx, run, vmCommand, dir, s, name, now, &rep); err != nil {
				return rep, fmt.Errorf("%s/%s: %w", s, name, err)
			}
		}
	}
	return rep, nil
}

func pullFile(ctx context.Context, run Runner, vmCommand, dir, session, name string, now func() time.Time, rep *Report) error {
	path := filepath.Join(dir, name)
	if st, err := os.Lstat(path); err == nil && !st.Mode().IsRegular() {
		return errors.New("the host log is not a regular file")
	}
	last, size, err := lastSeq(path)
	if err != nil {
		return err
	}
	for size < MaxFile {
		out, err := run(ctx, []string{vmCommand, VMRead, session, name, strconv.FormatUint(last, 10)}, MaxRead)
		if err != nil {
			return err
		}
		if len(bytes.TrimSpace(out)) == 0 {
			return nil
		}
		progressed := false
		for _, line := range bytes.Split(bytes.TrimRight(out, "\n"), []byte("\n")) {
			var rec map[string]any
			if len(line) > MaxLine || json.Unmarshal(line, &rec) != nil {
				rep.Refused = append(rep.Refused, session+"/"+name+": not a JSON record")
				continue
			}
			seq, ok := rec["seq"].(float64)
			typ, ok2 := rec["type"].(string)
			if !ok || !ok2 || typ == "" || rec["session"] != session || seq != float64(uint64(seq)) || seq < 1 {
				rep.Refused = append(rep.Refused, session+"/"+name+": a record without its session, sequence, or type")
				continue
			}
			n := uint64(seq)
			if n <= last {
				continue // held already: never rewritten
			}
			if n != last+1 {
				gap, _ := json.Marshal(map[string]any{"type": "audit_gap", "session": session, "file": name,
					"missing_from": last + 1, "missing_to": n - 1, "time": now().UTC().Format(time.RFC3339Nano)})
				if err := appendLine(filepath.Join(dir, Gaps), gap); err != nil {
					return err
				}
				rep.Gaps++
			}
			clean, _ := json.Marshal(rec) // one line, re-encoded by the host
			if err := appendLine(path, clean); err != nil {
				return err
			}
			size += int64(len(clean)) + 1
			last, progressed = n, true
			rep.Records++
		}
		// another round only if this one was cut off by the size limit
		if !progressed || len(out) < MaxRead-MaxLine {
			return nil
		}
	}
	return nil
}
