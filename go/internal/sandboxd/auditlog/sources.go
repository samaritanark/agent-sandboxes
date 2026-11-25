package auditlog

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"
)

// Flow turns one line of a gateway's connection log (envoyconf's access log format) into a flow
// record. Only the fields the design allows are kept: time, SNI or dependency, decision, upstream
// address, bytes, and duration.
func Flow(line []byte) (typ string, rec map[string]any, ok bool) {
	var in map[string]any
	if json.Unmarshal(line, &in) != nil {
		return "", nil, false
	}
	rec = map[string]any{}
	for _, k := range []string{"start", "sni", "port", "upstream", "sent", "received", "duration_ms", "dependency"} {
		if v, ok := in[k]; ok && v != nil && v != "-" {
			rec[k] = v
		}
	}
	switch {
	case in["refused"] == true:
		rec["decision"] = "refused"
	case in["dependency"] != nil:
		rec["decision"] = "dependency"
	default:
		rec["decision"] = "allowed"
		if f, _ := in["flags"].(string); f != "" && f != "-" {
			rec["flags"] = f // an upstream failure, for example
		}
	}
	return "flow", rec, true
}

// Tail copies new lines of a gateway connection log, from byte offset off, into flows; it returns
// the offset after the last complete line, for the next call.
func Tail(path string, off int64, flows *File) (int64, error) {
	r, err := os.Open(path)
	if os.IsNotExist(err) {
		return off, nil
	}
	if err != nil {
		return off, err
	}
	defer r.Close()
	if _, err := r.Seek(off, io.SeekStart); err != nil {
		return off, err
	}
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return off, nil // a partial line waits for the next call
		}
		off += int64(len(line))
		if typ, rec, ok := Flow(line); ok {
			if err := flows.Append(typ, rec); err != nil {
				return off, err
			}
		}
	}
}

// kmsgRE is a kernel log record of a gateway namespace's drop: "sbx <session> <what> IN=... SRC=...".
var kmsgRE = regexp.MustCompile(`sbx ([a-z0-9][a-z0-9-]{2,62}) (drop|forward|spoof|weakhost|blocked) (.*)$`)

// Drop parses a kernel log line into a session and a link-drop record (a bypass attempt): what
// rule dropped it and the packet's addresses, protocol, and ports, never its payload.
func Drop(line string) (session string, rec map[string]any, ok bool) {
	m := kmsgRE.FindStringSubmatch(line)
	if m == nil {
		return "", nil, false
	}
	rec = map[string]any{"rule": m[2]}
	for _, f := range strings.Fields(m[3]) {
		k, v, found := strings.Cut(f, "=")
		if !found {
			continue
		}
		switch k {
		case "SRC", "DST", "PROTO", "SPT", "DPT", "IN", "OUT":
			if v != "" {
				rec[strings.ToLower(k)] = v
			}
		}
	}
	return m[1], rec, true
}
