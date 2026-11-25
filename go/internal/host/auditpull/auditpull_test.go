package auditpull

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeVM serves records from memory as cmd/sandbox-vm would.
type fakeVM struct {
	logs map[string][]string // "session/file" -> lines
	list string
}

func (f *fakeVM) run(_ context.Context, argv []string, max int) ([]byte, error) {
	switch argv[1] {
	case VMSessions:
		return []byte(f.list), nil
	case VMRead:
		after, _ := strconv.ParseUint(argv[4], 10, 64)
		var b strings.Builder
		for _, l := range f.logs[argv[2]+"/"+argv[3]] {
			var seq uint64
			fmt.Sscanf(l[strings.Index(l, `"seq":`)+6:], "%d", &seq)
			if seq > after && b.Len()+len(l)+1 <= max {
				b.WriteString(l + "\n")
			}
		}
		return []byte(b.String()), nil
	}
	return nil, errors.New("unknown")
}

func rec(session string, seq int, typ string) string {
	return fmt.Sprintf(`{"seq":%d,"session":%q,"type":%q,"time":"T"}`, seq, session, typ)
}

var now = func() time.Time { return time.Unix(1800000000, 0) }

func TestPull(t *testing.T) {
	dest := t.TempDir()
	vm := &fakeVM{list: "s-one\n", logs: map[string][]string{
		"s-one/events.jsonl": {rec("s-one", 1, "session_requested"), rec("s-one", 2, "session_running")},
		"s-one/flows.jsonl":  {rec("s-one", 1, "flow")},
	}}
	rep, err := Pull(context.Background(), vm.run, "sandbox", dest, now)
	if err != nil || rep.Records != 3 || rep.Gaps != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	// new records, a gap, a rewrite of a held record, a forged session, and junk
	vm.logs["s-one/events.jsonl"] = []string{
		strings.Replace(rec("s-one", 2, "session_running"), "running", "REWRITTEN", 1),
		rec("s-one", 3, "link_drop"), rec("s-one", 6, "session_end"), rec("s-two", 7, "forged"),
		`{"seq":8,"session":"s-one"}`, `not json "seq":9`,
	}
	rep, err = Pull(context.Background(), vm.run, "sandbox", dest, now)
	if err != nil || rep.Records != 2 || rep.Gaps != 1 || len(rep.Refused) != 3 {
		t.Fatalf("%+v %v", rep, err)
	}
	b, _ := os.ReadFile(filepath.Join(dest, "s-one", "events.jsonl"))
	if strings.Contains(string(b), "REWRITTEN") || strings.Count(string(b), "\n") != 4 || !strings.Contains(string(b), `"seq":6`) {
		t.Errorf("host events:\n%s", b)
	}
	g, _ := os.ReadFile(filepath.Join(dest, "s-one", Gaps))
	if !strings.Contains(string(g), `"missing_from":4`) || !strings.Contains(string(g), `"missing_to":5`) {
		t.Errorf("gap record %s", g)
	}
	// nothing new: nothing written
	rep, _ = Pull(context.Background(), vm.run, "sandbox", dest, now)
	if rep.Records != 0 {
		t.Errorf("re-pulled %+v", rep)
	}
}

func TestRefusals(t *testing.T) {
	dest := t.TempDir()
	vm := &fakeVM{list: "../etc\nS-UPPER\ns-ok\n", logs: map[string][]string{}}
	rep, err := Pull(context.Background(), vm.run, "sandbox", dest, now)
	if err != nil || len(rep.Refused) != 2 {
		t.Errorf("%+v %v", rep, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "..", "etc")); err == nil {
		t.Error("escaped the log directory")
	}
	// a symlink where a host log should be is refused, not followed
	os.MkdirAll(filepath.Join(dest, "s-ok"), 0o700)
	os.Symlink("/etc/hosts", filepath.Join(dest, "s-ok", "events.jsonl"))
	vm.logs["s-ok/events.jsonl"] = []string{rec("s-ok", 1, "x")}
	if _, err := Pull(context.Background(), vm.run, "sandbox", dest, now); err == nil {
		t.Error("followed a symlink")
	}
}
