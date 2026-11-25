package auditlog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func records(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("not JSON: %s", sc.Text())
		}
		out = append(out, m)
	}
	return out
}

func TestAppendAndReopen(t *testing.T) {
	root := t.TempDir()
	f, err := Open(root, "s-one", Events)
	if err != nil {
		t.Fatal(err)
	}
	f.Append("session_start", map[string]any{"agent": "claude"})
	f.Append("session_end", map[string]any{"end_reason": "operator stop", "seq": 99, "session": "forged"})
	g, _ := Open(root, "s-one", Events) // continues the sequence
	g.Append("note", nil)
	r := records(t, filepath.Join(root, "s-one", Events))
	if len(r) != 3 || r[0]["seq"] != 1.0 || r[1]["seq"] != 2.0 || r[2]["seq"] != 3.0 {
		t.Fatalf("%v", r)
	}
	if r[1]["session"] != "s-one" || r[1]["end_reason"] != "operator stop" {
		t.Errorf("a field overrode the envelope: %v", r[1])
	}
	if st, _ := os.Stat(filepath.Join(root, "s-one")); st.Mode().Perm() != 0o700 {
		t.Errorf("mode %v", st.Mode())
	}
	if _, err := Open(root, "../x", Events); err == nil {
		t.Error("bad session id")
	}
	if _, err := Open(root, "s-one", "other.log"); err == nil {
		t.Error("unknown file")
	}
}

func TestCap(t *testing.T) {
	root := t.TempDir()
	f, _ := Open(root, "s-cap", Flows)
	f.max = 400
	for i := 0; i < 20; i++ {
		f.Append("flow", map[string]any{"sni": strings.Repeat("x", 40)})
	}
	r := records(t, filepath.Join(root, "s-cap", Flows))
	last := r[len(r)-1]
	if last["type"] != "audit_truncated" || len(r) > 6 {
		t.Errorf("%d records, last %v", len(r), last)
	}
	g, _ := Open(root, "s-cap", Flows)
	g.Append("flow", nil)
	if n := len(records(t, filepath.Join(root, "s-cap", Flows))); n != len(r) {
		t.Error("a truncated log grew after reopening")
	}
}

func TestFlow(t *testing.T) {
	cases := map[string]string{
		`{"duration_ms":170,"flags":"-","port":443,"received":783,"sent":6933,"sni":"api.github.com","start":"T","upstream":"140.82.114.6:443"}`: "allowed",
		`{"port":443,"refused":true,"sni":"example.com","start":"T"}`:                                                                            "refused",
		`{"port":443,"refused":true,"sni":null,"start":"T"}`:                                                                                     "refused",
		`{"dependency":"db","duration_ms":20,"flags":"-","port":5432,"received":0,"sent":10,"start":"T"}`:                                        "dependency",
	}
	for line, want := range cases {
		typ, rec, ok := Flow([]byte(line))
		if !ok || typ != "flow" || rec["decision"] != want {
			t.Errorf("%s: %v %v", line, rec, ok)
		}
		if _, has := rec["refused"]; has {
			t.Errorf("raw field kept: %v", rec)
		}
	}
	if _, _, ok := Flow([]byte("not json")); ok {
		t.Error("garbage accepted")
	}
}

func TestTail(t *testing.T) {
	root := t.TempDir()
	flows, _ := Open(root, "s-tail", Flows)
	src := filepath.Join(t.TempDir(), "connections.log")
	os.WriteFile(src, []byte(`{"port":443,"refused":true,"sni":"a.com","start":"T"}`+"\n"+`{"port":443,"ref`), 0o600)
	off, err := Tail(src, 0, flows)
	if err != nil || off == 0 {
		t.Fatal(off, err)
	}
	// the partial line completes later
	fh, _ := os.OpenFile(src, os.O_APPEND|os.O_WRONLY, 0)
	fh.WriteString(`used":true,"sni":"b.com","start":"T"}` + "\n")
	fh.Close()
	if off, err = Tail(src, off, flows); err != nil {
		t.Fatal(err)
	}
	r := records(t, filepath.Join(root, "s-tail", Flows))
	if len(r) != 2 || r[1]["sni"] != "b.com" {
		t.Errorf("%v", r)
	}
	if off2, _ := Tail(src, off, flows); off2 != off || len(records(t, filepath.Join(root, "s-tail", Flows))) != 2 {
		t.Error("re-read old lines")
	}
}

func TestDrop(t *testing.T) {
	line := `[ 812.3] sbx s-net3 drop IN=vethc0e84413 OUT= MAC=4e:db SRC=10.200.0.2 DST=10.200.0.1 LEN=60 TOS=0x00 PROTO=TCP SPT=41000 DPT=22 WINDOW=64240 SYN`
	s, rec, ok := Drop(line)
	if !ok || s != "s-net3" || rec["rule"] != "drop" || rec["dst"] != "10.200.0.1" || rec["dpt"] != "22" || rec["proto"] != "TCP" {
		t.Errorf("%s %v %v", s, rec, ok)
	}
	if _, has := rec["out"]; has {
		t.Error("empty field kept")
	}
	if _, _, ok := Drop("audit: something else"); ok {
		t.Error("an unrelated line matched")
	}
}
