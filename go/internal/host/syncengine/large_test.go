package syncengine

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncgate"
	"github.com/samaritanark/agent-sandboxes/go/internal/syncproto"
)

// big writes a file just over the message limit, so it goes in parts (and partSize splits it).
func big(t *testing.T, dir, p string, fill byte, mode os.FileMode) []byte {
	t.Helper()
	b := bytes.Repeat([]byte{fill}, syncproto.MaxBody+partSize/2+3)
	os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
	if err := os.WriteFile(filepath.Join(dir, p), b, mode); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestLargeFiles: a host file larger than one message reaches the VM in parts, executable bit
// and all, and is then in step; a change the VM makes to it does not come back (the gate's
// per-file limit) and is noted once, not every pass; the host's next change to it is held as
// for any path the VM changed too.
func TestLargeFiles(t *testing.T) {
	host, vmdir, state := t.TempDir(), t.TempDir(), t.TempDir()
	want := big(t, host, "bin/tool", 'a', 0o755)
	e := &Engine{Repo: host, StateFile: filepath.Join(state, "s.json"), Store: &syncgate.Store{Dir: filepath.Join(state, "q")}, VM: pipeVM(t, vmdir)}
	rep, err := e.Sync()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(vmdir, "bin/tool")); !bytes.Equal(got, want) || sorted(rep.ToVM) != "bin/tool" {
		t.Fatalf("not sent whole: %d bytes, %+v", len(got), rep)
	}
	if st, _ := os.Stat(filepath.Join(vmdir, "bin/tool")); st.Mode()&0o111 == 0 {
		t.Error("lost its executable bit")
	}
	if left, _ := filepath.Glob(filepath.Join(vmdir, "bin", ".sandbox-sync-*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
	if rep, err = e.Sync(); err != nil || len(rep.ToVM)+len(rep.ToHost) != 0 {
		t.Errorf("not in step: %+v %v", rep, err)
	}
	// the VM changes it: not brought back, noted once
	big(t, vmdir, "bin/tool", 'b', 0o755)
	rep, err = e.Sync()
	if err != nil || len(rep.ToHost) != 0 || !strings.Contains(strings.Join(rep.Notes, "\n"), "not synced to the host: bin/tool") {
		t.Errorf("%+v %v", rep, err)
	}
	if got := read(host, "bin/tool"); got[0] != 'a' {
		t.Error("the VM's large file reached the host")
	}
	if rep, err = e.Sync(); err != nil || strings.Contains(strings.Join(rep.Notes, "\n"), "bin/tool") {
		t.Errorf("noted again: %+v %v", rep, err)
	}
}

// TestLargeFileOlderAgent: an older sync agent, which does not know write-part, refuses it; the
// file is then not synced, with a note, and nothing partial is left in the VM.
func TestLargeFileOlderAgent(t *testing.T) {
	host, vmdir, state := t.TempDir(), t.TempDir(), t.TempDir()
	big(t, host, "data.bin", 'a', 0o644)
	write(t, host, "small.txt", "s")
	e := &Engine{Repo: host, StateFile: filepath.Join(state, "s.json"), VM: &oldAgent{pipeVM(t, vmdir)}}
	rep, err := e.Sync()
	if err != nil {
		t.Fatal(err)
	}
	if exists(vmdir, "data.bin") || !exists(vmdir, "small.txt") || !strings.Contains(strings.Join(rep.Notes, "\n"), "an older image") {
		t.Errorf("%+v", rep)
	}
	// tried again each pass, but said once
	if rep, err = e.Sync(); err != nil || strings.Contains(strings.Join(rep.Notes, "\n"), "an older image") {
		t.Errorf("noted again: %+v %v", rep, err)
	}
}

// oldAgent answers write-part as a sync agent from before it existed does.
type oldAgent struct{ *StreamVM }

func (o *oldAgent) Call(h syncproto.Header, body []byte) (syncproto.Header, []byte, error) {
	if h.Op == syncproto.OpWritePart {
		return syncproto.Header{Err: `unknown operation "write-part"`}, nil, nil
	}
	return o.StreamVM.Call(h, body)
}
