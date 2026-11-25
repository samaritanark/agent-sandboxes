package syncengine

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncgate"
	"github.com/samaritanark/agent-sandboxes/go/internal/syncagent"
	"github.com/samaritanark/agent-sandboxes/go/internal/syncproto"
)

// pipeVM runs a real agent on dir, connected by in-process pipes.
func pipeVM(t *testing.T, dir string) *StreamVM {
	toAgentR, toAgentW := io.Pipe()
	fromAgentR, fromAgentW := io.Pipe()
	go func() {
		syncagent.Serve(dir, toAgentR, fromAgentW)
		fromAgentW.Close()
	}()
	t.Cleanup(func() { toAgentW.Close() })
	return &StreamVM{W: toAgentW, R: fromAgentR}
}

func write(t *testing.T, dir, p, c string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
	if err := os.WriteFile(filepath.Join(dir, p), []byte(c), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(dir, p string) string { b, _ := os.ReadFile(filepath.Join(dir, p)); return string(b) }

func exists(dir, p string) bool { _, err := os.Lstat(filepath.Join(dir, p)); return err == nil }

func sorted(s []string) string {
	s = append([]string(nil), s...)
	sort.Strings(s)
	return strings.Join(s, ",")
}

func TestSyncBothWays(t *testing.T) {
	host, vmdir, state := t.TempDir(), t.TempDir(), t.TempDir()
	write(t, host, "src/a.go", "package a")
	write(t, host, "c.txt", "c")
	write(t, host, "x.txt", "x")
	write(t, host, ".env", "SECRET=real")
	write(t, host, "conf/db.yml", "password: real")
	write(t, host, ".sandbox/config.yaml", "masked_paths:\n  - conf/db.yml\n")
	write(t, host, ".git/HEAD", "ref: refs/heads/main\n")
	store := &syncgate.Store{Dir: filepath.Join(state, "quarantine")}
	e := &Engine{Repo: host, StateFile: filepath.Join(state, "sync.json"), Store: store, VM: pipeVM(t, vmdir)}

	// 1. first sync: everything but masked paths (and .git, left to the git rules) reaches the VM
	rep, err := e.Sync()
	if err != nil {
		t.Fatal(err)
	}
	if got := sorted(rep.ToVM); got != ".sandbox/config.yaml,c.txt,src/a.go,x.txt" {
		t.Fatalf("to VM: %s", got)
	}
	if exists(vmdir, ".env") || exists(vmdir, "conf/db.yml") || exists(vmdir, ".git/HEAD") {
		t.Fatal("a masked path or git state reached the VM")
	}

	// 2-4. the agent works in the VM; the operator edits x.txt on the host meanwhile
	write(t, vmdir, "src/a.go", "package a // agent")
	write(t, vmdir, "src/b.go", "package b")
	if err := os.Remove(filepath.Join(vmdir, "c.txt")); err != nil {
		t.Fatal(err)
	}
	write(t, vmdir, ".env", "SECRET=agent")
	write(t, vmdir, ".vscode/settings.json", "{\"task\":\"evil\"}")
	write(t, vmdir, "x.txt", "x from the agent")
	write(t, host, "x.txt", "x from the operator")
	write(t, vmdir, ".sandbox/config.yaml", "masked_paths: []\n")
	rep, err = e.Sync()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pass 2: %+v", rep)
	if got := sorted(rep.ToHost); got != "c.txt,src/a.go,src/b.go" {
		t.Errorf("to host: %s", got)
	}
	if got := sorted(rep.Quarantined); got != ".env,.sandbox/config.yaml,.vscode/settings.json" {
		t.Errorf("quarantined: %s", got)
	}
	if got := sorted(rep.Conflicts); got != "x.txt" {
		t.Errorf("conflicts: %s", got)
	}
	if read(host, "src/a.go") != "package a // agent" || exists(host, "c.txt") || read(host, "src/b.go") != "package b" {
		t.Error("VM changes not applied")
	}
	if read(host, ".env") != "SECRET=real" || exists(host, ".vscode") || read(host, "x.txt") != "x from the operator" ||
		read(host, ".sandbox/config.yaml") != "masked_paths:\n  - conf/db.yml\n" {
		t.Error("a withheld change reached the host")
	}
	if held, _ := store.List(); len(held) != 4 {
		t.Errorf("%d held, want 4", len(held))
	}

	// nothing new: withheld changes are not quarantined again
	rep, err = e.Sync()
	if err != nil || len(rep.Quarantined)+len(rep.Conflicts)+len(rep.ToHost)+len(rep.ToVM) != 0 {
		t.Errorf("second pass did something: %+v %v", rep, err)
	}
	if held, _ := store.List(); len(held) != 4 {
		t.Errorf("re-quarantined: %d held", len(held))
	}

	// 5. a host edit reaches the VM
	write(t, host, "src/a.go", "package a // operator")
	rep, _ = e.Sync()
	if sorted(rep.ToVM) != "src/a.go" || read(vmdir, "src/a.go") != "package a // operator" {
		t.Errorf("host edit: %+v", rep)
	}
}

// lyingVM answers a scan with whatever it was given and reads with fixed data.
type lyingVM struct {
	entries []syncproto.Entry
	data    string
}

func (l *lyingVM) Call(h syncproto.Header, body []byte) (syncproto.Header, []byte, error) {
	switch h.Op {
	case syncproto.OpScan:
		return syncproto.Header{Entries: l.entries}, nil, nil
	case syncproto.OpRead:
		return syncproto.Header{FP: syncproto.Fingerprint("file", []byte(l.data), false, "")}, []byte(l.data), nil
	}
	return syncproto.Header{Err: "read-only"}, nil, nil
}

func TestHostileVM(t *testing.T) {
	host, state := t.TempDir(), t.TempDir()
	claimed := syncproto.Fingerprint("file", []byte("what the scan said"), false, "")
	vm := &lyingVM{data: "something else", entries: []syncproto.Entry{
		{Path: "../escape", FP: claimed}, {Path: "/abs", FP: claimed}, {Path: "a/./b", FP: claimed},
		{Path: "ok.txt", FP: claimed},
	}}
	e := &Engine{Repo: host, StateFile: filepath.Join(state, "s.json"), VM: vm}
	rep, err := e.Sync()
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Refused) != 3 {
		t.Errorf("refused %v", rep.Refused)
	}
	if exists(host, "ok.txt") || len(rep.ToHost) != 0 {
		t.Error("content that did not match the scan was applied")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(host), "escape")); err == nil {
		t.Error("escaped the repository")
	}
}
