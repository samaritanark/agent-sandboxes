package syncengine

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

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

	// 1. first sync: everything but masked paths reaches the VM (HEAD through the git rules)
	rep, err := e.Sync()
	if err != nil {
		t.Fatal(err)
	}
	if got := sorted(rep.ToVM); got != ".git/HEAD,.sandbox/config.yaml,c.txt,src/a.go,x.txt" {
		t.Fatalf("to VM: %s", got)
	}
	if exists(vmdir, ".env") || exists(vmdir, "conf/db.yml") {
		t.Fatal("a masked path reached the VM")
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

func TestCacheSeesSameSizeRewrites(t *testing.T) {
	host, vmdir, state := t.TempDir(), t.TempDir(), t.TempDir()
	write(t, host, "f.txt", "aaaa")
	e := &Engine{Repo: host, StateFile: filepath.Join(state, "s.json"), VM: pipeVM(t, vmdir)}
	if _, err := e.Sync(); err != nil {
		t.Fatal(err)
	}
	for i, c := range []string{"bbbb", "cccc", "dddd"} { // same size, immediately after one another
		write(t, host, "f.txt", c)
		if _, err := e.Sync(); err != nil {
			t.Fatal(err)
		}
		if read(vmdir, "f.txt") != c {
			t.Fatalf("rewrite %d: the VM has %q", i, read(vmdir, "f.txt"))
		}
		write(t, vmdir, "f.txt", strings.ToUpper(c))
		if _, err := e.Sync(); err != nil {
			t.Fatal(err)
		}
		if read(host, "f.txt") != strings.ToUpper(c) {
			t.Fatalf("VM rewrite %d: the host has %q", i, read(host, "f.txt"))
		}
	}
}

func TestSteadyStateCost(t *testing.T) {
	if testing.Short() {
		t.Skip("measures a 5,000-file tree")
	}
	host, vmdir, state := t.TempDir(), t.TempDir(), t.TempDir()
	for i := 0; i < 5000; i++ {
		write(t, host, fmt.Sprintf("d%02d/f%04d.txt", i%50, i), strings.Repeat("x", 2048))
	}
	e := &Engine{Repo: host, StateFile: filepath.Join(state, "s.json"), VM: pipeVM(t, vmdir)}
	start := time.Now()
	if _, err := e.Sync(); err != nil {
		t.Fatal(err)
	}
	first := time.Since(start)
	start = time.Now()
	rep, err := e.Sync()
	if err != nil || len(rep.ToVM)+len(rep.ToHost) != 0 {
		t.Fatal(rep, err)
	}
	steady := time.Since(start)
	t.Logf("5,000 files: first sync %v, an unchanged pass %v", first, steady)
	if steady > first {
		t.Errorf("an unchanged pass (%v) cost more than the first sync (%v): the cache is not working", steady, first)
	}
}

func TestRunStops(t *testing.T) {
	host, vmdir, state := t.TempDir(), t.TempDir(), t.TempDir()
	write(t, host, "a", "a")
	e := &Engine{Repo: host, StateFile: filepath.Join(state, "s.json"), VM: pipeVM(t, vmdir)}
	ctx, cancel := context.WithCancel(context.Background())
	passes := 0
	done := make(chan struct{})
	go func() {
		e.Run(ctx, 10*time.Millisecond, func(r Report, err error) {
			if err != nil {
				t.Error(err)
			}
			passes++
			if passes == 3 {
				cancel()
			}
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
	if read(vmdir, "a") != "a" {
		t.Error("Run did not sync")
	}
}

// TestNewCopyKeepsHostFiles: after the VM copy is made again (a reinstalled VM: a new epoch, an
// empty copy), the state kept for the old copy is set aside, so the files the new copy lacks go to
// it and nothing is deleted on the host. With the same epoch, a file gone from the VM is a deletion
// in the VM, as before.
func TestNewCopyKeepsHostFiles(t *testing.T) {
	host, state := t.TempDir(), t.TempDir()
	write(t, host, "README", "hi")
	write(t, host, "src/a.go", "package a")
	sf := filepath.Join(state, "s.json")
	first := t.TempDir()
	if _, err := (&Engine{Repo: host, StateFile: sf, VM: pipeVM(t, first), Copy: "old"}).Sync(); err != nil {
		t.Fatal(err)
	}
	// the VM is reinstalled: a new, empty copy with a new epoch
	second := t.TempDir()
	rep, err := (&Engine{Repo: host, StateFile: sf, VM: pipeVM(t, second), Copy: "new"}).Sync()
	if err != nil {
		t.Fatal(err)
	}
	if !exists(host, "README") || !exists(host, "src/a.go") || len(rep.ToHost) != 0 {
		t.Fatalf("host files deleted: to host %v", rep.ToHost)
	}
	if read(second, "README") != "hi" || read(second, "src/a.go") != "package a" {
		t.Errorf("the new copy did not get the files: %v", rep.ToVM)
	}
	// the same copy: a deletion in the VM still reaches the host
	os.Remove(filepath.Join(second, "README"))
	if _, err := (&Engine{Repo: host, StateFile: sf, VM: pipeVM(t, second), Copy: "new"}).Sync(); err != nil {
		t.Fatal(err)
	}
	if exists(host, "README") {
		t.Error("a deletion in the same copy did not reach the host")
	}
}

func TestNextPass(t *testing.T) {
	for _, c := range [][3]time.Duration{
		{3 * time.Second, 100 * time.Millisecond, 3 * time.Second},
		{3 * time.Second, 1500 * time.Millisecond, 3 * time.Second},
		{3 * time.Second, 4 * time.Second, 8 * time.Second},
	} {
		if got := NextPass(c[0], c[1]); got != c[2] {
			t.Errorf("NextPass(%v, %v) = %v, want %v", c[0], c[1], got, c[2])
		}
	}
}
