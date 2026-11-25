package journal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

func store(t *testing.T) *Store {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	return &Store{Dir: filepath.Join(t.TempDir(), "sessions"), Now: func() time.Time { now = now.Add(time.Second); return now }}
}

func spec(id string) *sessionspec.Spec { return &sessionspec.Spec{Version: 1, ID: id, Name: id} }

func TestLifecycle(t *testing.T) {
	st := store(t)
	if _, err := st.Create(spec("s-one")); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Create(spec("s-one")); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate: %v", err)
	}
	must := func(_ *Session, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.Transition("s-one", Admitted, "budget ok"))
	must(st.Transition("s-one", Starting, "starting"))
	for _, r := range [][2]string{{"netns", "sbx-s-one-agent"}, {"container", "s-one"}} {
		if err := st.Intend("s-one", r[0], r[1]); err != nil {
			t.Fatal(err)
		}
		if err := st.Mark("s-one", r[0], r[1], Created, ""); err != nil {
			t.Fatal(err)
		}
	}
	must(st.Transition("s-one", Running, "started"))
	if _, err := st.Transition("s-one", Terminated, "skip"); err == nil {
		t.Error("RUNNING -> TERMINATED allowed")
	}
	must(st.Transition("s-one", Stopping, "operator stop"))
	if err := st.Intend("s-one", "netns", "late"); err == nil {
		t.Error("a stopping session took a new resource")
	}
	if _, err := st.Transition("s-one", Terminated, "done"); err == nil || !strings.Contains(err.Error(), "still created") {
		t.Errorf("terminated with live resources: %v", err)
	}
	st.Mark("s-one", "container", "s-one", Released, "")
	st.Mark("s-one", "netns", "sbx-s-one-agent", Incomplete, "device busy")
	s, err := st.Transition("s-one", Terminated, "done")
	if err != nil {
		t.Fatal(err)
	}
	if s.EndReason != "operator stop" || len(s.Live()) != 1 || s.Live()[0].State != Incomplete {
		t.Errorf("%+v", s)
	}
	if _, err := st.Transition("s-one", Failed, "late"); err == nil {
		t.Error("a terminated session failed")
	}
	// survives a reload, with its history
	back, err := st.Load("s-one")
	if err != nil || back.State != Terminated || len(back.Events) != 7 || !strings.Contains(back.Events[len(back.Events)-2].What, "teardown-incomplete") {
		t.Errorf("reload: %+v %v", back, err)
	}
}

func TestFailedFromAnywhere(t *testing.T) {
	for _, path := range [][]State{{}, {Admitted}, {Admitted, Starting}, {Admitted, Starting, Running}, {Stopping}} {
		st := store(t)
		st.Create(spec("s-x"))
		for _, p := range path {
			if _, err := st.Transition("s-x", p, "step"); err != nil {
				t.Fatal(err)
			}
		}
		s, err := st.Transition("s-x", Failed, "crashed")
		want := "crashed" // the first end reason is the one recorded
		if len(path) > 0 && path[len(path)-1] == Stopping {
			want = "step"
		}
		if err != nil || s.EndReason != want {
			t.Errorf("%v -> FAILED: %v, end reason %q", path, err, s.EndReason)
		}
		if _, err := st.Transition("s-x", Stopping, "teardown"); err != nil {
			t.Errorf("FAILED -> STOPPING: %v", err)
		}
	}
}

func TestIntendIsIdempotent(t *testing.T) {
	st := store(t)
	st.Create(spec("s-y"))
	st.Transition("s-y", Admitted, "")
	for i := 0; i < 3; i++ {
		if err := st.Intend("s-y", "netns", "n1"); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := st.Load("s-y")
	if len(s.Resources) != 1 {
		t.Errorf("%+v", s.Resources)
	}
	if err := st.Mark("s-y", "netns", "never", Created, ""); err == nil {
		t.Error("marked a resource never journaled")
	}
	if err := st.Intend("s-y", "netns", "../etc"); err == nil {
		t.Error("bad resource name")
	}
}

func TestListAndCorruption(t *testing.T) {
	st := store(t)
	for _, id := range []string{"s-b", "s-a", "s-c"} {
		st.Create(spec(id))
	}
	l, err := st.List()
	if err != nil || len(l) != 3 || l[0].ID != "s-b" || l[2].ID != "s-c" {
		t.Fatalf("%v %v", l, err)
	}
	os.WriteFile(filepath.Join(st.Dir, "s-d.json"), []byte("{"), 0o600)
	if _, err := st.List(); err == nil {
		t.Error("a corrupt record was skipped")
	}
	os.WriteFile(filepath.Join(st.Dir, "s-d.json"), []byte(`{"id":"s-other"}`), 0o600)
	if _, err := st.List(); err == nil {
		t.Error("a record naming another session was accepted")
	}
	if fi, _ := os.Stat(st.Dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("journal dir mode %v", fi.Mode())
	}
	if _, err := st.Load("../x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("traversal: %v", err)
	}
}
