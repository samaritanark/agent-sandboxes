package daemon

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestDependencyRestarts: a dependency that exits is started again once it has been down for the
// delay, which doubles after each restart up to the cap and returns to the minimum after a long
// enough run; each exit and restart is in the audit log, and an ended session's dependencies are
// not restarted.
func TestDependencyRestarts(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, err := r.d.Start(ctx, spec("s-dep", 4096, "db")); err != nil {
		t.Fatal(err)
	}
	cid := "db.s-dep"
	restarts := func() int {
		n := 0
		for _, c := range r.rt.calls {
			if c == "restart "+cid {
				n++
			}
		}
		return n
	}
	tick := func(d time.Duration) {
		*r.now = r.now.Add(d)
		r.d.Heartbeat("s-dep")
		r.d.Reap(ctx)
	}
	tick(5 * time.Second) // running: nothing
	r.rt.started[cid] = false
	tick(5 * time.Second) // seen down
	tick(5 * time.Second) // 5 s down, under 10 s
	if restarts() != 0 {
		t.Fatal("restarted before its delay")
	}
	tick(5 * time.Second) // 10 s down
	if restarts() != 1 {
		t.Fatalf("not restarted after 10 s: %v", r.rt.calls)
	}
	// it exits again: now 20 s
	r.rt.started[cid] = false
	tick(time.Second)
	tick(15 * time.Second)
	if restarts() != 1 {
		t.Error("the delay did not double")
	}
	tick(5 * time.Second)
	if restarts() != 2 {
		t.Errorf("not restarted after 20 s: %d", restarts())
	}
	// the delay is capped
	for i := 0; i < 8; i++ {
		r.rt.started[cid] = false
		tick(time.Second)
		tick(DepRestartMax)
	}
	if dep := r.d.deps["s-dep"][0]; dep.delay != DepRestartMax {
		t.Errorf("delay %v", dep.delay)
	}
	// a long run resets it
	tick(DepRestartReset)
	if dep := r.d.deps["s-dep"][0]; dep.delay != DepRestartMin {
		t.Errorf("delay after a long run %v", dep.delay)
	}
	ev := strings.Join(auditTypes(t, r.d.AuditRoot, "s-dep", "events.jsonl"), ",")
	if !strings.Contains(ev, "dependency_exited") || !strings.Contains(ev, "dependency_restarted") {
		t.Errorf("events %s", ev)
	}
	// the session ends: its dependencies are forgotten
	if err := r.d.Stop(ctx, "s-dep", "operator stop"); err != nil {
		t.Fatal(err)
	}
	n := restarts()
	r.rt.started[cid] = false
	tick(time.Hour)
	if restarts() != n || r.d.deps["s-dep"] != nil {
		t.Error("an ended session's dependency was restarted")
	}
}
