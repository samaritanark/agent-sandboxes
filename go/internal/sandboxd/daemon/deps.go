package daemon

import (
	"context"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/auditlog"
)

// Dependencies that exit are started again, as v2's pods restarted their containers: with a
// delay that doubles from DepRestartMin to DepRestartMax after each restart, and back to the
// minimum once one has run DepRestartReset. Each restart is recorded in the session's audit log.

// The restart delays (Kubernetes' CrashLoopBackOff).
var (
	DepRestartMin   = 10 * time.Second
	DepRestartMax   = 5 * time.Minute
	DepRestartReset = 10 * time.Minute
)

// dependency is one of a live session's dependency containers.
type dependency struct {
	name, container string
	restarts        int
	delay           time.Duration // before the next restart
	down            time.Time     // when it was first seen not running; zero while it runs
	started         time.Time     // when it was last started
}

func (d *Daemon) trackDependency(session, name, container string) {
	if d.deps == nil {
		d.deps = map[string][]*dependency{}
	}
	d.deps[session] = append(d.deps[session], &dependency{name: name, container: container, delay: DepRestartMin, started: d.now()})
}

// restartDependencies starts again each dependency that has been down for its delay. d.mu is held.
func (d *Daemon) restartDependencies(ctx context.Context, now time.Time) {
	for session, deps := range d.deps {
		if _, ok := d.live[session]; !ok {
			continue
		}
		for _, dep := range deps {
			running, err := d.Runtime.Running(ctx, dep.container)
			if err != nil {
				d.logf("session %s: dependency %s: %v", session, dep.name, err)
				continue
			}
			if running {
				dep.down = time.Time{}
				if now.Sub(dep.started) >= DepRestartReset {
					dep.delay = DepRestartMin
				}
				continue
			}
			if dep.down.IsZero() {
				dep.down = now
				d.audit(session, auditlog.Events, "dependency_exited", map[string]any{"name": dep.name, "restarts": dep.restarts})
			}
			if now.Sub(dep.down) < dep.delay {
				continue
			}
			if err := d.Runtime.Restart(ctx, dep.container); err != nil {
				d.logf("session %s: restarting dependency %s: %v", session, dep.name, err)
				d.audit(session, auditlog.Events, "dependency_restart_failed", map[string]any{"name": dep.name, "error": err.Error()})
			} else {
				dep.restarts++
				d.audit(session, auditlog.Events, "dependency_restarted", map[string]any{"name": dep.name, "restarts": dep.restarts})
			}
			dep.down, dep.started = time.Time{}, now
			if dep.delay *= 2; dep.delay > DepRestartMax {
				dep.delay = DepRestartMax
			}
		}
	}
}
