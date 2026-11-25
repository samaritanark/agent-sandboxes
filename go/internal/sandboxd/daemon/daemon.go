// Package daemon is sandboxd's lifecycle (design 5.4.3): it admits a session spec, journals and
// creates its resources (a network namespace and a Kata microVM for the agent and for each
// dependency), tears everything down on every end, reaps sessions whose attach lease or
// keep-alive limits expire, and on start reconciles the journal against what exists before it
// accepts new sessions.
//
// This first increment gives each microVM a network namespace with no link, so sessions have no
// network yet; links, nftables, and the gateway (5.8.2), the broker (5.9), and attaching a
// terminal come next. Keep-alive sessions are not yet restarted after a VM reboot: they are torn
// down like the rest (item 9 needs the broker store key).
package daemon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/journal"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/limits"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/runtime"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// Runtime is the microVM runtime (runtime.Runtime in production).
type Runtime interface {
	Create(ctx context.Context, m runtime.MicroVM) error
	Start(ctx context.Context, id string) error
	Destroy(ctx context.Context, id string, grace time.Duration) error
	List(ctx context.Context) ([]string, error)
}

// Namespaces makes network namespaces (netns.Manager in production).
type Namespaces interface {
	Create(ctx context.Context, name string) error
	Delete(ctx context.Context, name string) error
	List(ctx context.Context) ([]string, error)
}

// Paths: where a namespace is bound, given its name.
type Paths func(name string) string

// Resource kinds in the journal.
const (
	KindContainer = "container"
	KindNetNS     = "netns"
	KindMasks     = "masks" // the session's directory of empty mask files and directories
)

// StopGrace is how long a microVM gets between SIGTERM and SIGKILL.
const StopGrace = 10 * time.Second

// Daemon is sandboxd.
type Daemon struct {
	Journal     *journal.Store
	Runtime     Runtime
	NetNS       Namespaces
	NetNSPath   Paths
	Budget      limits.Budget
	Expiry      limits.Expiry
	SessionRoot string // sessionspec.SessionStore in production
	Now         func() time.Time
	Log         *log.Logger

	mu    sync.Mutex // serializes lifecycle changes
	live  map[string]*limits.Times
	ready bool
}

func (d *Daemon) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now().UTC()
}

func (d *Daemon) logf(f string, a ...any) {
	if d.Log != nil {
		d.Log.Printf(f, a...)
	}
}

// ErrNotReady is returned until Reconcile has finished.
var ErrNotReady = errors.New("sandboxd is reconciling its sessions; try again")

func agentNetNS(id string) string        { return "sbx-" + id + "-a" }
func depNetNS(id, dep string) string     { return "sbx-" + id + "-d-" + dep }
func depContainer(id, dep string) string { return id + "--" + dep }

// holding is the specs of sessions that hold memory now.
func (d *Daemon) holding(except string) ([]*sessionspec.Spec, error) {
	all, err := d.Journal.List()
	if err != nil {
		return nil, err
	}
	var out []*sessionspec.Spec
	for _, s := range all {
		switch s.State {
		case journal.Admitted, journal.Starting, journal.Running, journal.Stopping, journal.Failed:
			if s.ID != except && s.Spec != nil {
				out = append(out, s.Spec)
			}
		}
	}
	return out, nil
}

// Start admits and starts the session in raw (a session spec), returning its ID.
func (d *Daemon) Start(ctx context.Context, raw []byte) (string, error) {
	spec, err := sessionspec.Decode(bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	if err := spec.Validate(sessionspec.Options{}); err != nil {
		return "", fmt.Errorf("session spec refused: %w", err)
	}
	if len(spec.Readable) > 0 {
		return "", errors.New("session spec refused: readable secrets need the broker, which sandboxd does not run yet")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.ready {
		return "", ErrNotReady
	}
	if _, err := d.Journal.Create(spec); err != nil {
		return "", err
	}
	id := spec.ID
	holding, err := d.holding(id)
	if err == nil {
		err = d.Budget.Admit(holding, spec)
	}
	if err != nil {
		d.end(ctx, id, "not admitted: "+firstLine(err), true)
		return "", err
	}
	if _, err := d.Journal.Transition(id, journal.Admitted, "memory budget"); err != nil {
		return "", err
	}
	if _, err := d.Journal.Transition(id, journal.Starting, "creating resources"); err != nil {
		return "", err
	}
	if err := d.bringUp(ctx, spec); err != nil {
		d.logf("session %s: start failed: %v", id, err)
		d.end(ctx, id, "start failed: "+firstLine(err), true)
		return "", errors.New(firstLine(err))
	}
	if _, err := d.Journal.Transition(id, journal.Running, "started"); err != nil {
		d.end(ctx, id, "start failed: "+firstLine(err), true)
		return "", err
	}
	if d.live == nil {
		d.live = map[string]*limits.Times{}
	}
	d.live[id] = &limits.Times{Started: d.now(), KeepAlive: spec.KeepAlive}
	d.logf("session %s running", id)
	return id, nil
}

// step journals a resource, creates it, and records it created.
func (d *Daemon) step(id, kind, name string, create func() error) error {
	if err := d.Journal.Intend(id, kind, name); err != nil {
		return err
	}
	if err := create(); err != nil {
		return fmt.Errorf("%s %s: %w", kind, name, err)
	}
	return d.Journal.Mark(id, kind, name, journal.Created, "")
}

func (d *Daemon) maskDir(id string) string { return filepath.Join(d.SessionRoot, id, "masks") }

// mounts turns the spec's mounts into bind mounts, making the empty mask files and directories.
// Workspace mounts come first, so overlays and masks inside them land on top.
func (d *Daemon) mounts(spec *sessionspec.Spec) ([]runtime.Mount, error) {
	ms := append([]sessionspec.Mount(nil), spec.Mounts...)
	sort.SliceStable(ms, func(i, j int) bool {
		return ms[i].Kind == sessionspec.Workspace && ms[j].Kind != sessionspec.Workspace
	})
	var out []runtime.Mount
	for i, m := range ms {
		switch m.Kind {
		case sessionspec.MaskFile, sessionspec.MaskDir:
			p := filepath.Join(d.maskDir(spec.ID), strconv.Itoa(i))
			var err error
			if m.Kind == sessionspec.MaskFile {
				err = os.WriteFile(p, nil, 0o444)
			} else {
				err = os.Mkdir(p, 0o555)
			}
			if err != nil {
				return nil, err
			}
			out = append(out, runtime.Mount{Source: p, Target: m.Target, ReadOnly: true})
		case sessionspec.ReadOnly:
			out = append(out, runtime.Mount{Source: m.Source, Target: m.Target, ReadOnly: true})
		default:
			out = append(out, runtime.Mount{Source: m.Source, Target: m.Target, ReadOnly: m.ReadOnly})
		}
	}
	return out, nil
}

func env(vs []sessionspec.EnvVar) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.Name+"="+v.Value)
	}
	return out
}

// bringUp creates the session's namespaces and microVMs, each journaled first.
func (d *Daemon) bringUp(ctx context.Context, spec *sessionspec.Spec) error {
	id := spec.ID
	if err := d.step(id, KindMasks, "masks", func() error { return os.MkdirAll(d.maskDir(id), 0o700) }); err != nil {
		return err
	}
	mounts, err := d.mounts(spec)
	if err != nil {
		return err
	}
	for _, dep := range spec.Dependencies {
		ns, cid := depNetNS(id, dep.Name), depContainer(id, dep.Name)
		if err := d.step(id, KindNetNS, ns, func() error { return d.NetNS.Create(ctx, ns) }); err != nil {
			return err
		}
		m := runtime.MicroVM{ID: cid, Image: dep.Image, Args: dep.Command, Env: env(dep.Env),
			UID: uint32(dep.RunAsUser), GID: uint32(dep.RunAsUser), NetNS: d.NetNSPath(ns),
			CPUs: dep.Resources.CPUs, MemoryMiB: dep.Resources.MemoryMiB, Hostname: dep.Name}
		if err := d.step(id, KindContainer, cid, func() error {
			if err := d.Runtime.Create(ctx, m); err != nil {
				return err
			}
			return d.Runtime.Start(ctx, cid)
		}); err != nil {
			return err
		}
	}
	ns := agentNetNS(id)
	if err := d.step(id, KindNetNS, ns, func() error { return d.NetNS.Create(ctx, ns) }); err != nil {
		return err
	}
	agent := runtime.MicroVM{ID: id, Image: spec.Image, Args: spec.Command, Env: env(spec.Env),
		UID: 1000, GID: 1000, Mounts: mounts, NetNS: d.NetNSPath(ns),
		CPUs: spec.Resources.CPUs, MemoryMiB: spec.Resources.MemoryMiB, Hostname: "sandbox"}
	return d.step(id, KindContainer, id, func() error {
		if err := d.Runtime.Create(ctx, agent); err != nil {
			return err
		}
		return d.Runtime.Start(ctx, id)
	})
}

// Stop ends a session (operator stop, or the reaper).
func (d *Daemon) Stop(ctx context.Context, id, reason string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, err := d.Journal.Load(id)
	if err != nil {
		return err
	}
	if s.State == journal.Terminated {
		return nil
	}
	return d.end(ctx, id, reason, false)
}

// end tears a session down: the microVMs first (the containment action), then namespaces and
// files. A resource that cannot be removed is recorded as teardown-incomplete. failed marks the
// session FAILED first.
func (d *Daemon) end(ctx context.Context, id, reason string, failed bool) error {
	delete(d.live, id)
	s, err := d.Journal.Load(id)
	if err != nil {
		return err
	}
	if failed && s.State != journal.Failed && s.State != journal.Stopping {
		if _, err := d.Journal.Transition(id, journal.Failed, reason); err != nil {
			return err
		}
	}
	if s.State != journal.Stopping {
		if _, err := d.Journal.Transition(id, journal.Stopping, reason); err != nil {
			return err
		}
	}
	if s, err = d.Journal.Load(id); err != nil {
		return err
	}
	order := map[string]int{KindContainer: 0, KindNetNS: 1, KindMasks: 2}
	live := s.Live()
	sort.SliceStable(live, func(i, j int) bool { return order[live[i].Kind] < order[live[j].Kind] })
	for _, r := range live {
		if r.State == journal.Incomplete {
			continue
		}
		var err error
		switch r.Kind {
		case KindContainer:
			err = d.Runtime.Destroy(ctx, r.Name, StopGrace)
		case KindNetNS:
			err = d.NetNS.Delete(ctx, r.Name)
		case KindMasks:
			err = os.RemoveAll(d.maskDir(id))
		default:
			err = fmt.Errorf("unknown resource kind %q", r.Kind)
		}
		to, note := journal.Released, ""
		if err != nil {
			to, note = journal.Incomplete, err.Error()
			d.logf("session %s: teardown-incomplete: %s %s: %v", id, r.Kind, r.Name, err)
		}
		if err := d.Journal.Mark(id, r.Kind, r.Name, to, note); err != nil {
			return err
		}
	}
	os.Remove(filepath.Join(d.SessionRoot, id)) // only if empty: history and transcripts stay
	_, err = d.Journal.Transition(id, journal.Terminated, "torn down")
	d.logf("session %s ended: %s", id, reason)
	return err
}

// firstLine is an error's first line: runtimes append stack traces that do not belong in an end
// reason (the log keeps the whole error).
func firstLine(err error) string {
	s := strings.TrimSpace(err.Error())
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}

// Heartbeat renews a session's attach lease.
func (d *Daemon) Heartbeat(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.live[id]
	if !ok {
		return journal.ErrNotFound
	}
	t.LastHeartbeat = d.now()
	return nil
}

// Reap ends every session whose lease or keep-alive limits have expired.
func (d *Daemon) Reap(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	ids := make([]string, 0, len(d.live))
	for id := range d.live {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if ok, why := d.Expiry.Expired(*d.live[id], now); ok {
			if err := d.end(ctx, id, why, false); err != nil {
				d.logf("session %s: reaping: %v", id, err)
			}
		}
	}
}

// Reconcile runs once at start, before any session is accepted: every journaled session that
// has not ended is torn down (sandboxd cannot vouch for one it did not see start), then any
// microVM or namespace of sandboxd's that the journal does not account for is removed.
func (d *Daemon) Reconcile(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	all, err := d.Journal.List()
	if err != nil {
		return fmt.Errorf("reading the journal: %w", err)
	}
	owned := map[string]bool{}
	for _, s := range all {
		if s.State != journal.Terminated {
			if err := d.end(ctx, s.ID, "sandboxd restarted", false); err != nil {
				return fmt.Errorf("session %s: %w", s.ID, err)
			}
			if s, err = d.Journal.Load(s.ID); err != nil {
				return err
			}
		}
		for _, r := range s.Resources {
			if r.State == journal.Incomplete {
				owned[r.Kind+"/"+r.Name] = true // recorded already; retried below
			}
		}
	}
	cs, err := d.Runtime.List(ctx)
	if err != nil {
		return fmt.Errorf("listing microVMs: %w", err)
	}
	for _, c := range cs {
		d.logf("removing orphan microVM %s", c)
		if err := d.Runtime.Destroy(ctx, c, StopGrace); err != nil {
			return fmt.Errorf("orphan microVM %s: %w", c, err)
		}
	}
	nss, err := d.NetNS.List(ctx)
	if err != nil {
		return fmt.Errorf("listing namespaces: %w", err)
	}
	for _, n := range nss {
		d.logf("removing orphan namespace %s", n)
		if err := d.NetNS.Delete(ctx, n); err != nil {
			return fmt.Errorf("orphan namespace %s: %w", n, err)
		}
	}
	d.live = map[string]*limits.Times{}
	d.ready = true
	return nil
}

// Summary is one session as List reports it.
type Summary struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	State     journal.State `json:"state"`
	EndReason string        `json:"end_reason,omitempty"`
}

// List reports every journaled session.
func (d *Daemon) List() ([]Summary, error) {
	all, err := d.Journal.List()
	if err != nil {
		return nil, err
	}
	out := make([]Summary, 0, len(all))
	for _, s := range all {
		name := ""
		if s.Spec != nil {
			name = s.Spec.Name
		}
		out = append(out, Summary{ID: s.ID, Name: name, State: s.State, EndReason: s.EndReason})
	}
	return out, nil
}
