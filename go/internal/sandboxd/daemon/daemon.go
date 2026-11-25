// Package daemon is sandboxd's lifecycle (design 5.4.3): it admits a session spec, journals and
// creates its resources (a network namespace and a Kata microVM for the agent and for each
// dependency), tears everything down on every end, reaps sessions whose attach lease or
// keep-alive limits expire, and on start reconciles the journal against what exists before it
// accepts new sessions.
//
// Every microVM's network is its own link to the session's gateway namespace (5.8.2): its resolver
// and Envoy are the only things it can reach, under its own allowlist, and the agent reaches its
// dependencies only through the gateway (5.8.6). The broker (5.9) and attaching a terminal come
// next. Keep-alive sessions are not yet restarted after a VM reboot: they are torn
// down like the rest (item 9 needs the broker store key).
package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/gwpolicy"
	"github.com/samaritanark/agent-sandboxes/go/internal/l7"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/auditlog"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/journal"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/limits"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/netsetup"
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

// Network builds a session's network (netsetup in production).
type Network interface {
	Root(ctx context.Context) error // the VM root namespace's rules, once at start
	Up(ctx context.Context, s netsetup.Session) error
}

// GatewayRunner runs a session's gateway process in its gateway namespace.
type GatewayRunner interface {
	// Start makes dir afresh with files in it (relative paths: "policy.json", the leaves, the
	// upstream roots), readable only by the gateway, starts the gateway, and waits until it serves;
	// it returns the process id.
	Start(ctx context.Context, id, gatewayNS, dir string, files map[string][]byte) (int, error)
	// Stop ends it (pid as Start returned it).
	Stop(ctx context.Context, id string, pid int) error
}

// Paths: where a namespace is bound, given its name.
type Paths func(name string) string

// Resource kinds in the journal.
const (
	KindContainer = "container"
	KindNetNS     = "netns"
	KindMasks     = "masks"   // the session's directory of empty mask files and directories
	KindUplink    = "uplink"  // an uplink index (its interfaces go with the gateway namespace)
	KindGateway   = "gateway" // the gateway process (its id in the resource's note)
)

// StopGrace is how long a microVM gets between SIGTERM and SIGKILL.
const StopGrace = 10 * time.Second

// Daemon is sandboxd.
type Daemon struct {
	Journal     *journal.Store
	Runtime     Runtime
	NetNS       Namespaces
	Network     Network
	Gateways    GatewayRunner
	TLS         *TLS         // interception (tls.go); nil refuses any session that intercepts
	Resolvers   []netip.Addr // the VM's upstream resolvers, for each gateway
	AuditRoot   string       // each session's audit log (auditlog.Root); "" for none
	NetNSPath   Paths
	Budget      limits.Budget
	Expiry      limits.Expiry
	SessionRoot string // sessionspec.SessionStore in production
	Now         func() time.Time
	Log         *log.Logger

	mu      sync.Mutex // serializes lifecycle changes
	live    map[string]*limits.Times
	ready   bool
	offsets map[string]int64 // how far each session's gateway connection log has been collected
}

// audit appends one record to a session's audit file; a failure is logged, never fatal (the
// session's own state is the journal).
func (d *Daemon) audit(id, file, typ string, rec map[string]any) {
	if d.AuditRoot == "" {
		return
	}
	f, err := auditlog.Open(d.AuditRoot, id, file)
	if err == nil {
		err = f.Append(typ, rec)
	}
	if err != nil {
		d.logf("session %s: audit: %v", id, err)
	}
}

// specSummary is what the audit log keeps of a spec: names and hosts, never values.
func specSummary(s *sessionspec.Spec) map[string]any {
	var bindings, deps []map[string]any
	for _, b := range s.Bindings {
		bindings = append(bindings, map[string]any{"ref": b.Ref, "hosts": b.Hosts})
	}
	for _, d := range s.Dependencies {
		deps = append(deps, map[string]any{"name": d.Name, "image": d.Image, "port": d.Port})
	}
	return map[string]any{"name": s.Name, "agent": s.Agent, "tier": s.Tier, "image": s.Image, "keep_alive": s.KeepAlive,
		"bindings": bindings, "dependencies": deps, "allow": s.Egress.Allow, "extra_ports": s.Egress.ExtraPorts}
}

// collect copies a session's new gateway connections into its flow log.
func (d *Daemon) collect(id string) {
	if d.AuditRoot == "" {
		return
	}
	flows, err := auditlog.Open(d.AuditRoot, id, auditlog.Flows)
	if err != nil {
		d.logf("session %s: audit: %v", id, err)
		return
	}
	if d.offsets == nil {
		d.offsets = map[string]int64{}
	}
	off, err := auditlog.Tail(filepath.Join(d.SessionRoot, id, "gateway", "connections.log"), d.offsets[id], flows)
	if err != nil {
		d.logf("session %s: audit: %v", id, err)
	}
	d.offsets[id] = off
}

// Collect gathers every live session's new connections (sandboxd calls it periodically).
func (d *Daemon) Collect() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id := range d.live {
		d.collect(id)
	}
}

// RecordDrop records a link drop (a bypass attempt) for a session sandboxd knows.
func (d *Daemon) RecordDrop(session string, rec map[string]any) {
	if _, err := d.Journal.Load(session); err != nil {
		return
	}
	d.audit(session, auditlog.Events, "link_drop", rec)
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
func gatewayNetNS(id string) string      { return "sbx-" + id + "-g" }
func depNetNS(id, dep string) string     { return "sbx-" + id + "-d-" + dep }
func depContainer(id, dep string) string { return id + "." + dep } // containerd ids allow single separators; session ids have no dots

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
	d.audit(id, auditlog.Events, "session_requested", specSummary(spec))
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
	d.audit(id, auditlog.Events, "session_running", nil)
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

// bringUp creates the session's namespaces, network, gateway, and microVMs, each journaled first.
// The network and gateway exist before any microVM starts, so no microVM ever runs unfiltered.
func (d *Daemon) bringUp(ctx context.Context, spec *sessionspec.Spec) error {
	id := spec.ID
	if err := d.step(id, KindMasks, "masks", func() error { return os.MkdirAll(d.maskDir(id), 0o700) }); err != nil {
		return err
	}
	mounts, err := d.mounts(spec)
	if err != nil {
		return err
	}
	ns, gns := agentNetNS(id), gatewayNetNS(id)
	all := []string{ns, gns}
	links := []netsetup.Link{{Index: 0, NS: ns, Name: id}}
	for i, dep := range spec.Dependencies {
		n := depNetNS(id, dep.Name)
		all = append(all, n)
		links = append(links, netsetup.Link{Index: i + 1, NS: n, Name: depContainer(id, dep.Name)})
	}
	for _, n := range all {
		if err := d.step(id, KindNetNS, n, func() error { return d.NetNS.Create(ctx, n) }); err != nil {
			return err
		}
	}

	// the gateway's policy: each link's own allowlist, and the agent's way to its dependencies
	agentPorts := append([]int{443}, spec.Egress.ExtraPorts...)
	pol := gwpolicy.Policy{Resolvers: d.Resolvers, Links: []gwpolicy.Link{{Name: "agent", Listen: netsetup.GatewayAddr,
		Ports: agentPorts, Allow: spec.Egress.Allow, BlockDomains: spec.Egress.BlockDomains}}}
	ports := map[int]bool{}
	blockCIDRs := append([]string(nil), spec.Egress.BlockCIDRs...)
	for _, p := range agentPorts {
		ports[p] = true
	}
	for i, dep := range spec.Dependencies {
		gw, guest := netsetup.LinkAddrs(i + 1)
		dp := append([]int{443}, dep.Egress.ExtraPorts...)
		pol.Links = append(pol.Links, gwpolicy.Link{Name: dep.Name, Listen: gw, Ports: dp,
			Allow: dep.Egress.Allow, BlockDomains: dep.Egress.BlockDomains})
		pol.Deps = append(pol.Deps, gwpolicy.Dep{Name: dep.Name, Port: dep.Port, Addr: guest})
		ports[dep.Port] = true
		for _, p := range dp {
			ports[p] = true
		}
		blockCIDRs = append(blockCIDRs, dep.Egress.BlockCIDRs...)
	}
	// interception: each link's names (its L7 rules' hosts and its bindings'), with the leaves
	gwDir := filepath.Join(d.SessionRoot, id, "gateway")
	names := [][]string{interceptNames(spec.Egress, spec.Bindings)}
	rules := [][]l7.Rule{spec.Egress.L7}
	for _, dep := range spec.Dependencies {
		names = append(names, interceptNames(dep.Egress, dep.Bindings))
		rules = append(rules, dep.Egress.L7)
	}
	files := map[string][]byte{}
	if err := d.gatewayTLS(id, gwDir, names, rules, &pol, files); err != nil {
		return err
	}
	trustMounts, trustEnv, err := d.guestTrust(id)
	if err != nil {
		return err
	}
	var portList []int
	for p := range ports {
		portList = append(portList, p)
	}
	sort.Ints(portList)

	uplink, err := d.freeUplink()
	if err != nil {
		return err
	}
	if err := d.step(id, KindUplink, strconv.Itoa(uplink), func() error {
		return d.Network.Up(ctx, netsetup.Session{ID: id, GatewayNS: gns, Links: links, Uplink: uplink,
			Ports: portList, BlockCIDRs: blockCIDRs, Resolvers: d.Resolvers})
	}); err != nil {
		return err
	}
	files["policy.json"], _ = json.Marshal(pol)
	if err := d.Journal.Intend(id, KindGateway, "gateway"); err != nil {
		return err
	}
	pid, err := d.Gateways.Start(ctx, id, gns, gwDir, files)
	if err != nil {
		return fmt.Errorf("gateway: %w", err)
	}
	if err := d.Journal.Mark(id, KindGateway, "gateway", journal.Created, strconv.Itoa(pid)); err != nil {
		return err
	}
	// each microVM's resolver is its own gateway address
	resolvConf := func(n int) (runtime.Mount, error) {
		gw, _ := netsetup.LinkAddrs(n)
		p := filepath.Join(d.maskDir(id), "resolv-"+strconv.Itoa(n)+".conf")
		err := os.WriteFile(p, []byte("nameserver "+gw.String()+"\n"), 0o444)
		return runtime.Mount{Source: p, Target: "/etc/resolv.conf", ReadOnly: true}, err
	}

	for i, dep := range spec.Dependencies {
		cid := depContainer(id, dep.Name)
		rc, err := resolvConf(i + 1)
		if err != nil {
			return err
		}
		m := runtime.MicroVM{ID: cid, Image: dep.Image, Args: dep.Command, Env: append(env(dep.Env), trustEnv...),
			UID: uint32(dep.RunAsUser), GID: uint32(dep.RunAsUser), NetNS: d.NetNSPath(depNetNS(id, dep.Name)),
			Mounts: append([]runtime.Mount{rc}, trustMounts...), CPUs: dep.Resources.CPUs, MemoryMiB: dep.Resources.MemoryMiB, Hostname: dep.Name}
		if err := d.step(id, KindContainer, cid, func() error {
			if err := d.Runtime.Create(ctx, m); err != nil {
				return err
			}
			return d.Runtime.Start(ctx, cid)
		}); err != nil {
			return err
		}
		d.audit(id, auditlog.Events, "dependency_up", map[string]any{"name": dep.Name, "image": dep.Image})
	}
	rc, err := resolvConf(0)
	if err != nil {
		return err
	}
	mounts = append(append(mounts, rc), trustMounts...)
	agent := runtime.MicroVM{ID: id, Image: spec.Image, Args: spec.Command, Env: append(env(spec.Env), trustEnv...),
		UID: 1000, GID: 1000, Mounts: mounts, NetNS: d.NetNSPath(ns),
		CPUs: spec.Resources.CPUs, MemoryMiB: spec.Resources.MemoryMiB, Hostname: "sandbox"}
	return d.step(id, KindContainer, id, func() error {
		if err := d.Runtime.Create(ctx, agent); err != nil {
			return err
		}
		return d.Runtime.Start(ctx, id)
	})
}

// freeUplink is the lowest uplink index no live session holds.
func (d *Daemon) freeUplink() (int, error) {
	all, err := d.Journal.List()
	if err != nil {
		return 0, err
	}
	used := map[int]bool{}
	for _, s := range all {
		for _, r := range s.Live() {
			if r.Kind == KindUplink {
				if n, err := strconv.Atoi(r.Name); err == nil {
					used[n] = true
				}
			}
		}
	}
	for n := 0; n < netsetup.MaxUplinks; n++ {
		if !used[n] {
			return n, nil
		}
	}
	return 0, errors.New("no free uplink: too many sessions")
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
	order := map[string]int{KindContainer: 0, KindGateway: 1, KindNetNS: 2, KindUplink: 3, KindMasks: 4}
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
		case KindGateway:
			pid, _ := strconv.Atoi(r.Note)
			err = d.Gateways.Stop(ctx, id, pid)
		case KindUplink:
			// its interfaces went with the gateway namespace; the index is free again
		case KindMasks:
			d.collect(id) // the last connections, before the gateway's directory goes
			err = os.RemoveAll(d.maskDir(id))
			os.RemoveAll(filepath.Join(d.SessionRoot, id, "gateway"))
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
	delete(d.offsets, id)
	end := map[string]any{"end_reason": reason}
	if s, err := d.Journal.Load(id); err == nil {
		var incomplete []string
		for _, r := range s.Live() {
			incomplete = append(incomplete, r.Kind+" "+r.Name+": "+r.Note)
		}
		if len(incomplete) > 0 {
			end["teardown_incomplete"] = incomplete
		}
		if s.EndReason != "" {
			end["end_reason"] = s.EndReason
		}
	}
	d.audit(id, auditlog.Events, "session_end", end)
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
	if err := d.Network.Root(ctx); err != nil {
		return fmt.Errorf("the VM's network rules: %w", err)
	}
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
