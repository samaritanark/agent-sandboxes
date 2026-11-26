// Package limits holds sandboxd's admission and expiry decisions as pure functions: the memory
// budget (design 5.5.3) and when a session's attach lease or keep-alive limits end it (5.4.3
// items 4 and 6).
package limits

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// Defaults.
const (
	// DefaultReserveMiB is kept free for the VM itself (sandboxd, containerd, the gateways): v2's
	// in-VM HOST_RESERVE_MEM_GI.
	DefaultReserveMiB = 2048
	// DefaultOverheadMiB is each microVM's memory outside its guest: S1 measured about 197 MiB of
	// host-side RSS (Cloud Hypervisor, the shim, virtiofsd) for an idle microVM.
	DefaultOverheadMiB = 256
	// DefaultLeaseGrace is how long a session outlives its last heartbeat (v2's
	// SANDBOX_TEARDOWN_REMINDER_GRACE).
	DefaultLeaseGrace = 120 * time.Second
	// DefaultKeepAliveIdle and DefaultKeepAliveMax bound a keep-alive session: idle is the time
	// with no client attached (issue #94).
	DefaultKeepAliveIdle = 24 * time.Hour
	DefaultKeepAliveMax  = 7 * 24 * time.Hour
)

// Budget is the VM's memory for microVMs.
type Budget struct {
	VMMemoryMiB int
	ReserveMiB  int // 0 means DefaultReserveMiB
	OverheadMiB int // 0 means DefaultOverheadMiB
}

func (b Budget) overhead() int {
	if b.OverheadMiB > 0 {
		return b.OverheadMiB
	}
	return DefaultOverheadMiB
}

func (b Budget) reserve() int {
	if b.ReserveMiB > 0 {
		return b.ReserveMiB
	}
	return DefaultReserveMiB
}

// Cost is the memory a session commits: its microVM and every dependency's, each with overhead.
func (b Budget) Cost(s *sessionspec.Spec) int {
	n := s.Resources.MemoryMiB + b.overhead()
	for _, d := range s.Dependencies {
		n += d.Resources.MemoryMiB + b.overhead()
	}
	return n
}

// Admit refuses spec if it would commit more memory than the VM has after the reserve, given the
// sessions already holding memory. Memory is not overcommitted; CPU may be.
func (b Budget) Admit(holding []*sessionspec.Spec, spec *sessionspec.Spec) error {
	used := 0
	for _, h := range holding {
		used += b.Cost(h)
	}
	avail := b.VMMemoryMiB - b.reserve()
	if need := b.Cost(spec); used+need > avail {
		return fmt.Errorf("not enough memory: the session needs %d MiB (with %d dependencies), %d MiB of %d is free (the VM's %d MiB less a %d MiB reserve); stop a session or give the VM more memory (sandbox install --vm-memory)",
			need, len(spec.Dependencies), max(avail-used, 0), avail, b.VMMemoryMiB, b.reserve())
	}
	return nil
}

// AgentMaxMiB is the agent microVM's default memory on a VM with room for it: v2's pod limit.
// AgentMinMiB is the floor of the scaled default; a VM too small for it is refused at admission.
const (
	AgentMaxMiB = 6 << 10
	AgentMinMiB = 1 << 10
)

// AgentMemory is the agent microVM's default memory (owner decision, 2026-11-26): what the VM has
// for one session after the reserve, the agent's overhead, and its dependencies' cost (depMiB is
// their guest memory; each also costs an overhead), rounded down to 256 MiB and capped at
// AgentMaxMiB. Other sessions do not shrink it: admission refuses a launch that does not fit.
func (b Budget) AgentMemory(depMiB []int) int {
	n := b.VMMemoryMiB - b.reserve() - b.overhead()
	for _, d := range depMiB {
		n -= d + b.overhead()
	}
	n &^= 255
	return max(min(n, AgentMaxMiB), AgentMinMiB)
}

// MemTotalMiB reads MemTotal from /proc/meminfo's text.
func MemTotalMiB(r io.Reader) (int, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if fs := strings.Fields(sc.Text()); len(fs) >= 2 && fs[0] == "MemTotal:" {
			kb, err := strconv.Atoi(fs[1])
			return kb / 1024, err
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("no MemTotal in /proc/meminfo")
}

// Expiry is the operator's limits on how long sessions live.
type Expiry struct {
	LeaseGrace    time.Duration // 0 means DefaultLeaseGrace
	KeepAliveIdle time.Duration // 0 means DefaultKeepAliveIdle
	KeepAliveMax  time.Duration // 0 means DefaultKeepAliveMax
}

// MaxKeepAlive is the longest a keep-alive session lives.
func (e Expiry) MaxKeepAlive() time.Duration { return or(e.KeepAliveMax, DefaultKeepAliveMax) }

// Times are what sandboxd observed of a running session (never what the microVM reports).
type Times struct {
	Started       time.Time
	LastHeartbeat time.Time // the host binary's last attach-lease renewal
	Attached      bool      // a client is attached now
	LastDetached  time.Time // when the last client went away
	KeepAlive     bool
}

func or(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// Expired reports whether the session must be torn down now, and why (its end reason).
func (e Expiry) Expired(t Times, now time.Time) (bool, string) {
	if t.KeepAlive {
		if max := or(e.KeepAliveMax, DefaultKeepAliveMax); now.Sub(t.Started) >= max {
			return true, fmt.Sprintf("keep-alive lifetime reached (%v)", max)
		}
		if idle := or(e.KeepAliveIdle, DefaultKeepAliveIdle); !t.Attached && now.Sub(latest(t.LastDetached, t.Started)) >= idle {
			return true, fmt.Sprintf("keep-alive idle for %v", idle)
		}
		return false, ""
	}
	// An attached terminal holds the lease; the grace counts from its end (Attach sets
	// LastHeartbeat then). A session that never got a heartbeat counts from its start, so a
	// signal during launch, before attach, still ends it.
	if t.Attached {
		return false, ""
	}
	if grace := or(e.LeaseGrace, DefaultLeaseGrace); now.Sub(latest(t.LastHeartbeat, t.Started)) >= grace {
		return true, fmt.Sprintf("attach lease expired (no heartbeat for %v)", grace)
	}
	return false, ""
}

func latest(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
