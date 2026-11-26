package limits

import (
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

func sess(mem int, deps ...int) *sessionspec.Spec {
	s := &sessionspec.Spec{Resources: sessionspec.Resources{MemoryMiB: mem}}
	for _, d := range deps {
		s.Dependencies = append(s.Dependencies, sessionspec.Dependency{Resources: sessionspec.Resources{MemoryMiB: d}})
	}
	return s
}

func TestAdmit(t *testing.T) {
	b := Budget{VMMemoryMiB: 16384} // 14336 usable
	if c := b.Cost(sess(6144, 1024)); c != 6144+1024+2*256 {
		t.Errorf("cost %d", c)
	}
	held := []*sessionspec.Spec{sess(6144)}                 // 6400 of 14336
	if err := b.Admit(held, sess(6144, 1024)); err != nil { // 6400 + 7680 = 14080 fits
		t.Errorf("a fitting session refused: %v", err)
	}
	held = append(held, sess(6144, 1024))
	if err := b.Admit(held, sess(1024)); err == nil || !strings.Contains(err.Error(), "not enough memory") {
		t.Errorf("over budget admitted: %v", err)
	}
}

func TestAdmitBoundary(t *testing.T) {
	b := Budget{VMMemoryMiB: 16384, ReserveMiB: 2048, OverheadMiB: 256}
	held := []*sessionspec.Spec{sess(6144)} // 6400 used, 7936 free
	if err := b.Admit(held, sess(7680)); err != nil {
		t.Errorf("exact fit refused: %v", err)
	}
	if err := b.Admit(held, sess(7681)); err == nil {
		t.Error("one MiB over admitted")
	}
	if err := (Budget{VMMemoryMiB: 1024}).Admit(nil, sess(256)); err == nil {
		t.Error("a VM smaller than its reserve admitted a session")
	}
}

func TestExpiry(t *testing.T) {
	t0 := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	e := Expiry{}
	cases := []struct {
		name string
		t    Times
		now  time.Duration
		want bool
	}{
		{"fresh, never attached", Times{Started: t0}, 119 * time.Second, false},
		{"never attached past grace", Times{Started: t0}, 120 * time.Second, true},
		{"heartbeat keeps it", Times{Started: t0, LastHeartbeat: t0.Add(10 * time.Minute)}, 11 * time.Minute, false},
		{"heartbeat stopped", Times{Started: t0, LastHeartbeat: t0.Add(10 * time.Minute)}, 12 * time.Minute, true},
		{"attached holds the lease", Times{Started: t0, Attached: true}, 30 * 24 * time.Hour, false},
		{"detached, within grace", Times{Started: t0, LastHeartbeat: t0.Add(time.Hour)}, time.Hour + 119*time.Second, false},
		{"keep-alive detached, short", Times{Started: t0, KeepAlive: true, LastDetached: t0.Add(time.Hour)}, 20 * time.Hour, false},
		{"keep-alive idle", Times{Started: t0, KeepAlive: true, LastDetached: t0.Add(time.Hour)}, 25 * time.Hour, true},
		{"keep-alive attached, not idle", Times{Started: t0, KeepAlive: true, Attached: true}, 6 * 24 * time.Hour, false},
		{"keep-alive lifetime", Times{Started: t0, KeepAlive: true, Attached: true}, 7 * 24 * time.Hour, true},
		{"keep-alive ignores heartbeats", Times{Started: t0, KeepAlive: true, Attached: true}, time.Hour, false},
	}
	for _, c := range cases {
		got, why := e.Expired(c.t, t0.Add(c.now))
		if got != c.want || got && why == "" {
			t.Errorf("%s: %v %q", c.name, got, why)
		}
	}
	short := Expiry{LeaseGrace: 5 * time.Second}
	if ok, _ := short.Expired(Times{Started: t0}, t0.Add(5*time.Second)); !ok {
		t.Error("a configured grace was ignored")
	}
}

func TestAgentMemory(t *testing.T) {
	for _, c := range []struct {
		vm   int
		deps []int
		want int
	}{
		{16384, nil, AgentMaxMiB},
		{8192, nil, 5888},        // 8192 - 2048 - 256
		{7936, nil, 5632},        // a minimum VM's MemTotal
		{7900, nil, 5376},        // 5596 rounded down to 256
		{8448, nil, AgentMaxMiB}, // exactly the cap
		{8447, nil, 5888},        // just under it
		{7936, []int{512}, 4864}, // a dependency's memory and overhead
		{7936, []int{512, 1024}, 3584},
		{3000, nil, AgentMinMiB}, // too small: the floor, refused at admission
	} {
		if got := (Budget{VMMemoryMiB: c.vm}).AgentMemory(c.deps); got != c.want {
			t.Errorf("AgentMemory(%d, %v) = %d, want %d", c.vm, c.deps, got, c.want)
		}
	}
	// the default always fits an otherwise idle VM, down to the floor
	for vm := 3328; vm <= 20000; vm += 7 {
		for _, deps := range [][]int{nil, {512}, {512, 1024}} {
			b := Budget{VMMemoryMiB: vm}
			m := b.AgentMemory(deps)
			if m == AgentMinMiB {
				continue
			}
			if err := b.Admit(nil, sess(m, deps...)); err != nil {
				t.Fatalf("vm %d deps %v: default %d refused: %v", vm, deps, m, err)
			}
		}
	}
}

func TestMemTotalMiB(t *testing.T) {
	n, err := MemTotalMiB(strings.NewReader("MemFree:  100 kB\nMemTotal:        8126464 kB\n"))
	if err != nil || n != 7936 {
		t.Errorf("%d %v", n, err)
	}
	if _, err := MemTotalMiB(strings.NewReader("MemFree: 1 kB\n")); err == nil {
		t.Error("no MemTotal accepted")
	}
	if _, err := MemTotalMiB(strings.NewReader("MemTotal: x kB\n")); err == nil {
		t.Error("a bad number accepted")
	}
}
