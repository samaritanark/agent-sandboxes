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
