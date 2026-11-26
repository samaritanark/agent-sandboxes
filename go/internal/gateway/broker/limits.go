package broker

import (
	"sync"
	"time"
)

// Per-credential limits (credential-brokering design, "Rate-limit and quota per credential"): an
// agent must not burn a credential's quota or bill, or use the broker as a request amplifier.
// Each credential has a token bucket (a rate and a burst) and an optional quota of injections for
// the session's life, shared by all its bindings. Only injected requests count; a refusal costs nothing.

// Defaults for a binding that names no rate (S8 records them; the owner may tune them).
const (
	DefaultRatePerMinute = 300
	DefaultBurst         = 60
)

// MaxLimit bounds every limit field.
const MaxLimit = 1_000_000

type bucket struct {
	tokens   float64
	last     time.Time
	perSec   float64
	burst    float64
	quota    int // 0: none
	injected int
}

type limiter struct {
	mu      sync.Mutex
	now     func() time.Time
	buckets map[string]*bucket
}

func newLimiter(bs []Binding, now func() time.Time) *limiter {
	l := &limiter{now: now, buckets: map[string]*bucket{}}
	t := now()
	for _, b := range bs {
		if l.buckets[b.Ref] != nil {
			continue // one bucket per credential: its first binding's limits (sessionspec keeps them equal)
		}
		rate, burst := b.RatePerMinute, b.Burst
		if rate == 0 {
			rate = DefaultRatePerMinute
		}
		if burst == 0 {
			burst = DefaultBurst
		}
		l.buckets[b.Ref] = &bucket{tokens: float64(burst), last: t, perSec: float64(rate) / 60, burst: float64(burst), quota: b.Quota}
	}
	return l
}

// spend takes one injection from each of refs, or from none: it returns the event and reference
// of the first that is exhausted.
func (l *limiter) spend(refs []string) (event, ref string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	for _, r := range refs {
		b := l.buckets[r]
		if el := t.Sub(b.last).Seconds(); el > 0 {
			b.tokens += el * b.perSec
			if b.tokens > b.burst {
				b.tokens = b.burst
			}
			b.last = t
		}
		if b.quota > 0 && b.injected >= b.quota {
			return "credential_quota_exhausted", r
		}
		if b.tokens < 1 {
			return "credential_rate_limited", r
		}
	}
	for _, r := range refs {
		l.buckets[r].tokens--
		l.buckets[r].injected++
	}
	return "", ""
}
