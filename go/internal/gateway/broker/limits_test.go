package broker

import (
	"testing"
	"time"
)

func limitedSet(t *testing.T, bs []Binding) (*Set, *time.Time) {
	t.Helper()
	s, err := NewSet(bs)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	s.limits = newLimiter(bs, func() time.Time { return now })
	return s, &now
}

func gh(rate, burst, quota int) Binding {
	return Binding{Ref: "github", Hosts: []string{"api.github.com"}, Inject: "bearer", Placeholder: phGH, Value: "ghp_realtoken1234567890",
		RatePerMinute: rate, Burst: burst, Quota: quota}
}

var ghReq = Request{Host: "api.github.com", Path: "/", Headers: hdr("authorization", "Bearer "+phGH)}

func TestRateLimit(t *testing.T) {
	s, now := limitedSet(t, []Binding{gh(60, 3, 0)})
	for i := 0; i < 3; i++ {
		if o := s.Decide(ghReq); !o.Injected {
			t.Fatalf("within the burst, request %d: %+v", i, o)
		}
	}
	o := s.Decide(ghReq)
	if !o.Refuse || !o.TooMany || o.Event != "credential_rate_limited" || o.Ref != "github" {
		t.Fatalf("past the burst: %+v", o)
	}
	*now = now.Add(999 * time.Millisecond)
	if o := s.Decide(ghReq); !o.Refuse {
		t.Error("a token before a second passed")
	}
	*now = now.Add(2 * time.Millisecond)
	if o := s.Decide(ghReq); !o.Injected {
		t.Errorf("one a second at 60 a minute: %+v", o)
	}
	// a long idle fills the bucket to its burst, no more
	*now = now.Add(time.Hour)
	n := 0
	for s.Decide(ghReq).Injected {
		n++
	}
	if n != 3 {
		t.Errorf("after an hour, %d in a row", n)
	}
	// a refusal costs nothing: requests without the placeholder do not drain the bucket
	*now = now.Add(time.Hour)
	for i := 0; i < 10; i++ {
		if o := s.Decide(Request{Host: "api.github.com", Path: "/"}); o.Event != "credential_missing" {
			t.Fatal(o)
		}
	}
	if !s.Decide(ghReq).Injected {
		t.Error("refusals drained the bucket")
	}
}

func TestQuota(t *testing.T) {
	s, now := limitedSet(t, []Binding{gh(MaxLimit, MaxLimit, 2)})
	s.Decide(ghReq)
	s.Decide(ghReq)
	*now = now.Add(24 * time.Hour)
	if o := s.Decide(ghReq); !o.TooMany || o.Event != "credential_quota_exhausted" {
		t.Errorf("past the quota: %+v", o)
	}
}

func TestDefaultLimits(t *testing.T) {
	s, now := limitedSet(t, []Binding{gh(0, 0, 0)})
	count := func() int {
		n := 0
		for i := 0; i < DefaultBurst+5; i++ {
			if s.Decide(ghReq).Injected {
				n++
			}
		}
		return n
	}
	if n := count(); n != DefaultBurst {
		t.Errorf("default burst: %d", n)
	}
	// the default rate refills a second's worth in a second
	*now = now.Add(time.Second)
	if n := count(); n != DefaultRatePerMinute/60 {
		t.Errorf("default rate: %d a second", n)
	}
}

// TestLimitsAllOrNothing: a request that uses two credentials spends from both or from neither.
func TestLimitsAllOrNothing(t *testing.T) {
	a := gh(60, 5, 0)
	a.Hosts = []string{"api.example.com"}
	b := Binding{Ref: "other", Hosts: []string{"api.example.com"}, Inject: "header:x-key", Placeholder: phAn, Value: "other-value-123",
		RatePerMinute: 60, Burst: 1}
	s, _ := limitedSet(t, []Binding{a, b})
	both := Request{Host: "api.example.com", Path: "/", Headers: hdr("authorization", "Bearer "+phGH, "x-key", phAn)}
	if o := s.Decide(both); !o.Injected {
		t.Fatal(o)
	}
	for i := 0; i < 3; i++ {
		if o := s.Decide(both); o.Ref != "other" || !o.TooMany {
			t.Fatalf("%+v", o)
		}
	}
	if got := s.limits.buckets["github"].tokens; got != 4 {
		t.Errorf("the refused requests spent the other credential: %v left", got)
	}
}

func TestLimitsChecked(t *testing.T) {
	for _, b := range []Binding{gh(-1, 0, 0), gh(0, MaxLimit+1, 0), gh(0, 0, -5)} {
		if _, err := NewSet([]Binding{b}); err == nil {
			t.Errorf("accepted %+v", b)
		}
	}
}

// TestLimitsPerCredential: two bindings of one credential share its bucket.
func TestLimitsPerCredential(t *testing.T) {
	a := gh(60, 2, 0)
	b := gh(60, 2, 0)
	b.Hosts, b.Inject, b.Placeholder = []string{"uploads.github.com"}, "header:x-token", phAn
	s, _ := limitedSet(t, []Binding{a, b})
	up := Request{Host: "uploads.github.com", Path: "/", Headers: hdr("x-token", phAn)}
	if !s.Decide(ghReq).Injected || !s.Decide(up).Injected {
		t.Fatal("within the burst")
	}
	if o := s.Decide(up); !o.TooMany {
		t.Errorf("the second binding has its own bucket: %+v", o)
	}
	// one request that uses two bindings of one credential spends one injection
	c := gh(60, 2, 0)
	c.Inject, c.Placeholder = "header:x-token", phAn
	s, _ = limitedSet(t, []Binding{a, c})
	two := Request{Host: "api.github.com", Path: "/", Headers: hdr("authorization", "Bearer "+phGH, "x-token", phAn)}
	if !s.Decide(two).Injected || !s.Decide(two).Injected {
		t.Error("two bindings of one credential spent two injections a request")
	}
}
