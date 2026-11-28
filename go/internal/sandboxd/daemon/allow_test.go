package daemon

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// TestAllow: names added to a running session reach its spec and its gateway's policy (a new
// generation, reloaded), and the audit log; names already there change nothing; a name the spec
// refuses, a session that is not running, and a gateway that fails to reload leave it as it was.
func TestAllow(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, err := r.d.Start(ctx, spec("s-al", 4096)); err != nil {
		t.Fatal(err)
	}
	n, err := r.d.Allow(ctx, "s-al", []string{"pypi.org", "api.anthropic.com", " files.pythonhosted.org "})
	if err != nil || n != 2 {
		t.Fatalf("%d %v", n, err)
	}
	pol := r.gw.policies["s-al"]
	if pol.Generation != 1 || !slices.Contains(pol.Links[0].Allow, "pypi.org") || !slices.Contains(pol.Links[0].Allow, "files.pythonhosted.org") {
		t.Errorf("policy %+v", pol.Links[0].Allow)
	}
	s, _ := r.d.Journal.Load("s-al")
	if !slices.Contains(s.Spec.Egress.Allow, "pypi.org") {
		t.Errorf("spec %v", s.Spec.Egress.Allow)
	}
	if ev := strings.Join(auditTypes(t, r.d.AuditRoot, "s-al", "events.jsonl"), ","); !strings.Contains(ev, "allowlist_extended") {
		t.Errorf("events %s", ev)
	}
	// nothing new: no reload
	if n, err := r.d.Allow(ctx, "s-al", []string{"pypi.org"}); err != nil || n != 0 || r.gw.reloads != 1 {
		t.Errorf("repeat: %d %v, %d reloads", n, err, r.gw.reloads)
	}
	// refused names and failures change nothing
	for _, bad := range [][]string{{"bad name!"}, {"*"}} {
		if _, err := r.d.Allow(ctx, "s-al", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	r.gw.reloadErr = context.DeadlineExceeded
	if _, err := r.d.Allow(ctx, "s-al", []string{"example.org"}); err == nil {
		t.Error("a failed reload was reported as done")
	}
	if s, _ := r.d.Journal.Load("s-al"); slices.Contains(s.Spec.Egress.Allow, "example.org") {
		t.Error("the spec took a name its gateway never served")
	}
	if _, err := r.d.Allow(ctx, "s-none", []string{"example.org"}); err == nil {
		t.Error("a session that is not running was widened")
	}
}
