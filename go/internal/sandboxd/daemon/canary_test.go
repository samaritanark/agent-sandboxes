package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/runtime"
)

// canaryRT plays sandbox-canary: it reads the probe through the "in" mount and writes its result
// through the "out" one, as the program does in a real sandbox.
type canaryRT struct {
	*fakeRuntime
	release string
	uid     int
	probe   func(string) string // what it reads
	code    int
	seen    runtime.MicroVM
}

func (c *canaryRT) Canary(_ context.Context, m runtime.MicroVM, rootfs string, _ time.Duration) (int, error) {
	c.seen = m
	var in, out string
	for _, mt := range m.Mounts {
		switch mt.Target {
		case "/canary/in":
			in = mt.Source
		case "/canary/out":
			out = mt.Source
		}
	}
	b, _ := os.ReadFile(filepath.Join(in, "probe"))
	r := canaryResult{Release: c.release, Probe: c.probe(strings.TrimSpace(string(b))), UID: c.uid}
	j, _ := json.Marshal(r)
	os.WriteFile(filepath.Join(out, "result.json"), j, 0o644)
	return c.code, nil
}

// TestCanary: the canary passes when it ran as the agent, in a namespace of its own, read the probe
// through its mount, and saw a kernel that is not the VM's; it fails, saying why, otherwise; and
// nothing of it is left behind.
func TestCanary(t *testing.T) {
	r := newRig(t)
	same := func(s string) string { return s }
	for _, c := range []struct {
		rt   *canaryRT
		kind string
		want string // "" passes
	}{
		{&canaryRT{release: "6.12.0-kata", uid: AgentUID, probe: same}, "kata", ""},
		{&canaryRT{release: "4.19.0", uid: AgentUID, probe: same}, "gvisor", ""},
		{&canaryRT{release: "6.8.0-vm", uid: AgentUID, probe: same}, "kata", "the VM's own kernel"},
		{&canaryRT{release: "6.12.0-kata", uid: 0, probe: same}, "kata", "ran as uid 0"},
		{&canaryRT{release: "6.12.0-kata", uid: AgentUID, probe: func(string) string { return "" }}, "kata", "did not read the probe"},
		{&canaryRT{release: "6.12.0-kata", uid: AgentUID, probe: same, code: 3}, "kata", "exited 3"},
		{&canaryRT{release: "6.12.0-kata", uid: AgentUID, probe: same}, "runc", "unknown runtime"},
	} {
		c.rt.fakeRuntime = r.rt
		r.d.Runtime = c.rt
		r.d.KernelRelease = func() string { return "6.8.0-vm" }
		got, err := r.d.Canary(context.Background(), c.kind)
		if c.want == "" {
			if err != nil || !strings.Contains(got, "kernel "+c.rt.release) {
				t.Errorf("%+v: %q %v", c.rt, got, err)
			}
			if m := c.rt.seen; m.Runtime != c.kind || m.UID != AgentUID || !strings.HasSuffix(m.NetNS, "sbx-canary-"+c.kind) {
				t.Errorf("canary %+v", m)
			}
		} else if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: want %q, got %q %v", c.rt, c.want, got, err)
		}
		if r.ns.names["sbx-canary-"+c.kind] {
			t.Error("the canary's namespace was left")
		}
		if left, _ := filepath.Glob(filepath.Join(r.d.SessionRoot, ".canary-*")); len(left) != 0 {
			t.Errorf("left: %v", left)
		}
	}
}
