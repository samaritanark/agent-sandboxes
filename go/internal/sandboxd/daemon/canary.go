package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/runtime"
)

// The capability probe's canary (design 5.2.3 check 3): `sandbox doctor` asks sandboxd to run
// sandbox-canary under a runtime, in a network namespace of its own, with a read-only root file
// system that holds nothing else. It must start, report a kernel that is not the VM's (Kata's
// guest kernel, or gVisor's), read a probe file through a mount, run as the agent's user, and be
// torn down.

// CanaryRoot is the canary's root file system in the appliance image, and CanaryBin its program.
const (
	CanaryRoot = "/usr/lib/sandbox/canary/rootfs"
	CanaryBin  = "/sandbox-canary"
)

// CanaryRuntime runs one canary sandbox to completion (runtime.Runtime.Canary in production).
type CanaryRuntime interface {
	Canary(ctx context.Context, m runtime.MicroVM, rootfs string, timeout time.Duration) (int, error)
}

// canaryResult is what sandbox-canary writes.
type canaryResult struct {
	Release, Version, Probe string
	UID                     int
}

// Canary runs the canary under kind and describes what it found; an error says which part failed.
func (d *Daemon) Canary(ctx context.Context, kind string) (string, error) {
	cr, ok := d.Runtime.(CanaryRuntime)
	if !ok {
		return "", errors.New("this sandboxd cannot run a canary")
	}
	if kind != runtime.Kata && kind != runtime.GVisor {
		return "", fmt.Errorf("unknown runtime %q", kind)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.ready {
		return "", ErrNotReady
	}
	id := "canary-" + kind
	ns := "sbx-" + id
	if err := d.NetNS.Create(ctx, ns); err != nil {
		return "", fmt.Errorf("network namespace: %w", err)
	}
	defer d.NetNS.Delete(context.WithoutCancel(ctx), ns)
	dir := filepath.Join(d.SessionRoot, "."+id)
	os.RemoveAll(dir)
	defer os.RemoveAll(dir)
	in, out := filepath.Join(dir, "in"), filepath.Join(dir, "out")
	for _, p := range []string{in, out} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			return "", err
		}
	}
	if err := os.Chown(out, AgentUID, AgentUID); err != nil && !errors.Is(err, os.ErrPermission) {
		return "", err
	}
	nonce := make([]byte, 8)
	rand.Read(nonce)
	probe := "canary " + hex.EncodeToString(nonce)
	if err := os.WriteFile(filepath.Join(in, "probe"), []byte(probe+"\n"), 0o644); err != nil {
		return "", err
	}
	m := runtime.MicroVM{ID: id, Runtime: kind, Args: []string{CanaryBin}, UID: AgentUID, GID: AgentUID,
		NetNS: d.NetNSPath(ns), CPUs: 1, MemoryMiB: 256, Hostname: "canary",
		Mounts: []runtime.Mount{{Source: in, Target: "/canary/in", ReadOnly: true}, {Source: out, Target: "/canary/out"}}}
	start := d.now()
	code, err := cr.Canary(ctx, m, CanaryRoot, 2*time.Minute)
	if err != nil {
		return "", fmt.Errorf("did not run: %w", err)
	}
	if code != 0 {
		return "", fmt.Errorf("exited %d", code)
	}
	b, err := os.ReadFile(filepath.Join(out, "result.json"))
	if err != nil {
		return "", errors.New("wrote no result")
	}
	var r canaryResult
	if err := json.Unmarshal(b, &r); err != nil {
		return "", errors.New("wrote a result that is not JSON")
	}
	switch {
	case r.Probe != probe:
		return "", errors.New("did not read the probe file through its mount")
	case r.UID != AgentUID:
		return "", fmt.Errorf("ran as uid %d, not %d", r.UID, AgentUID)
	case r.Release == "" || r.Release == d.vmKernel():
		return "", fmt.Errorf("reported the VM's own kernel (%s), so it is not isolated", r.Release)
	}
	return fmt.Sprintf("kernel %s, probe read, %.1f s", r.Release, d.now().Sub(start).Seconds()), nil
}

// vmKernel is the VM's own kernel release.
func (d *Daemon) vmKernel() string {
	if d.KernelRelease != nil {
		return d.KernelRelease()
	}
	b, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return strings.TrimSpace(string(b))
}
