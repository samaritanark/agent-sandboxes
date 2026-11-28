//go:build linux

package main

// A microVM whose Kata shim stops answering (seen: a guest whose agent hung, the shim's calls
// timing out) cannot be torn down through containerd, and would hold its memory and block
// sandboxd's start. Destroy then kills that microVM's own processes, the shim and the hypervisor,
// found by the container ID in their command lines, and tries again: containerd then sees a dead
// shim and lets the container go. A gVisor sandbox is handled the same way: its shim, sandbox, and
// gofer by their command lines, and its sentry, whose processes have none, through its cgroup.

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/containerd/containerd/v2/pkg/cio"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/runtime"
)

// microVMs adapts runtime.Runtime to the daemon: no terminal is attached yet, so output is dropped.
type microVMs struct{ *runtime.Runtime }

func (m microVMs) Start(ctx context.Context, id string) error {
	return m.Runtime.Start(ctx, id, cio.NullIO)
}

func (m microVMs) Restart(ctx context.Context, id string) error {
	return m.Runtime.Restart(ctx, id, cio.NullIO)
}

func (m microVMs) Destroy(ctx context.Context, id string, grace time.Duration) error {
	err := m.Runtime.Destroy(ctx, id, grace)
	if err == nil {
		return nil
	}
	if n := killMicroVM(id); n == 0 {
		return err
	}
	time.Sleep(2 * time.Second)
	return m.Runtime.Destroy(ctx, id, grace)
}

// killMicroVM sends SIGKILL to the runtime processes of container id and returns how many it
// killed (a cgroup it emptied counts as one).
func killMicroVM(id string) int {
	ents, _ := os.ReadDir("/proc")
	n := 0
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cmd, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil || !microVMProcess(cmd, id) {
			continue
		}
		if syscall.Kill(pid, syscall.SIGKILL) == nil {
			n++
		}
	}
	// cgroup.kill kills every process in the cgroup and its descendants (Linux 5.14)
	if procs, err := os.ReadFile(filepath.Join(microVMCgroup(id), "cgroup.procs")); err == nil && len(procs) > 0 {
		if os.WriteFile(filepath.Join(microVMCgroup(id), "cgroup.kill"), []byte("1"), 0) == nil {
			n++
		}
	}
	return n
}
