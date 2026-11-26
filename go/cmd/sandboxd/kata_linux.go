//go:build linux

package main

// A microVM whose Kata shim stops answering (seen: a guest whose agent hung, the shim's calls
// timing out) cannot be torn down through containerd, and would hold its memory and block
// sandboxd's start. Destroy then kills that microVM's own processes, the shim and the hypervisor,
// found by the container ID in their command lines, and tries again: containerd then sees a dead
// shim and lets the container go.

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func (k kata) Destroy(ctx context.Context, id string, grace time.Duration) error {
	err := k.Runtime.Destroy(ctx, id, grace)
	if err == nil {
		return nil
	}
	if n := killMicroVM(id); n == 0 {
		return err
	}
	time.Sleep(2 * time.Second)
	return k.Runtime.Destroy(ctx, id, grace)
}

// killMicroVM sends SIGKILL to the Kata shim and hypervisor processes of container id and returns
// how many it killed.
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
	return n
}
