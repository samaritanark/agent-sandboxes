package runtime

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"syscall"
)

// Mount is a bind mount of a VM path into the guest.
type Mount struct {
	Source, Target string
	ReadOnly       bool
}

// Namespace is sandboxd's containerd namespace; nothing else uses it.
const Namespace = "sandbox"

// The isolation runtimes a session can run under (owner decision, 2026-11-27): Kata (a microVM
// with its own kernel, the default) or gVisor (a user-space kernel, faster where the appliance VM
// makes Kata nested). Both get the same hardening, network, and mounts.
const (
	Kata   = "kata"
	GVisor = "gvisor"
)

// MicroVM describes one microVM (a gVisor sandbox under GVisor): a session's agent or one of its
// dependencies.
type MicroVM struct {
	ID      string
	Runtime string // Kata or GVisor; empty is Kata
	Image   string // pinned by digest
	Args    []string
	// ImageArgs, when Args is empty, follow the image's entrypoint in place of its default command
	// (Kubernetes' args: a catalogue dependency's args:).
	ImageArgs []string
	Env       []string // NAME=value
	UID, GID  uint32   // never 0
	Mounts    []Mount
	NetNS     string // the network namespace's path; required
	CPUs      float64
	MemoryMiB int
	Hostname  string
}

func clean(p string) bool { return strings.HasPrefix(p, "/") && path.Clean(p) == p }

// Check refuses a description sandboxd must never run.
func (m MicroVM) Check() error {
	switch {
	case m.ID == "" || m.Image == "":
		return errors.New("runtime: microVM needs an id and an image")
	case m.UID == 0 || m.GID == 0:
		return fmt.Errorf("runtime: %s would run as root", m.ID)
	case m.NetNS == "":
		return fmt.Errorf("runtime: %s has no network namespace of its own", m.ID)
	case m.MemoryMiB <= 0 || m.CPUs <= 0:
		return fmt.Errorf("runtime: %s has no resource limits", m.ID)
	case m.Runtime != "" && m.Runtime != Kata && m.Runtime != GVisor:
		return fmt.Errorf("runtime: %s: unknown runtime %q", m.ID, m.Runtime)
	}
	for _, mt := range m.Mounts {
		if !clean(mt.Source) || !clean(mt.Target) || mt.Target == "/" {
			return fmt.Errorf("runtime: %s: bad mount %s -> %s", m.ID, mt.Source, mt.Target)
		}
	}
	return nil
}

// Process is a command run in a running microVM (Runtime.Exec).
type Process interface {
	Resize(ctx context.Context, cols, rows uint32) error
	Kill(ctx context.Context, sig syscall.Signal) error
	// Wait returns the exit status once the process ends, and removes it.
	Wait(ctx context.Context) (int, error)
}
