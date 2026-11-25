//go:build linux

package runtime

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"

	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/contrib/seccomp"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	// Namespace is sandboxd's containerd namespace; nothing else uses it.
	Namespace = "sandbox"
	// KataRuntime is the shim, found as containerd-shim-kata-v2 on containerd's PATH.
	KataRuntime = "io.containerd.kata.v2"
	// KataConfig selects Cloud Hypervisor (S1: Kata accepts only its shipped configuration
	// files, so the selection is the runtime's config path).
	KataConfig = "/opt/kata/share/defaults/kata-containers/configuration-clh.toml"
	// Socket is containerd's.
	Socket = "/run/containerd/containerd.sock"
)

// MicroVM describes one microVM: a session's agent or one of its dependencies.
type MicroVM struct {
	ID        string
	Image     string // pinned by digest
	Args      []string
	Env       []string // NAME=value
	UID, GID  uint32   // never 0
	Mounts    []specs.Mount
	NetNS     string // the network namespace's path; required
	CPUs      float64
	MemoryMiB int
	Hostname  string
}

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
	}
	for _, mt := range m.Mounts {
		if mt.Type != "bind" {
			return fmt.Errorf("runtime: %s: only bind mounts, not %q", m.ID, mt.Type)
		}
	}
	return nil
}

// dropAll removes every capability from the process, in every set.
func dropAll(_ context.Context, _ oci.Client, _ *containers.Container, s *oci.Spec) error {
	if s.Process == nil {
		s.Process = &specs.Process{}
	}
	s.Process.Capabilities = &specs.LinuxCapabilities{Bounding: []string{}, Effective: []string{},
		Permitted: []string{}, Inheritable: []string{}, Ambient: []string{}}
	return nil
}

// SpecOpts is the OCI spec of m, hardening last so nothing before it can widen it.
func SpecOpts(m MicroVM) []oci.SpecOpts {
	period := uint64(100000)
	opts := []oci.SpecOpts{
		oci.WithDefaultSpec(),
		oci.WithProcessArgs(m.Args...),
		oci.WithEnv(m.Env),
		oci.WithMounts(m.Mounts),
		oci.WithLinuxNamespace(specs.LinuxNamespace{Type: specs.NetworkNamespace, Path: m.NetNS}),
		oci.WithMemoryLimit(uint64(m.MemoryMiB) << 20),
		oci.WithCPUCFS(int64(m.CPUs*float64(period)), period),
	}
	if m.Hostname != "" {
		opts = append(opts, oci.WithHostname(m.Hostname))
	}
	return append(opts,
		oci.WithUIDGID(m.UID, m.GID),
		oci.WithNoNewPrivileges,
		dropAll,
		seccomp.WithDefaultProfile(),
	)
}

// Runtime drives containerd.
type Runtime struct {
	c *client.Client
}

// Open connects to containerd.
func Open(socket string) (*Runtime, error) {
	c, err := client.New(socket, client.WithDefaultNamespace(Namespace))
	if err != nil {
		return nil, err
	}
	return &Runtime{c: c}, nil
}

func (r *Runtime) Close() error { return r.c.Close() }

func ctxNS(ctx context.Context) context.Context { return namespaces.WithNamespace(ctx, Namespace) }

// Image returns the image by its digest-pinned reference, pulling and unpacking it if needed.
func (r *Runtime) image(ctx context.Context, ref string) (client.Image, error) {
	img, err := r.c.GetImage(ctx, ref)
	if err == nil {
		return img, nil
	}
	if !errdefs.IsNotFound(err) {
		return nil, err
	}
	return r.c.Pull(ctx, ref, client.WithPullUnpack)
}

// Create makes the container for m (the microVM boots at Start).
func (r *Runtime) Create(ctx context.Context, m MicroVM) error {
	if err := m.Check(); err != nil {
		return err
	}
	ctx = ctxNS(ctx)
	img, err := r.image(ctx, m.Image)
	if err != nil {
		return fmt.Errorf("image %s: %w", m.Image, err)
	}
	_, err = r.c.NewContainer(ctx, m.ID,
		client.WithImage(img),
		client.WithNewSnapshot(m.ID+"-rootfs", img),
		client.WithRuntime(KataRuntime, &runtimeoptions.Options{ConfigPath: KataConfig}),
		client.WithNewSpec(SpecOpts(m)...),
	)
	return err
}

// Start boots m's microVM and starts its process, with its I/O on creator (cio.NullIO for none).
func (r *Runtime) Start(ctx context.Context, id string, creator cio.Creator) error {
	ctx = ctxNS(ctx)
	c, err := r.c.LoadContainer(ctx, id)
	if err != nil {
		return err
	}
	t, err := c.NewTask(ctx, creator)
	if err != nil {
		return err
	}
	if err := t.Start(ctx); err != nil {
		t.Delete(ctx, client.WithProcessKill)
		return err
	}
	return nil
}

// Destroy stops and removes id's microVM, its container, and its snapshot: SIGTERM, then SIGKILL
// after grace. Something already gone is not an error, so teardown can be repeated.
func (r *Runtime) Destroy(ctx context.Context, id string, grace time.Duration) error {
	ctx = ctxNS(ctx)
	c, err := r.c.LoadContainer(ctx, id)
	if errdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if t, err := c.Task(ctx, nil); err == nil {
		if st, err := t.Status(ctx); err == nil && st.Status != client.Stopped {
			wait, werr := t.Wait(ctx)
			if werr == nil && t.Kill(ctx, syscall.SIGTERM) == nil {
				select {
				case <-wait:
				case <-time.After(grace):
					t.Kill(ctx, syscall.SIGKILL)
					<-wait
				}
			} else {
				t.Kill(ctx, syscall.SIGKILL)
			}
		}
		if _, err := t.Delete(ctx, client.WithProcessKill); err != nil && !errdefs.IsNotFound(err) {
			return fmt.Errorf("delete task %s: %w", id, err)
		}
	} else if !errdefs.IsNotFound(err) {
		return err
	}
	if err := c.Delete(ctx, client.WithSnapshotCleanup); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("delete container %s: %w", id, err)
	}
	return nil
}

// List is every container in sandboxd's namespace, for reconciliation.
func (r *Runtime) List(ctx context.Context) ([]string, error) {
	cs, err := r.c.Containers(ctxNS(ctx))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.ID())
	}
	return out, nil
}
