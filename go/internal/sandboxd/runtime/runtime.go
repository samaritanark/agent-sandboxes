//go:build linux

package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
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
	// KataRuntime is the shim, found as containerd-shim-kata-v2 on containerd's PATH.
	KataRuntime = "io.containerd.kata.v2"
	// KataConfig selects Cloud Hypervisor (S1: Kata accepts only its shipped configuration
	// files, so the selection is the runtime's config path).
	KataConfig = "/opt/kata/share/defaults/kata-containers/configuration-clh.toml"
	// GVisorRuntime is gVisor's shim, containerd-shim-runsc-v1 on containerd's PATH.
	GVisorRuntime = "io.containerd.runsc.v1"
	// GVisorConfig is the shim's configuration, which sets runsc's flags (the image's
	// /usr/lib/sandbox/runsc.toml: the systrap platform, gVisor's own network stack, and the
	// spec's seccomp profile applied by the sentry, which runsc otherwise ignores).
	GVisorConfig = "/usr/lib/sandbox/runsc.toml"
	// Socket is containerd's.
	Socket = "/run/containerd/containerd.sock"
)

// criContainerType is the CRI annotation that says what a container is in a pod; gVisor's shim
// reads it.
const criContainerType = "io.kubernetes.cri.container-type"

// ociMounts are m's mounts as OCI bind mounts.
func ociMounts(ms []Mount) []specs.Mount {
	out := make([]specs.Mount, 0, len(ms))
	for _, m := range ms {
		mode := "rw"
		if m.ReadOnly {
			mode = "ro"
		}
		out = append(out, specs.Mount{Type: "bind", Source: m.Source, Destination: m.Target, Options: []string{"rbind", mode}})
	}
	return out
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

// SpecOpts is the OCI spec of m: the default spec, then image (the image's own config: its PATH,
// working directory, and default command), then m, and the hardening last so nothing before it,
// the image included, can widen it.
func SpecOpts(m MicroVM, image ...oci.SpecOpts) []oci.SpecOpts {
	period := uint64(100000)
	opts := append([]oci.SpecOpts{oci.WithDefaultSpec()}, image...)
	if len(m.Args) > 0 {
		opts = append(opts, oci.WithProcessArgs(m.Args...))
	}
	opts = append(opts,
		oci.WithEnv(m.Env),
		oci.WithMounts(ociMounts(m.Mounts)),
		oci.WithLinuxNamespace(specs.LinuxNamespace{Type: specs.NetworkNamespace, Path: m.NetNS}),
		oci.WithMemoryLimit(uint64(m.MemoryMiB)<<20),
		oci.WithCPUCFS(int64(m.CPUs*float64(period)), period),
	)
	if m.Hostname != "" {
		opts = append(opts, oci.WithHostname(m.Hostname))
	}
	if m.Runtime == GVisor {
		// each gVisor container is a sandbox of its own: gVisor's shim gives `runsc create` the
		// container's I/O only for a sandbox, and otherwise captures its output through a pipe
		// that runsc hands on to the sandbox as the container's stdout, so the shim waits on it
		// until the sandbox ends (release 20260914.0 for good, later ones for 5 s)
		opts = append(opts, oci.WithAnnotations(map[string]string{criContainerType: "sandbox"}))
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
		withRuntime(m.Runtime),
		client.WithNewSpec(SpecOpts(m, imageConfig(img, m))...),
	)
	return err
}

// withRuntime is the shim and its configuration for kind.
func withRuntime(kind string) client.NewContainerOpts {
	if kind == GVisor {
		return client.WithRuntime(GVisorRuntime, &runtimeoptions.Options{ConfigPath: GVisorConfig})
	}
	return client.WithRuntime(KataRuntime, &runtimeoptions.Options{ConfigPath: KataConfig})
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

// Running reports whether id's process is running (a container with no task, or a stopped one,
// is not).
func (r *Runtime) Running(ctx context.Context, id string) (bool, error) {
	ctx = ctxNS(ctx)
	c, err := r.c.LoadContainer(ctx, id)
	if err != nil {
		return false, err
	}
	t, err := c.Task(ctx, nil)
	if errdefs.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	st, err := t.Status(ctx)
	if err != nil {
		return false, err
	}
	return st.Status == client.Running || st.Status == client.Created || st.Status == client.Paused || st.Status == client.Pausing, nil
}

// Restart starts id's process again after it ended: its stopped task is removed, and a new one
// started with no I/O, as at first.
func (r *Runtime) Restart(ctx context.Context, id string, creator cio.Creator) error {
	nctx := ctxNS(ctx)
	c, err := r.c.LoadContainer(nctx, id)
	if err != nil {
		return err
	}
	if t, err := c.Task(nctx, nil); err == nil {
		if _, err := t.Delete(nctx, client.WithProcessKill); err != nil && !errdefs.IsNotFound(err) {
			return fmt.Errorf("delete task %s: %w", id, err)
		}
	} else if !errdefs.IsNotFound(err) {
		return err
	}
	return r.Start(ctx, id, creator)
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

// Exec runs args in id's running microVM as its own process runs (the same user, environment,
// capabilities, and no_new_privs; only the arguments and the terminal differ), with stdio on the
// given streams. With tty, the process gets a terminal and stderr is not used.
func (r *Runtime) Exec(ctx context.Context, id, execID string, args []string, tty bool, stdin io.Reader, stdout, stderr io.Writer) (Process, error) {
	if len(args) == 0 {
		return nil, errors.New("runtime: exec needs a command")
	}
	ctx = ctxNS(ctx)
	c, err := r.c.LoadContainer(ctx, id)
	if err != nil {
		return nil, err
	}
	spec, err := c.Spec(ctx)
	if err != nil {
		return nil, err
	}
	t, err := c.Task(ctx, nil)
	if err != nil {
		return nil, err
	}
	ps := *spec.Process
	ps.Args, ps.Terminal = args, tty
	// the shim holds the stdin pipe open, so the process sees end-of-file only when it is closed
	// through containerd: once the client's stdin ends
	eof := make(chan struct{})
	if stdin != nil {
		stdin = &eofReader{r: stdin, eof: eof}
	}
	opts := []cio.Opt{cio.WithStreams(stdin, stdout, stderr)}
	if tty {
		opts = append(opts, cio.WithTerminal)
	}
	p, err := t.Exec(ctx, execID, &ps, cio.NewCreator(opts...))
	if err != nil {
		return nil, err
	}
	status, err := p.Wait(ctx)
	if err != nil {
		p.Delete(ctx)
		return nil, err
	}
	if err := p.Start(ctx); err != nil {
		p.Delete(ctx)
		return nil, err
	}
	finished := make(chan struct{})
	go func() {
		select {
		case <-eof:
			p.CloseIO(context.WithoutCancel(ctx), client.WithStdinCloser)
		case <-finished:
		}
	}()
	return &execProc{p: p, status: status, finished: finished}, nil
}

// eofReader closes eof when its reader reaches the end.
type eofReader struct {
	r    io.Reader
	eof  chan struct{}
	once sync.Once
}

func (e *eofReader) Read(b []byte) (int, error) {
	n, err := e.r.Read(b)
	if err == io.EOF {
		e.once.Do(func() { close(e.eof) })
	}
	return n, err
}

type execProc struct {
	p        client.Process
	status   <-chan client.ExitStatus
	finished chan struct{} // closed when Wait has the status
}

func (e *execProc) Resize(ctx context.Context, cols, rows uint32) error {
	return e.p.Resize(ctxNS(ctx), cols, rows)
}

func (e *execProc) Kill(ctx context.Context, sig syscall.Signal) error {
	return e.p.Kill(ctxNS(ctx), sig)
}

func (e *execProc) Wait(ctx context.Context) (int, error) {
	select {
	case st := <-e.status:
		close(e.finished)
		code, _, err := st.Result()
		if e.p.IO() != nil {
			e.p.IO().Wait() // the last output reaches the client before the exit status
		}
		e.p.Delete(ctxNS(context.WithoutCancel(ctx)))
		return int(code), err
	case <-ctx.Done():
		return -1, ctx.Err()
	}
}

// imageConfig is the image's own configuration for m, its default command replaced by m's
// ImageArgs when m gives no Args.
func imageConfig(img oci.Image, m MicroVM) oci.SpecOpts {
	if len(m.Args) == 0 && len(m.ImageArgs) > 0 {
		return oci.WithImageConfigArgs(img, m.ImageArgs)
	}
	return oci.WithImageConfig(img)
}
