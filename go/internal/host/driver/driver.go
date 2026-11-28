// Package driver is the host binary's VM driver interface (design 5.2.1) and the types its
// methods exchange. A driver owns one appliance VM; exec, copy, and sync all go over the SSH
// endpoint it reports, so they behave the same on every driver. Drivers MUST NOT configure host
// filesystem mounts, clipboard sharing, or host-exec integration (5.2.5).
package driver

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// State is the VM's lifecycle state.
type State int

const (
	NotCreated State = iota // no VM exists
	Stopped                 // created, not running
	Running                 // booted
	Broken                  // exists but the driver cannot use it (for example a half-created instance)
)

func (s State) String() string {
	switch s {
	case NotCreated:
		return "not created"
	case Stopped:
		return "stopped"
	case Running:
		return "running"
	}
	return "broken"
}

// Capabilities is what Probe found on the host (5.2.3). Probe reports; the caller decides.
type Capabilities struct {
	Hypervisor   string // "vz", "qemu", "hyperv"
	NestedVirt   bool   // the host can expose nested virtualization to the VM
	CPUs         int    // host logical CPUs
	MemoryBytes  uint64 // host physical memory
	Problems     []string
	DriverBinary string // the absolute path of the tool the driver runs (limactl), if any
}

// ImageRef is a verified appliance image on local disk (5.3.2): signature checking happens before
// a driver ever sees it.
type ImageRef struct {
	Path    string // the system disk
	Format  string // "raw", "qcow2", "vhdx"
	Version string // IMAGE_VERSION
}

// Resources is the VM's sizing.
type Resources struct {
	CPUs      int
	MemoryMiB int
	DiskGiB   int // the state disk
}

// SeedConfig is the per-install first-boot configuration, delivered as a cloud-init NoCloud seed
// (5.3.3) and deleted after first boot.
type SeedConfig struct {
	Hostname       string
	AuthorizedKey  string // the per-install client public key, one OpenSSH line
	HostKeyPrivate string // the guest's SSH host key, generated on the host (5.2.5: no TOFU)
	HostKeyPublic  string
	CABundle       string   // PEM, corporate CAs
	DNS            []string // upstream resolvers
	Proxy          string   // HTTPS proxy URL, if any
}

// SSHEndpoint is how the host reaches the VM. HostKey is the pinned public host key: the
// connection fails if the server presents any other.
type SSHEndpoint struct {
	Host    string
	Port    int
	User    string
	HostKey string // "ssh-ed25519 AAAA..."
}

// HostReachControl describes how the driver keeps the VM from reaching the host (5.2.6).
type HostReachControl struct {
	Mechanism string // for example "lima hostLoopback=false"
	BlocksAll bool   // true when no declared endpoint can be opened (all-or-nothing controls)
	Scoped    bool   // true when declared Tier 3 endpoints can be opened one by one
}

// NetworkReport is the state of a driver's host-side network process (`sandbox netd`, D-31).
type NetworkReport struct {
	Running bool   // the process that owns the VM's network is alive
	Detail  string // for status and doctor
}

// NetworkOwner is implemented by drivers whose VM network is served by a host process of ours.
// When it is not running while the VM is, the VM has no network until the VM is restarted.
type NetworkOwner interface {
	Network(ctx context.Context) NetworkReport
}

// SystemDiskReplacer is implemented by drivers whose VM keeps its state on a disk of its own, so
// `sandbox upgrade` can replace the system disk (design 10). The VM must be stopped.
type SystemDiskReplacer interface {
	// ReplaceSystemDisk makes img the system disk, keeping the one it replaces for RollBack.
	ReplaceSystemDisk(ctx context.Context, img ImageRef) error
	// RollBack makes the kept system disk the system disk again.
	RollBack(ctx context.Context) error
	// CanRollBack reports whether a previous system disk is kept.
	CanRollBack(ctx context.Context) bool
}

// EndpointDeclarer is implemented by drivers whose host-reach control opens declared Tier 3
// endpoints one by one (5.2.6): a session's endpoints are opened until expires, and closed once
// the session is no longer live (or at expires, whichever is first).
type EndpointDeclarer interface {
	DeclareEndpoints(ctx context.Context, session string, eps []netip.AddrPort, expires time.Time) error
	// ReleaseEndpoints closes the endpoints of every session live reports as not live.
	ReleaseEndpoints(ctx context.Context, live func(session string) bool) error
	// EndpointSessions is the sessions holding declared endpoints.
	EndpointSessions(ctx context.Context) ([]string, error)
}

// Driver is one VM backend.
type Driver interface {
	Name() string
	Probe(ctx context.Context) (Capabilities, error)
	Create(ctx context.Context, img ImageRef, res Resources, seed SeedConfig) error
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Delete(ctx context.Context) error
	Status(ctx context.Context) (State, error)
	Endpoint(ctx context.Context) (SSHEndpoint, error)
	HostReach(ctx context.Context) (HostReachControl, error)
}

// ErrNotCreated is returned by operations that need an existing VM.
var ErrNotCreated = errors.New("the sandbox VM has not been created (run 'sandbox install')")

// Absent stands in when no VM has been installed: it reports NotCreated and refuses the rest.
type Absent struct{ Reason string }

func (a Absent) err() error {
	if a.Reason != "" {
		return errors.New(a.Reason)
	}
	return ErrNotCreated
}

func (a Absent) Name() string                                        { return "none" }
func (a Absent) Probe(context.Context) (Capabilities, error)         { return Capabilities{}, a.err() }
func (a Absent) Start(context.Context) error                         { return a.err() }
func (a Absent) Stop(context.Context) error                          { return a.err() }
func (a Absent) Delete(context.Context) error                        { return a.err() }
func (a Absent) Status(context.Context) (State, error)               { return NotCreated, nil }
func (a Absent) Endpoint(context.Context) (SSHEndpoint, error)       { return SSHEndpoint{}, a.err() }
func (a Absent) HostReach(context.Context) (HostReachControl, error) { return HostReachControl{}, nil }
func (a Absent) Create(context.Context, ImageRef, Resources, SeedConfig) error {
	return errors.New("this driver cannot create a VM")
}
