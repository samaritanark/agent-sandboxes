//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/containerd/v2/pkg/cio"

	"github.com/samaritanark/agent-sandboxes/go/internal/l7"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/auditlog"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/daemon"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/journal"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/limits"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/netns"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/pki"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/runtime"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// JournalDir holds sandboxd's journal.
const JournalDir = "/var/lib/sandboxd/journal"

// Interception's inputs: the gateway CA's directory (root-only), the org baseline the image ships,
// and the VM's trust store (the system roots and the operator's corporate CA from the seed).
const (
	CADir       = "/var/lib/sandboxd/ca"
	Baseline    = "/usr/lib/sandbox/config/egress-baseline.yaml"
	SystemRoots = "/etc/ssl/certs/ca-certificates.crt"
)

// loadTLS reads what interception needs; any of it missing is a broken image, and sandboxd does
// not start without it.
func loadTLS(l *log.Logger) (*daemon.TLS, error) {
	ca, made, err := pki.LoadOrCreate(CADir, time.Now())
	if err != nil {
		return nil, fmt.Errorf("gateway CA: %w", err)
	}
	if made {
		l.Printf("made a new gateway CA, valid until %s", ca.Cert.NotAfter.Format(time.DateOnly))
	}
	b, err := os.ReadFile(Baseline)
	if err != nil {
		return nil, err
	}
	rules, err := l7.ParseBaseline(b)
	if err != nil {
		return nil, err
	}
	roots, err := os.ReadFile(SystemRoots)
	if err != nil {
		return nil, err
	}
	return &daemon.TLS{CA: ca, Baseline: rules, SystemRoots: roots}, nil
}

// ClientGroup's members may use the socket besides root (the policy CLI's user).
const ClientGroup = "sandbox"

// kata adapts runtime.Runtime to the daemon: no terminal is attached yet, so output is dropped.
type kata struct{ *runtime.Runtime }

func (k kata) Start(ctx context.Context, id string) error {
	return k.Runtime.Start(ctx, id, cio.NullIO)
}

func memTotalMiB() (int, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fs := strings.Fields(sc.Text()); len(fs) >= 2 && fs[0] == "MemTotal:" {
			kb, err := strconv.Atoi(fs[1])
			return kb / 1024, err
		}
	}
	return 0, errors.New("no MemTotal in /proc/meminfo")
}

// authorize lets root and members of ClientGroup in, by the peer's kernel credentials.
func authorize(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return errors.New("not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	if cred.Uid == 0 {
		return nil
	}
	g, err := user.LookupGroup(ClientGroup)
	if err == nil {
		if u, err := user.LookupId(strconv.Itoa(int(cred.Uid))); err == nil {
			if ids, err := u.GroupIds(); err == nil && slices.Contains(ids, g.Gid) {
				return nil
			}
		}
	}
	return fmt.Errorf("uid %d is not root or in group %s", cred.Uid, ClientGroup)
}

func serve() error {
	l := log.New(os.Stderr, "", 0) // journald adds the time
	rt, err := runtime.Open(runtime.Socket)
	if err != nil {
		return fmt.Errorf("containerd: %w", err)
	}
	defer rt.Close()
	mem, err := memTotalMiB()
	if err != nil {
		return err
	}
	resolvers, err := upstreamResolvers()
	if err != nil {
		return err
	}
	gws, err := newGateways()
	if err != nil {
		return fmt.Errorf("the gateway user: %w", err)
	}
	tlsConf, err := loadTLS(l)
	if err != nil {
		return err
	}
	d := &daemon.Daemon{
		Journal: &journal.Store{Dir: JournalDir}, Runtime: kata{rt}, NetNS: netns.Manager{},
		Network: network{}, Gateways: gws, TLS: tlsConf, Resolvers: resolvers, AuditRoot: auditlog.Root,
		NetNSPath: netns.Path, Budget: limits.Budget{VMMemoryMiB: mem},
		SessionRoot: sessionspec.SessionStore, Log: l,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	stopAllGateways()
	l.Printf("reconciling (VM memory %d MiB)", mem)
	if err := d.Reconcile(ctx); err != nil {
		return fmt.Errorf("reconcile: %w", err)
	}
	os.Remove(Socket)
	ln, err := net.Listen("unix", Socket)
	if err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if g, err := user.LookupGroup(ClientGroup); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil && os.Chown(Socket, 0, gid) == nil {
			mode = 0o660
		}
	}
	if err := os.Chmod(Socket, mode); err != nil {
		return err
	}
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				d.Collect()
				d.Reap(ctx)
			}
		}
	}()
	go func() {
		if err := followDrops(ctx, d); err != nil {
			l.Printf("kernel log: %v (link drops are not recorded)", err)
		}
	}()
	l.Printf("serving on %s", Socket)
	return d.Serve(ctx, ln, authorize)
}
