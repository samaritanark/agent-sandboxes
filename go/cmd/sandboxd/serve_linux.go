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

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/auditlog"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/daemon"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/journal"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/limits"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/netns"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/runtime"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// JournalDir holds sandboxd's journal.
const JournalDir = "/var/lib/sandboxd/journal"

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
	d := &daemon.Daemon{
		Journal: &journal.Store{Dir: JournalDir}, Runtime: kata{rt}, NetNS: netns.Manager{},
		Network: network{}, Gateways: gws, Resolvers: resolvers, AuditRoot: auditlog.Root,
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
