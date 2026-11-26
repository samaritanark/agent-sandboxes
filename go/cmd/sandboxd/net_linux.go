//go:build linux

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/daemon"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/netsetup"
)

// GatewayIDBase is the first of the gateways' user and group ids (design 5.8.2: an unprivileged
// user). Each session's gateway runs as its own id, GatewayIDBase plus its uplink slot (unique
// among live sessions), so no gateway can read another session's leaves, connect to its broker
// (which would hand back that session's credentials), or signal its processes. The range has no
// passwd entries and sits below the subordinate ids (100000 and up) user namespaces use.
const GatewayIDBase = 70000

type execRunner struct{}

func (execRunner) Run(ctx context.Context, stdin, name string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.Stdin = strings.NewReader(stdin)
	var stderr strings.Builder
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

type network struct{}

func (network) Root(ctx context.Context) error {
	r := execRunner{}
	// forwarding for the uplinks' NAT; and log the gateway namespaces' drops (bypass attempts),
	// which the kernel otherwise logs only for the root namespace
	if _, err := r.Run(ctx, "", "sysctl", "-q", "-w", "net.ipv4.ip_forward=1", "net.netfilter.nf_log_all_netns=1"); err != nil {
		return err
	}
	_, err := r.Run(ctx, netsetup.RootRules(), "nft", "-f", "-")
	return err
}

func (network) Up(ctx context.Context, s netsetup.Session) error {
	return netsetup.Up(ctx, execRunner{}, s)
}

// upstreamResolvers is the VM's upstream DNS (systemd-resolved's real servers, not its stub,
// which a gateway namespace cannot reach).
func upstreamResolvers() ([]netip.Addr, error) {
	f, err := os.Open("/run/systemd/resolve/resolv.conf")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []netip.Addr
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fs := strings.Fields(sc.Text()); len(fs) >= 2 && fs[0] == "nameserver" {
			if a, err := netip.ParseAddr(fs[1]); err == nil && a.Is4() && !a.IsLoopback() {
				out = append(out, a)
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no upstream IPv4 resolver in /run/systemd/resolve/resolv.conf")
	}
	return out, sc.Err()
}

type gateways struct{}

func newGateways() (*gateways, error) { return &gateways{}, nil }

// unit is a session's gateway service.
func unit(id string) string { return "sandbox-gw-" + id + ".service" }

// gatewayProperties confine a gateway (design 5.8.2: an unprivileged user under a seccomp
// profile): it joins only its session's network namespace, holds no capabilities, sees a
// read-only system with only its own directory writable, may make only the system calls of an
// ordinary service and only IPv4, IPv6, and Unix sockets, and has a memory cap.
func gatewayProperties(ns, dir string) []string {
	return []string{
		"NetworkNamespacePath=/run/netns/" + ns,
		// the unit may only change its ids, which setpriv does (to this session's own, which has no
		// passwd entry for systemd's User= to resolve) before it drops every capability and execs
		"ProtectProc=invisible",
		"NoNewPrivileges=yes", "CapabilityBoundingSet=CAP_SETUID CAP_SETGID", "AmbientCapabilities=",
		"SystemCallFilter=@system-service", "SystemCallArchitectures=native", "SystemCallErrorNumber=EPERM",
		"RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", "RestrictNamespaces=yes", "LockPersonality=yes",
		"RestrictRealtime=yes", "RestrictSUIDSGID=yes",
		"ProtectSystem=strict", "ReadWritePaths=" + dir, "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes",
		"ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes",
		"ProtectClock=yes", "ProtectHostname=yes", "UMask=0077",
		"MemoryMax=512M", "TasksMax=256",
		"StandardOutput=append:" + filepath.Join(dir, "gateway.log"), "StandardError=append:" + filepath.Join(dir, "gateway.log"),
	}
}

// installLeaves writes leaves as dir/tls/v<version>, owned by the gateway's id and readable by it
// alone, points dir/tls/live at it with one rename (the gateway's Envoy watches dir/tls and
// reloads on the move), and removes every other version.
func installLeaves(dir string, gid, version int, leaves map[string][]byte) error {
	tdir := filepath.Join(dir, daemon.LeafDir)
	if err := os.MkdirAll(tdir, 0o700); err != nil {
		return err
	}
	if err := os.Chown(tdir, gid, gid); err != nil {
		return err
	}
	vname := "v" + strconv.Itoa(version)
	vdir := filepath.Join(tdir, vname)
	os.RemoveAll(vdir) // the remains of a failed attempt
	if err := os.Mkdir(vdir, 0o700); err != nil {
		return err
	}
	for name, b := range leaves {
		if !filepath.IsLocal(name) || strings.ContainsRune(name, '/') {
			return fmt.Errorf("leaf file %q", name)
		}
		p := filepath.Join(vdir, name)
		if err := os.WriteFile(p, b, 0o400); err != nil {
			return err
		}
		if err := os.Chown(p, gid, gid); err != nil {
			return err
		}
	}
	if err := os.Chown(vdir, gid, gid); err != nil {
		return err
	}
	tmp := filepath.Join(tdir, daemon.LiveLeaves+".new")
	os.Remove(tmp)
	if err := os.Symlink(vname, tmp); err != nil {
		return err
	}
	if err := os.Lchown(tmp, gid, gid); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(tdir, daemon.LiveLeaves)); err != nil {
		return err
	}
	ents, _ := os.ReadDir(tdir)
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), "v") && e.Name() != vname {
			os.RemoveAll(filepath.Join(tdir, e.Name()))
		}
	}
	return nil
}

func (g *gateways) Renew(_ context.Context, id, dir string, slot, version int, leaves map[string][]byte) error {
	if slot < 0 || slot > 0xffff || version < 2 {
		return fmt.Errorf("gateway slot %d, leaves version %d", slot, version)
	}
	return installLeaves(dir, GatewayIDBase+slot, version, leaves)
}

func (g *gateways) Start(ctx context.Context, id, ns, dir string, slot int, files, leaves map[string][]byte) (int, error) {
	if slot < 0 || slot > 0xffff {
		return 0, fmt.Errorf("gateway slot %d", slot)
	}
	gid := GatewayIDBase + slot
	exec.Command("systemctl", "stop", unit(id)).Run() // the remains of a failed start
	os.RemoveAll(dir)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return 0, err
	}
	// the sessions directory and the session's are root's; the gateway may pass through them to
	// its own directory only (traversable, not listable)
	for _, p := range []string{filepath.Dir(filepath.Dir(dir)), filepath.Dir(dir)} {
		if err := os.Chmod(p, 0o711); err != nil {
			return 0, err
		}
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return 0, err
	}
	owned := []string{dir}
	if _, ok := files["policy.json"]; !ok {
		return 0, errors.New("no gateway policy")
	}
	for name, b := range files {
		if !filepath.IsLocal(name) {
			return 0, fmt.Errorf("gateway file %q", name)
		}
		p := filepath.Join(dir, name)
		for d := filepath.Dir(p); d != dir && !slices.Contains(owned, d); d = filepath.Dir(d) {
			if err := os.MkdirAll(d, 0o700); err != nil {
				return 0, err
			}
			owned = append(owned, d)
		}
		if err := os.WriteFile(p, b, 0o400); err != nil {
			return 0, err
		}
		owned = append(owned, p)
	}
	if len(leaves) > 0 {
		if err := installLeaves(dir, gid, 1, leaves); err != nil {
			return 0, err
		}
	}
	pol := filepath.Join(dir, "policy.json")
	logPath := filepath.Join(dir, "gateway.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		return 0, err
	}
	for _, p := range append(owned, logPath) {
		if err := os.Chown(p, gid, gid); err != nil {
			return 0, err
		}
	}
	args := []string{"--unit=" + unit(id), "--collect", "--quiet", "--description=sandbox gateway for session " + id}
	for _, p := range gatewayProperties(ns, dir) {
		args = append(args, "--property="+p)
	}
	ids := strconv.Itoa(gid)
	args = append(args, "/usr/bin/setpriv", "--reuid="+ids, "--regid="+ids, "--clear-groups", "--inh-caps=-all",
		"--", "/usr/lib/sandbox/bin/sandbox-gateway", "--policy", pol, "--dir", dir)
	if out, err := exec.CommandContext(ctx, "systemd-run", args...).CombinedOutput(); err != nil {
		return 0, fmt.Errorf("systemd-run: %v: %s", err, strings.TrimSpace(string(out)))
	}
	// serving means Envoy listens on the gateway's address
	deadline := time.After(20 * time.Second)
	for {
		if listening(ns, netsetup.GatewayAddr.String()+":443") {
			pid, _ := strconv.Atoi(strings.TrimSpace(show(unit(id), "MainPID")))
			return pid, nil
		}
		if st := show(unit(id), "ActiveState"); st == "failed" || st == "inactive" {
			b, _ := os.ReadFile(logPath)
			exec.Command("systemctl", "stop", unit(id)).Run()
			return 0, fmt.Errorf("gateway exited: %s", lastLine(string(b)))
		}
		select {
		case <-deadline:
			exec.Command("systemctl", "stop", unit(id)).Run()
			return 0, errors.New("gateway did not start listening within 20 s")
		case <-ctx.Done():
			exec.Command("systemctl", "stop", unit(id)).Run()
			return 0, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// show is one property of a unit.
func show(unit, prop string) string {
	out, _ := exec.Command("systemctl", "show", "--value", "-p", prop, unit).Output()
	return strings.TrimSpace(string(out))
}

// stopAllGateways stops every gateway unit: at start, before reconciling, nothing that runs is
// vouched for (the sessions themselves are torn down by the reconciliation).
func stopAllGateways() {
	exec.Command("systemctl", "stop", "sandbox-gw-*.service").Run()
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// listening reports whether something accepts TCP on addr inside namespace ns.
func listening(ns, addr string) bool {
	return exec.Command("ip", "netns", "exec", ns, "bash", "-c", "exec 3<>/dev/tcp/"+strings.Replace(addr, ":", "/", 1)).Run() == nil
}

// Stop ends a session's gateway unit (the gateway and Envoy with it).
func (g *gateways) Stop(ctx context.Context, id string, pid int) error {
	if st := show(unit(id), "LoadState"); st == "not-found" {
		return nil
	}
	out, err := exec.CommandContext(ctx, "systemctl", "stop", unit(id)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl stop %s: %v: %s", unit(id), err, strings.TrimSpace(string(out)))
	}
	return nil
}
