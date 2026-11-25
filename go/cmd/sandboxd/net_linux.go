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
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/netsetup"
)

// GatewayUser runs every session's gateway (design 5.8.2: a dedicated unprivileged user).
const GatewayUser = "sandbox-gw"

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

type gateways struct{ uid, gid int }

func newGateways() (*gateways, error) {
	u, err := user.Lookup(GatewayUser)
	if err != nil {
		return nil, err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return &gateways{uid, gid}, nil
}

func (g *gateways) Start(ctx context.Context, id, ns, dir string, policy []byte) (int, error) {
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
	pol := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(pol, policy, 0o400); err != nil {
		return 0, err
	}
	for _, p := range []string{dir, pol} {
		if err := os.Chown(p, g.uid, g.gid); err != nil {
			return 0, err
		}
	}
	logf, err := os.OpenFile(filepath.Join(dir, "gateway.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return 0, err
	}
	defer logf.Close()
	os.Chown(logf.Name(), g.uid, g.gid)
	cmd := exec.Command("ip", "netns", "exec", ns,
		"setpriv", "--reuid="+strconv.Itoa(g.uid), "--regid="+strconv.Itoa(g.gid), "--clear-groups",
		"--no-new-privs", "--inh-caps=-all", "--bounding-set=-all",
		"/usr/lib/sandbox/bin/sandbox-gateway", "--policy", pol, "--dir", dir)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	// serving means Envoy listens on the gateway's address
	deadline := time.After(20 * time.Second)
	for {
		if listening(ns, netsetup.GatewayAddr.String()+":443") {
			return cmd.Process.Pid, nil
		}
		select {
		case err := <-exited:
			b, _ := os.ReadFile(filepath.Join(dir, "gateway.log"))
			return 0, fmt.Errorf("gateway exited (%v): %s", err, lastLine(string(b)))
		case <-deadline:
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return 0, errors.New("gateway did not start listening within 20 s")
		case <-ctx.Done():
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			return 0, ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
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

// Stop ends the gateway's process group (the gateway and Envoy), if pid is still that gateway.
func (g *gateways) Stop(ctx context.Context, id string, pid int) error {
	if pid <= 1 {
		return nil
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil || !strings.Contains(string(b), "/sessions/"+id+"/gateway") {
		return nil // gone (or the id was reused): nothing of ours to stop
	}
	syscall.Kill(-pid, syscall.SIGTERM)
	for i := 0; i < 50; i++ {
		if err := syscall.Kill(pid, 0); err != nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	syscall.Kill(-pid, syscall.SIGKILL)
	return nil
}
