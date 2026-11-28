package app

// Declared host endpoints (design 5.2.6): a tier 3 launch whose cluster API server or
// --infra-endpoint is an address of this machine (a k3d or kind cluster published on its LAN
// address, as v2's examples/k3d-podman/bake-kubeconfig.sh sets up) needs that address and port
// opened in the host-reach control, which otherwise refuses every address of this machine. The host
// decides, from what it resolves itself; the VM is told the session's ID (so the endpoints are
// declared under it) and the endpoints (for its spec and audit). They are closed when the session
// is no longer live, checked after every command, and at the latest when the longest session
// could end.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

const (
	// SessionIDEnv names the session a launch is to start (cli.SessionIDEnv).
	SessionIDEnv = "SANDBOX_SESSION_ID"
	// HostEndpointsEnv is the launch's declared host endpoints, "ip:port" comma-separated
	// (cli.HostEndpointsEnv).
	HostEndpointsEnv = "SANDBOX_HOST_ENDPOINTS"
	// endpointLifetime bounds a declaration: a keep-alive session's longest life (7 days), and
	// an hour to spare.
	endpointLifetime = 7*24*time.Hour + time.Hour
)

// hostEndpoints is the launch's destinations (its clusters' API servers and --infra-endpoint
// URLs) that resolve, on this machine, to an address of this machine.
func (a *app) hostEndpoints(args []string, ks []kubeCluster) []netip.AddrPort {
	urls := optionValues(args, "--infra-endpoint")
	for _, k := range ks {
		urls = append(urls, k.Server)
	}
	if len(urls) == 0 {
		return nil
	}
	own, err := a.hostAddrs()
	if err != nil {
		a.die("cannot read this machine's addresses: %v", err)
	}
	seen := map[netip.AddrPort]bool{}
	var out []netip.AddrPort
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			continue // the run refuses it with v2's message
		}
		port := 443
		if u.Scheme == "http" {
			port = 80
		}
		if p := u.Port(); p != "" {
			if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
				continue
			}
		}
		var addrs []netip.Addr
		if ad, err := netip.ParseAddr(u.Hostname()); err == nil {
			addrs = []netip.Addr{ad}
		} else {
			addrs, _ = a.lookupHost(u.Hostname())
		}
		for _, ad := range addrs {
			ad = ad.Unmap()
			if !ad.Is4() || ad.IsLoopback() || !own[ad] { // loopback: the run refuses it, as v2 did
				continue
			}
			ap := netip.AddrPortFrom(ad, uint16(port))
			if !seen[ap] {
				seen[ap] = true
				out = append(out, ap)
			}
		}
	}
	return out
}

// hostAddrs is the set of this machine's addresses (Env.HostAddrs in tests).
func (a *app) hostAddrs() (map[netip.Addr]bool, error) {
	f := a.env.HostAddrs
	if f == nil {
		f = interfacePrefixes
	}
	pfx, err := f()
	set := map[netip.Addr]bool{}
	for _, p := range pfx {
		set[p.Addr().Unmap()] = true
	}
	return set, err
}

// interfacePrefixes is every address on this machine's interfaces (netd.HostPrefixes, which the
// import graph keeps out of this package).
func interfacePrefixes() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	var out []netip.Prefix
	for _, ad := range addrs {
		if p, err := netip.ParsePrefix(ad.String()); err == nil {
			out = append(out, p)
		}
	}
	return out, err
}

// lookupHost resolves a name on this machine (Env.LookupHost in tests).
func (a *app) lookupHost(h string) ([]netip.Addr, error) {
	if a.env.LookupHost != nil {
		return a.env.LookupHost(h)
	}
	ips, err := net.DefaultResolver.LookupNetIP(a.ctx, "ip4", h)
	return ips, err
}

// newSessionID is a session ID the host chooses for a launch (cli: SessionIDEnv), when it needs to
// know it: to declare endpoints under it, or to renew its credentials.
func (a *app) newSessionID() string {
	b := make([]byte, 2)
	rand.Read(b)
	now := a.env.Now().UTC()
	return "ses-" + now.Format("20060102") + "-" + now.Format("150405") + "-" + hex.EncodeToString(b)
}

// declareEndpoints opens eps for session id and returns the run's environment for them.
func (a *app) declareEndpoints(id string, eps []netip.AddrPort) []string {
	if len(eps) == 0 {
		return nil
	}
	dd, ok := a.env.Driver.(driver.EndpointDeclarer)
	if !ok {
		a.die("%s is an address of this machine. Reaching it from a session needs a declared endpoint, which the %s driver cannot open one by one; reinstall with the vfkit driver (macOS) or the qemu driver (Linux).",
			eps[0], a.env.Driver.Name())
	}
	now := a.env.Now().UTC()
	if err := dd.DeclareEndpoints(a.ctx, id, eps, now.Add(endpointLifetime)); err != nil {
		a.die("could not declare this machine's endpoints for the session: %v", err)
	}
	s := make([]string, len(eps))
	for i, ep := range eps {
		s[i] = ep.String()
	}
	fmt.Fprintf(a.env.Stdout, "==> Declared host endpoint(s) %s (this machine) for session %s, until it ends\n", strings.Join(s, " "), id)
	return []string{HostEndpointsEnv + "=" + strings.Join(s, ",")}
}

// releaseEndpoints closes the declared endpoints of sessions sandboxd no longer runs. When the
// sessions cannot be read, nothing is closed (the declarations still expire).
func (a *app) releaseEndpoints(ep driver.SSHEndpoint) {
	dd, ok := a.env.Driver.(driver.EndpointDeclarer)
	if !ok {
		return
	}
	held, err := dd.EndpointSessions(a.ctx)
	if err != nil || len(held) == 0 {
		return
	}
	out, err := a.env.Transport.Output(a.ctx, ep, []string{SandboxdCommand, "ctl", "list"}, 1<<20)
	if err != nil {
		return
	}
	live := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Split(l, "\t")
		if len(f) >= 3 && f[2] != "TERMINATED" && f[2] != "FAILED" {
			live[f[0]] = true
		}
	}
	if err := dd.ReleaseEndpoints(a.ctx, func(id string) bool { return live[id] }); err != nil {
		fmt.Fprintf(a.env.Stderr, "WARNING: could not close the declared endpoints of ended sessions: %v\n", err)
	}
}

// releaseAllEndpoints closes every session's declared endpoints (the VM is stopping).
func (a *app) releaseAllEndpoints() {
	if dd, ok := a.env.Driver.(driver.EndpointDeclarer); ok {
		if err := dd.ReleaseEndpoints(a.ctx, func(string) bool { return false }); err != nil {
			fmt.Fprintf(a.env.Stderr, "WARNING: could not close the declared endpoints: %v\n", err)
		}
	}
}
