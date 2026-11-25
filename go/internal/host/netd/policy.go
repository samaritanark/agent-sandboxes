// Package netd is `sandbox netd` (design 5.2.6, D-31): the host-side userspace network that is the
// appliance VM's only NIC, and the host-reach control. A supervisor owns the VM's link (one end of
// a datagram socket pair, the other end held by the hypervisor) and the SSH listener for the VM's
// whole life; a worker process runs the network stack on them and is restarted if it dies. While
// no worker runs, the link is open but unserved, so the VM has no network at all (fail closed).
//
// The stack is gvisor-tap-vsock's link endpoint, switch, DHCP, and DNS on gVisor's netstack (the
// module's only third-party dependency, confined to this package by the import-graph test). The
// forwarders are ours: every flow the VM opens is checked by Policy before it is dialed from the
// host, and again on the address actually connected to.
package netd

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// The VM's network. The guest's address comes from a static DHCP lease on its MAC address.
var (
	Subnet    = netip.MustParsePrefix("192.168.127.0/24")
	GatewayIP = netip.MustParseAddr("192.168.127.1")
	GuestIP   = netip.MustParseAddr("192.168.127.2")
)

const GatewayMAC = "5a:94:ef:e4:0c:dd"

// Policy decides which destinations the VM may reach. The zero value's fields are filled by
// NewPolicy; tests set them directly.
type Policy struct {
	// HostPrefixes is every address on every host interface with its prefix length, read on each
	// decision so addresses that appear later (a VPN, another VM's bridge) are covered.
	HostPrefixes func() ([]netip.Prefix, error)
	// Declared is the operator's declared host endpoints (5.2.6); nil means none.
	Declared func() (map[netip.AddrPort]bool, error)
}

// Refuse reports why the VM may not reach dst, or "" if it may. Anything that cannot be decided
// is refused.
func (p Policy) Refuse(dst netip.AddrPort) string {
	a := dst.Addr().Unmap()
	if !dst.IsValid() || !a.Is4() {
		return "not an IPv4 address"
	}
	if p.Declared != nil {
		d, err := p.Declared()
		if err != nil {
			return "cannot read the declared endpoints: " + err.Error()
		}
		if d[netip.AddrPortFrom(a, dst.Port())] {
			return ""
		}
	}
	switch {
	case a.IsLoopback(), a.IsUnspecified():
		return "loopback or unspecified"
	case a.IsMulticast(), a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return "multicast or broadcast"
	case a.IsLinkLocalUnicast():
		return "link-local"
	case Subnet.Contains(a):
		return "the VM's own network"
	}
	if p.HostPrefixes == nil {
		return "no view of the host's addresses"
	}
	pfx, err := p.HostPrefixes()
	if err != nil {
		return "cannot read the host's addresses: " + err.Error()
	}
	for _, h := range pfx {
		if h.Addr().Unmap() == a {
			return "an address of this host"
		}
		// A directed broadcast reaches the host's own listeners on every address.
		if b, ok := broadcast(h); ok && b == a {
			return "the broadcast address of a host network"
		}
	}
	return ""
}

// broadcast is an IPv4 prefix's directed broadcast address (none for /31 and /32).
func broadcast(p netip.Prefix) (netip.Addr, bool) {
	if !p.Addr().Is4() || p.Bits() < 0 || p.Bits() >= 31 {
		return netip.Addr{}, false
	}
	b := p.Addr().As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= 1<<(32-p.Bits()) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
}

// HostPrefixes reads every interface address of this host, up or not.
func HostPrefixes() ([]netip.Prefix, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ifc.Name, err)
		}
		for _, ad := range addrs {
			if p, err := netip.ParsePrefix(ad.String()); err == nil {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// EndpointsFile reads the declared endpoints from a file of "ip:port" lines ('#' starts a
// comment), re-reading it when it changes. A missing file declares nothing; a file that cannot be
// read or parsed is an error, so Policy refuses everything until it is fixed.
type EndpointsFile struct {
	Path string

	mu    sync.Mutex
	mtime time.Time
	size  int64
	set   map[netip.AddrPort]bool
	err   error
}

func (e *EndpointsFile) Read() (map[netip.AddrPort]bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st, err := os.Stat(e.Path)
	if os.IsNotExist(err) {
		e.set, e.err, e.mtime, e.size = nil, nil, time.Time{}, -1
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if e.set != nil || e.err != nil {
		if st.ModTime().Equal(e.mtime) && st.Size() == e.size {
			return e.set, e.err
		}
	}
	e.mtime, e.size = st.ModTime(), st.Size()
	e.set, e.err = parseEndpoints(e.Path)
	return e.set, e.err
}

func parseEndpoints(path string) (map[netip.AddrPort]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	set := map[netip.AddrPort]bool{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		l := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		if l == "" {
			continue
		}
		ap, err := netip.ParseAddrPort(l)
		if err != nil || !ap.Addr().Is4() || ap.Port() == 0 {
			return nil, fmt.Errorf("%s line %d: not an IPv4 address and port: %q", path, n, l)
		}
		set[ap] = true
	}
	return set, sc.Err()
}
