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
	"regexp"
	"strconv"
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

// EndpointsFile reads the declared endpoints from a file of lines "ip:port [session=ID]
// [expires=UNIX]" ('#' starts a comment), re-reading it when it changes. An entry past its expiry
// is not declared, whether or not the host has removed it yet, so an endpoint closes on time even
// if the host that declared it is gone. A missing file declares nothing; a file that cannot be read
// or parsed is an error, so Policy refuses everything until it is fixed.
type EndpointsFile struct {
	Path string
	Now  func() time.Time // time.Now when nil

	mu      sync.Mutex
	mtime   time.Time
	size    int64
	entries []Endpoint
	read    bool
	err     error
}

// Endpoint is one declared endpoint: Session is the session it was declared for ("" for one the
// operator wrote by hand), Expires when it closes (zero: never).
type Endpoint struct {
	Addr    netip.AddrPort
	Session string
	Expires time.Time
}

func (e *EndpointsFile) Read() (map[netip.AddrPort]bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st, err := os.Stat(e.Path)
	if os.IsNotExist(err) {
		e.entries, e.read, e.err, e.mtime, e.size = nil, false, nil, time.Time{}, -1
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !e.read || !st.ModTime().Equal(e.mtime) || st.Size() != e.size {
		e.mtime, e.size, e.read = st.ModTime(), st.Size(), true
		e.entries, e.err = ReadEndpoints(e.Path)
	}
	if e.err != nil {
		return nil, e.err
	}
	now := time.Now
	if e.Now != nil {
		now = e.Now
	}
	set := map[netip.AddrPort]bool{}
	for _, en := range e.entries {
		if en.Expires.IsZero() || now().Before(en.Expires) {
			set[en.Addr] = true
		}
	}
	return set, nil
}

// sessionRE is what a session=ID may hold.
var sessionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

// ReadEndpoints parses an endpoints file; a missing one declares nothing.
func ReadEndpoints(path string) ([]Endpoint, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Endpoint
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		l := sc.Text()
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		fields := strings.Fields(l)
		if len(fields) == 0 {
			continue
		}
		bad := func(why string) error { return fmt.Errorf("%s line %d: %s: %q", path, n, why, strings.TrimSpace(l)) }
		ap, err := netip.ParseAddrPort(fields[0])
		if err != nil || !ap.Addr().Is4() || ap.Port() == 0 {
			return nil, bad("not an IPv4 address and port")
		}
		en := Endpoint{Addr: ap}
		for _, f := range fields[1:] {
			k, v, _ := strings.Cut(f, "=")
			switch {
			case k == "session" && en.Session == "" && sessionRE.MatchString(v):
				en.Session = v
			case k == "expires" && en.Expires.IsZero():
				u, err := strconv.ParseInt(v, 10, 64)
				if err != nil || u <= 0 {
					return nil, bad("expires is not a time")
				}
				en.Expires = time.Unix(u, 0)
			default:
				return nil, bad("unknown or repeated field " + f)
			}
		}
		out = append(out, en)
	}
	return out, sc.Err()
}

// formatEndpoints is the file ReadEndpoints reads back.
func formatEndpoints(es []Endpoint) []byte {
	var b strings.Builder
	b.WriteString("# Declared host endpoints (design 5.2.6), written by the sandbox CLI.\n")
	for _, e := range es {
		b.WriteString(e.Addr.String())
		if e.Session != "" {
			b.WriteString(" session=" + e.Session)
		}
		if !e.Expires.IsZero() {
			fmt.Fprintf(&b, " expires=%d", e.Expires.Unix())
		}
		b.WriteByte('\n')
	}
	return []byte(b.String())
}
