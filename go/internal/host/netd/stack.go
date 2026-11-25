package netd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/services/dhcp"
	"github.com/containers/gvisor-tap-vsock/pkg/services/dns"
	"github.com/containers/gvisor-tap-vsock/pkg/services/forwarder"
	"github.com/containers/gvisor-tap-vsock/pkg/tap"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	mtu            = 1500
	connectTimeout = 30 * time.Second
	udpIdle        = 90 * time.Second
	tcpMaxInFlight = 128
)

// Stack is one worker's network: the VM's link served by a userspace stack whose only ways out
// are the policed forwarders and the gateway's DNS, and whose only way in is the SSH forward.
type Stack struct {
	Policy   Policy
	GuestMAC string
	Log      *log.Logger

	limiter refusalLog
}

func addrOf(a netip.Addr) tcpip.Address { return tcpip.AddrFrom4(a.As4()) }

// Serve runs the stack on link (a datagram connection carrying one Ethernet frame per message)
// and forwards connections accepted on ssh to the guest's port 22, until link fails or ctx ends.
func (s *Stack) Serve(ctx context.Context, link net.Conn, ssh net.Listener) error {
	if s.Log == nil {
		s.Log = log.New(io.Discard, "", 0)
	}
	cfg := &types.Configuration{
		MTU: mtu, Subnet: Subnet.String(), GatewayIP: GatewayIP.String(), GatewayMacAddress: GatewayMAC,
		DHCPStaticLeases: map[string]string{GuestIP.String(): s.GuestMAC},
	}
	pool, err := tap.NewIPPool(cfg.Subnet)
	if err != nil {
		return err
	}
	if err := pool.Reserve(cfg.GatewayIP, GatewayMAC); err != nil {
		return err
	}
	if err := pool.Reserve(GuestIP.String(), s.GuestMAC); err != nil {
		return err
	}
	ep, err := tap.NewLinkEndpoint(false, mtu, GatewayMAC, cfg.GatewayIP, nil)
	if err != nil {
		return err
	}
	sw := tap.NewSwitch(false)
	ep.Connect(sw)
	sw.Connect(ep)

	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	defer st.Close()
	if e := st.CreateNIC(1, ep); e != nil {
		return errors.New(e.String())
	}
	if e := st.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: addrOf(GatewayIP).WithPrefix()}, stack.AddressProperties{}); e != nil {
		return errors.New(e.String())
	}
	// Spoofing and promiscuous mode let the stack terminate the guest's flows to any address, so
	// the forwarders see every destination; nothing reaches the host without passing them.
	st.SetSpoofing(1, true)
	st.SetPromiscuousMode(1, true)
	sn, err := tcpip.NewSubnet(addrOf(Subnet.Addr()), tcpip.MaskFromBytes(net.CIDRMask(Subnet.Bits(), 32)))
	if err != nil {
		return err
	}
	st.SetRouteTable([]tcpip.Route{{Destination: sn, NIC: 1}})
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, s.tcpForwarder(st).HandlePacket)
	st.SetTransportProtocolHandler(udp.ProtocolNumber, s.udpForwarder(st).HandlePacket)

	// The gateway's DNS (5.2.6: upstream DNS is the one standing host service) and DHCP.
	gw := tcpip.FullAddress{NIC: 1, Addr: addrOf(GatewayIP), Port: 53}
	uc, err := gonet.DialUDP(st, &gw, nil, ipv4.ProtocolNumber)
	if err != nil {
		return err
	}
	tl, err := gonet.ListenTCP(st, gw, ipv4.ProtocolNumber)
	if err != nil {
		return err
	}
	ds, err := dns.New(uc, tl, nil)
	if err != nil {
		return err
	}
	go ds.Serve()
	go ds.ServeTCP()
	dh, err := dhcp.New(cfg, st, pool)
	if err != nil {
		return err
	}
	go dh.Serve()

	go s.forwardSSH(ctx, st, ssh)
	return sw.Accept(ctx, link, types.VfkitProtocol)
}

// dialer re-checks the address it actually connects to, so nothing between the decision and the
// connect can widen it.
func (s *Stack) dialer() *net.Dialer {
	return &net.Dialer{Timeout: connectTimeout, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		if why := s.Policy.Refuse(ap); why != "" {
			return fmt.Errorf("refused: %s", why)
		}
		return nil
	}}
}

func addrPort(a tcpip.Address, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return netip.AddrPortFrom(ip, port)
}

func (s *Stack) tcpForwarder(st *stack.Stack) *tcp.Forwarder {
	d := s.dialer()
	return tcp.NewForwarder(st, 0, tcpMaxInFlight, func(r *tcp.ForwarderRequest) {
		dst := addrPort(r.ID().LocalAddress, r.ID().LocalPort)
		if why := s.Policy.Refuse(dst); why != "" {
			s.limiter.log(s.Log, "tcp", dst, why)
			r.Complete(true) // reset
			return
		}
		out, err := d.Dial("tcp4", dst.String())
		if err != nil {
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		r.Complete(false)
		if terr != nil {
			out.Close()
			return
		}
		splice(gonet.NewTCPConn(&wq, ep), out.(*net.TCPConn))
	})
}

type halfCloser interface {
	net.Conn
	CloseWrite() error
}

// splice copies both ways, passing each side's end of stream on as a half close.
func splice(a, b halfCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { io.Copy(a, b); a.CloseWrite(); wg.Done() }()
	go func() { io.Copy(b, a); b.CloseWrite(); wg.Done() }()
	wg.Wait()
	a.Close()
	b.Close()
}

func (s *Stack) udpForwarder(st *stack.Stack) *udp.Forwarder {
	d := s.dialer()
	return udp.NewForwarder(st, func(r *udp.ForwarderRequest) bool {
		dst := addrPort(r.ID().LocalAddress, r.ID().LocalPort)
		if why := s.Policy.Refuse(dst); why != "" {
			s.limiter.log(s.Log, "udp", dst, why)
			return true // consumed and dropped
		}
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			return false
		}
		p, err := forwarder.NewUDPProxy(&idleUDP{gonet.NewUDPConn(&wq, ep)}, func(net.Addr) (net.Conn, error) {
			return d.Dial("udp4", dst.String())
		})
		if err != nil {
			ep.Close()
			return true
		}
		go func() { p.Run(); ep.Close() }()
		return true
	})
}

// idleUDP ends a UDP flow's proxy once the guest side has been quiet for udpIdle.
type idleUDP struct{ *gonet.UDPConn }

func (u *idleUDP) ReadFrom(b []byte) (int, net.Addr, error) {
	u.UDPConn.SetReadDeadline(time.Now().Add(udpIdle))
	return u.UDPConn.ReadFrom(b)
}

// forwardSSH is the only inbound path: each connection to the host's loopback listener is joined
// to the guest's sshd, where the pinned host key and the per-install client key authenticate.
func (s *Stack) forwardSSH(ctx context.Context, st *stack.Stack, ln net.Listener) {
	guest := tcpip.FullAddress{NIC: 1, Addr: addrOf(GuestIP), Port: 22}
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				s.Log.Printf("ssh listener: %v", err)
			}
			return
		}
		go func() {
			dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			g, err := gonet.DialContextTCP(dctx, st, guest, ipv4.ProtocolNumber)
			cancel()
			if err != nil {
				c.Close()
				return
			}
			if tc, ok := c.(*net.TCPConn); ok {
				splice(g, tc)
				return
			}
			c.Close()
			g.Close()
		}()
	}
}

// refusalLog logs refused flows, at most a few per destination per minute, so a guest cannot
// fill the host's disk through the log.
type refusalLog struct {
	mu     sync.Mutex
	window time.Time
	seen   map[string]int
}

func (r *refusalLog) log(l *log.Logger, proto string, dst netip.AddrPort, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.window) > time.Minute || r.seen == nil {
		if n := len(r.seen); n > 0 {
			l.Printf("refused flows to %d destinations in the last minute", n)
		}
		r.window, r.seen = time.Now(), map[string]int{}
	}
	k := proto + " " + dst.String()
	r.seen[k]++
	if r.seen[k] <= 3 && len(r.seen) <= 100 {
		l.Printf("refused %s %s: %s", proto, dst, why)
	}
}
