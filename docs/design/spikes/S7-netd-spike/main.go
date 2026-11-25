//go:build ignore

// Spike code (S7, 2026-11-25), not part of the module: built in its own module against
// github.com/containers/gvisor-tap-vsock v0.9.0. See ../S7.md.

// netd spike: the VM's only NIC is a userspace stack built from gvisor-tap-vsock's pieces, with our
// own TCP and UDP forwarders that refuse host addresses before dialing (design 5.2.6, D-31).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/services/dhcp"
	"github.com/containers/gvisor-tap-vsock/pkg/services/dns"
	"github.com/containers/gvisor-tap-vsock/pkg/services/forwarder"
	"github.com/containers/gvisor-tap-vsock/pkg/tap"
	"github.com/containers/gvisor-tap-vsock/pkg/transport"
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
	subnet     = "192.168.127.0/24"
	gatewayIP  = "192.168.127.1"
	gatewayMAC = "5a:94:ef:e4:0c:dd"
	guestIP    = "192.168.127.2"
	guestMAC   = "5a:94:ef:e4:0c:ee"
)

// allowed holds the declared host endpoints ("ip:port"); everything else on the host is refused.
var allowed = map[string]bool{}

// refuse reports why dst may not be dialed from the VM, or "" if it may.
func refuse(dst netip.AddrPort) string {
	a := dst.Addr().Unmap()
	if allowed[dst.String()] {
		return ""
	}
	switch {
	case !a.Is4():
		return "not IPv4"
	case a.IsLoopback(), a.IsUnspecified():
		return "loopback or unspecified"
	case a.IsMulticast(), a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return "multicast or broadcast"
	case a.IsLinkLocalUnicast():
		return "link-local"
	}
	if netip.MustParsePrefix(subnet).Contains(a) {
		return "the VM's own network"
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return "cannot list host interfaces: " + err.Error() // fail closed
	}
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			return "cannot list host addresses: " + err.Error()
		}
		for _, ad := range addrs {
			pfx, err := netip.ParsePrefix(ad.String())
			if err != nil {
				continue
			}
			if pfx.Addr().Unmap() == a {
				return "a host address (" + ifc.Name + ")"
			}
			if b, ok := broadcast(pfx); ok && b == a {
				return "a host subnet's broadcast (" + ifc.Name + ")"
			}
		}
	}
	return ""
}

func broadcast(p netip.Prefix) (netip.Addr, bool) {
	if !p.Addr().Is4() || p.Bits() >= 31 {
		return netip.Addr{}, false
	}
	b := p.Addr().As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= (1 << (32 - p.Bits())) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
}

// dialer re-checks the address it actually connects to, so nothing between the decision and the
// connect (a name, a NAT table) can widen it.
var dialer = net.Dialer{
	Timeout: 30 * time.Second,
	Control: func(network, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		if why := refuse(ap); why != "" {
			return errors.New("refused: " + why)
		}
		return nil
	},
}

func addrPort(a tcpip.Address, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return netip.AddrPortFrom(ip, port)
}

func tcpForwarder(s *stack.Stack) *tcp.Forwarder {
	return tcp.NewForwarder(s, 0, 128, func(r *tcp.ForwarderRequest) {
		dst := addrPort(r.ID().LocalAddress, r.ID().LocalPort)
		if why := refuse(dst); why != "" {
			log.Printf("tcp %v: refused, %s", dst, why)
			r.Complete(true) // RST
			return
		}
		out, err := dialer.Dial("tcp4", dst.String())
		if err != nil {
			log.Printf("tcp %v: %v", dst, err)
			r.Complete(true)
			return
		}
		log.Printf("tcp %v: allowed", dst)
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		r.Complete(false)
		if terr != nil {
			out.Close()
			return
		}
		in := gonet.NewTCPConn(&wq, ep)
		go func() { io.Copy(out, in); out.(*net.TCPConn).CloseWrite() }()
		go func() { io.Copy(in, out); in.CloseWrite() }()
	})
}

func udpForwarder(s *stack.Stack) *udp.Forwarder {
	return udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		dst := addrPort(r.ID().LocalAddress, r.ID().LocalPort)
		if why := refuse(dst); why != "" {
			log.Printf("udp %v: refused, %s", dst, why)
			return true // consumed, dropped
		}
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			return false
		}
		log.Printf("udp %v: allowed", dst)
		p, err := forwarder.NewUDPProxy(&udpListener{gonet.NewUDPConn(&wq, ep)}, func(_ net.Addr) (net.Conn, error) {
			return dialer.Dial("udp4", dst.String())
		})
		if err != nil {
			ep.Close()
			return true
		}
		go func() { p.Run(); ep.Close() }()
		return true
	})
}

// udpListener ends the proxy's read loop when the guest side goes quiet, like the library's own.
type udpListener struct{ *gonet.UDPConn }

func (l *udpListener) ReadFrom(b []byte) (int, net.Addr, error) {
	l.UDPConn.SetReadDeadline(time.Now().Add(90 * time.Second))
	return l.UDPConn.ReadFrom(b)
}

func main() {
	sock := flag.String("vfkit", "", "unixgram socket vfkit connects to")
	fd := flag.Int("fd", 0, "inherited datagram socket connected to the VM (worker mode)")
	supervise := flag.Bool("supervise", false, "own the VM's link and run vfkit (args after --) and a restartable worker")
	sshAddr := flag.String("ssh", "127.0.0.1:2223", "host address forwarded to the guest's port 22")
	allow := flag.String("allow", "", "comma-separated declared host endpoints ip:port")
	flag.Parse()
	for _, e := range strings.Split(*allow, ",") {
		if e != "" {
			allowed[netip.MustParseAddrPort(e).String()] = true
		}
	}

	if *supervise {
		superviseMain(flag.Args(), *sshAddr, *allow)
		return
	}
	cfg := &types.Configuration{
		MTU: 1500, Subnet: subnet, GatewayIP: gatewayIP, GatewayMacAddress: gatewayMAC,
		DHCPStaticLeases: map[string]string{guestIP: guestMAC},
	}
	pool, err := tap.NewIPPool(subnet)
	must(err)
	must(pool.Reserve(gatewayIP, gatewayMAC))
	must(pool.Reserve(guestIP, guestMAC))
	link, err := tap.NewLinkEndpoint(false, 1500, gatewayMAC, gatewayIP, nil)
	must(err)
	sw := tap.NewSwitch(false)
	link.Connect(sw)
	sw.Connect(link)

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if e := s.CreateNIC(1, link); e != nil {
		log.Fatal(e)
	}
	gw := tcpip.AddrFrom4Slice(net.ParseIP(gatewayIP).To4())
	if e := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: gw.WithPrefix()}, stack.AddressProperties{}); e != nil {
		log.Fatal(e)
	}
	s.SetSpoofing(1, true)
	s.SetPromiscuousMode(1, true)
	sn, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{192, 168, 127, 0}), tcpip.MaskFromBytes([]byte{255, 255, 255, 0}))
	s.SetRouteTable([]tcpip.Route{{Destination: sn, NIC: 1}})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder(s).HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder(s).HandlePacket)

	// DNS at the gateway (the one standing host service, 5.2.6) and DHCP.
	uc, err := gonet.DialUDP(s, &tcpip.FullAddress{NIC: 1, Addr: gw, Port: 53}, nil, ipv4.ProtocolNumber)
	must(err)
	tl, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Addr: gw, Port: 53}, ipv4.ProtocolNumber)
	must(err)
	ds, err := dns.New(uc, tl, nil)
	must(err)
	go ds.Serve()
	go ds.ServeTCP()
	dh, err := dhcp.New(cfg, s, pool)
	must(err)
	go dh.Serve()

	// The control channel: host loopback to the guest's sshd, the only inbound path.
	ln, err := net.Listen("tcp", *sshAddr)
	must(err)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				g, err := gonet.DialContextTCP(context.Background(), s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4Slice(net.ParseIP(guestIP).To4()), Port: 22}, ipv4.ProtocolNumber)
				if err != nil {
					log.Printf("ssh forward: %v", err)
					c.Close()
					return
				}
				var wg sync.WaitGroup
				wg.Add(2)
				go func() { io.Copy(g, c); g.CloseWrite(); wg.Done() }()
				go func() { io.Copy(c, g); c.(*net.TCPConn).CloseWrite(); wg.Done() }()
				wg.Wait()
				g.Close()
				c.Close()
			}()
		}
	}()

	if *fd != 0 {
		c, err := net.FileConn(os.NewFile(uintptr(*fd), "vm-link"))
		must(err)
		log.Printf("netd worker %d: on inherited link; ssh on %s; declared %v", os.Getpid(), *sshAddr, allowed)
		log.Fatal(sw.Accept(context.Background(), c, types.VfkitProtocol))
	}
	os.Remove(*sock)
	conn, err := transport.ListenUnixgram("unixgram://" + *sock)
	must(err)
	log.Printf("netd spike: waiting for vfkit on %s; ssh on %s; declared %v", *sock, *sshAddr, allowed)
	vc, err := transport.AcceptVfkit(conn)
	must(err)
	log.Fatal(sw.Accept(context.Background(), vc, types.VfkitProtocol))
}

func must(err error) {
	if err != nil {
		log.Fatal(fmt.Errorf("%w", err))
	}
}

// superviseMain holds both ends of the VM's link for the VM's lifetime: vfkit gets one, and each
// worker (the stack) gets the other. A worker that dies leaves the link open but unserved, so the
// VM has no network (fail closed) until the next worker takes over.
func superviseMain(vfkitArgs []string, sshAddr, allow string) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	must(err)
	for _, f := range fds {
		syscall.SetsockoptInt(f, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 1<<20)
		syscall.SetsockoptInt(f, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<20)
	}
	vmEnd, ourEnd := os.NewFile(uintptr(fds[0]), "vm"), os.NewFile(uintptr(fds[1]), "netd")
	vm := exec.Command(vfkitArgs[0], append(vfkitArgs[1:], "--device", "virtio-net,fd=3,mac="+guestMAC)...)
	vm.ExtraFiles = []*os.File{vmEnd}
	vm.Stdout, vm.Stderr = os.Stderr, os.Stderr
	must(vm.Start())
	vmEnd.Close()
	done := make(chan struct{})
	go func() { vm.Wait(); close(done) }()
	self, _ := os.Executable()
	for {
		w := exec.Command(self, "-fd", "3", "-ssh", sshAddr, "-allow", allow)
		w.ExtraFiles = []*os.File{ourEnd}
		w.Stdout, w.Stderr = os.Stderr, os.Stderr
		must(w.Start())
		wd := make(chan struct{})
		go func() { w.Wait(); close(wd) }()
		select {
		case <-done:
			w.Process.Kill()
			log.Printf("supervisor: VM exited")
			return
		case <-wd:
			log.Printf("supervisor: worker exited (%v); restarting", w.ProcessState)
			time.Sleep(time.Second)
		}
	}
}

var _ = strconv.Itoa
