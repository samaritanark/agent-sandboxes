package app

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// HostAliases are addresses a VM driver publishes for the host; the canary tries them too.
var HostAliases = []string{"192.168.5.2"} // Lima's host.lima.internal on its user-mode network

// doctor is `sandbox doctor`: the capability probe of design 5.2.3 as far as this build can run
// it, plus the state of the VM and its driver. Check 3 (a canary Kata microVM) waits for Kata in
// the image.
func (a *app) doctor(args []string) int {
	if len(args) > 0 {
		if args[0] == "-h" || args[0] == "--help" {
			fmt.Fprintln(a.env.Stdout, "Usage: sandbox doctor\n\nCheck the sandbox VM and the host-reach control (design 5.2.3).")
			return 0
		}
		a.die("doctor: unknown option '%s'", args[0])
	}
	failed := false
	report := func(ok bool, what, detail string) {
		mark := "ok  "
		if !ok {
			mark, failed = "FAIL", true
		}
		if detail != "" {
			what += ": " + detail
		}
		fmt.Fprintf(a.env.Stdout, "%s  %s\n", mark, what)
	}
	caps, err := a.env.Driver.Probe(a.ctx)
	report(err == nil, "driver "+a.env.Driver.Name(), errString(err)+strings.Join(caps.Problems, "; "))
	ep, err := a.env.Driver.Endpoint(a.ctx)
	if err != nil {
		report(false, "the sandbox VM is reachable", err.Error())
		return 1
	}
	info, err := a.checkRelease(ep)
	report(err == nil, "version handshake", map[bool]string{true: fmt.Sprintf("image %s, control API %d", info.ImageVersion, info.ControlAPI), false: errString(err)}[err == nil])

	// check 2: a hardware virtualization backend inside the VM (diagnostic; check 3 is the contract)
	out, err := a.env.Transport.Output(a.ctx, ep, []string{"sh", "-c", "test -c /dev/kvm && echo present || echo absent"}, 64)
	report(err == nil && strings.TrimSpace(string(out)) == "present", "/dev/kvm in the VM (nested virtualization)", strings.TrimSpace(string(out)))

	// check 4: the VM must not reach the host. Listen on every host address and let VM root try.
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		report(false, "host-reach canary", "cannot open a listener: "+err.Error())
		return 1
	}
	defer l.Close()
	reached := make(chan string, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			reached <- c.RemoteAddr().String()
			c.Close()
		}
	}()
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	targets := append(append([]string(nil), HostAliases...), hostAddresses()...)
	for _, t := range targets {
		cmd := []string{"timeout", "3", "bash", "-c", `exec 3<>"/dev/tcp/$0/$1" && echo reachable || echo blocked`, t, port}
		out, err := a.env.Transport.Output(a.ctx, ep, cmd, 64)
		res := strings.TrimSpace(string(out))
		if err != nil && res == "" {
			res = "blocked" // timeout(1) exits 124 with no output: the connection never completed
		}
		report(res == "blocked", "the VM cannot reach the host at "+t, res)
	}
	select {
	case from := <-reached:
		report(false, "host-reach canary", "the host listener accepted a connection from "+from)
	case <-time.After(200 * time.Millisecond):
	}
	if failed {
		return 1
	}
	return 0
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// hostAddresses is the host's own non-loopback IPv4 and IPv6 addresses (the LAN address is the
// path Lima's documentation says hostLoopback=false does not close).
func hostAddresses() []string {
	var out []string
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, n.IP.String())
		}
	}
	return out
}
