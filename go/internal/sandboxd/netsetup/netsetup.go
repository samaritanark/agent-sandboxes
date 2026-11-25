// Package netsetup builds a session's network (design 5.8.1, 5.8.2): egress by topology. Each
// session gets a gateway namespace with one link to its agent's microVM namespace (the CNI ptp
// plugin, run inside the gateway namespace so neither end is in the VM root namespace, S1) and one
// NAT'd uplink to the VM root namespace. nftables in the gateway namespace accept from the link
// only the gateway's listeners and resolver, drop and log the rest, forward nothing, and refuse
// connections to blocked CIDRs on output (S5); the root namespace drops all input from uplinks.
//
// Addresses repeat across sessions (every gateway namespace is separate): link n (0 is the agent,
// then each dependency) is 10.200.n.0/30, the gateway 10.200.n.1 and the microVM 10.200.n.2. Each
// link's rules pin its source and destination to those two addresses, so no microVM reaches
// another's gateway address or another link. Uplinks are /30s in 10.201.0.0/16.
//
// Commands run through Runner (ip, nft, sysctl, the CNI plugin), so the plan is testable.
package netsetup

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// LinkAddrs are the gateway and microVM ends of link n.
func LinkAddrs(n int) (gateway, guest netip.Addr) {
	return netip.AddrFrom4([4]byte{10, 200, byte(n), 1}), netip.AddrFrom4([4]byte{10, 200, byte(n), 2})
}

// The agent's link (0).
var (
	GatewayAddr, AgentAddr = LinkAddrs(0)
	uplinkNet              = netip.MustParsePrefix("10.201.0.0/16")
)

// MaxLinks bounds a session's microVMs (the agent and its dependencies).
const MaxLinks = 256

// Link is one microVM's link: its index (0 for the agent) and its network namespace.
type Link struct {
	Index int
	NS    string
	Name  string // for CNI (the container id)
}

// MaxUplinks is how many sessions can have an uplink at once.
const MaxUplinks = 1 << 14 // /30s in a /16

// Names in each gateway namespace.
const (
	UplinkIf = "uplink" // the gateway end of the uplink; every other interface but lo is a microVM link
	GuestIf  = "eth0"   // the microVM's end of its link
	CNIPath  = "/opt/cni/bin"
)

// Session is one session's network.
type Session struct {
	ID         string
	GatewayNS  string
	Links      []Link
	Uplink     int   // the uplink's index (0..MaxUplinks-1)
	Ports      []int // every port any gateway listener serves (each link's rules bound the address)
	BlockCIDRs []string
	Resolvers  []netip.Addr // the gateway's upstream resolvers (exempt from the CIDR block)
}

// UplinkAddrs are the root and gateway ends of uplink index n.
func UplinkAddrs(n int) (root, gw netip.Addr) {
	base := uplinkNet.Addr().As4()
	v := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(n*4)
	a := func(x uint32) netip.Addr {
		return netip.AddrFrom4([4]byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)})
	}
	return a(v + 1), a(v + 2)
}

// RootIf is the root end of uplink n (interface names are at most 15 bytes).
func RootIf(n int) string { return "sbxu" + strconv.Itoa(n) }

// Runner runs a command with optional stdin and returns its standard output.
type Runner interface {
	Run(ctx context.Context, stdin string, name string, args ...string) (string, error)
}

// RootRules is the VM root namespace's table (installed once, by sandboxd at start): no input from
// any uplink (the gateway namespaces cannot reach sshd, sandboxd, or anything local), no
// forwarding from one uplink to another, and NAT for the uplinks' traffic to the VM's uplink.
func RootRules() string {
	return `table inet sandbox
delete table inet sandbox
table inet sandbox {
	chain input {
		type filter hook input priority filter; policy accept;
		iifname "sbxu*" counter drop
	}
	chain forward {
		type filter hook forward priority filter; policy accept;
		iifname "sbxu*" oifname "sbxu*" counter drop
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr ` + uplinkNet.String() + ` oifname != "sbxu*" masquerade
	}
}
`
}

func joinInts(ps []int) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ", ")
}

// GatewayRules is a session's gateway namespace table.
// logPrefix tags a session's drops in the kernel log ("sbx <session> <what> "), so each bypass
// attempt can be traced to its session (nftables allows 127 bytes).
func logPrefix(s Session, what string) string {
	p := "sbx " + s.ID + " " + what + " "
	if len(p) > 120 {
		p = p[:120]
	}
	return p
}

func GatewayRules(s Session) string {
	ports := append([]int(nil), s.Ports...)
	sort.Ints(ports)
	var b strings.Builder
	fmt.Fprintf(&b, "table inet sbx {\n")
	if len(s.BlockCIDRs) > 0 {
		var v4, v6 []string
		for _, c := range s.BlockCIDRs {
			if p, err := netip.ParsePrefix(c); err == nil && p.Addr().Is4() {
				v4 = append(v4, p.Masked().String())
			} else if err == nil {
				v6 = append(v6, p.Masked().String())
			}
		}
		if len(v4) > 0 {
			fmt.Fprintf(&b, "\tset blocked4 { type ipv4_addr; flags interval; auto-merge; elements = { %s } }\n", strings.Join(v4, ", "))
		}
		if len(v6) > 0 {
			fmt.Fprintf(&b, "\tset blocked6 { type ipv6_addr; flags interval; auto-merge; elements = { %s } }\n", strings.Join(v6, ", "))
		}
	}
	links := fmt.Sprintf(`iifname != { "lo", %q }`, UplinkIf)
	// each link's address rules are inserted ahead of these once its interface exists (linkRules)
	fmt.Fprintf(&b, `	chain input {
		type filter hook input priority filter; policy drop;
		iif lo accept
		# replies: to the gateway's own connections out of the uplink and into a dependency's link
		# (5.8.6), and to what a link was allowed to open (each link's address rules come first)
		ct state established,related accept
		%s tcp dport { %s } accept
		%s meta l4proto { tcp, udp } th dport 53 accept
		counter log prefix %q drop
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
		counter log prefix %q drop
	}
	chain output {
		type filter hook output priority filter; policy accept;
`, links, joinInts(ports), links, logPrefix(s, "drop"), logPrefix(s, "forward"))
	for _, r := range s.Resolvers {
		fmt.Fprintf(&b, "\t\tip daddr %s meta l4proto { tcp, udp } th dport 53 accept\n", r)
	}
	if strings.Contains(b.String(), "set blocked4") {
		fmt.Fprintf(&b, "\t\tip daddr @blocked4 counter log prefix %q reject\n", logPrefix(s, "blocked"))
	}
	if strings.Contains(b.String(), "set blocked6") {
		fmt.Fprintf(&b, "\t\tip6 daddr @blocked6 counter log prefix %q reject\n", logPrefix(s, "blocked"))
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

// linkRules pin link n's interface to its two addresses: a packet from it must come from the
// microVM's address (no spoofing) and be for the gateway's address on that link (the weak-host
// model would otherwise accept it for any local address, another link's included).
func linkRules(s Session, ifname string, n int) []string {
	gw, guest := LinkAddrs(n)
	return []string{
		fmt.Sprintf(`insert rule inet sbx input iifname %q ip daddr != %s counter log prefix %q drop`, ifname, gw, logPrefix(s, "weakhost")),
		fmt.Sprintf(`insert rule inet sbx input iifname %q ip saddr != %s counter log prefix %q drop`, ifname, guest, logPrefix(s, "spoof")),
	}
}

// ptpConfig is the CNI configuration of link n.
func ptpConfig(n int) string {
	gw, guest := LinkAddrs(n)
	c := map[string]any{
		"cniVersion": "1.0.0", "name": "sandbox", "type": "ptp", "ipMasq": false, "mtu": 1500,
		"ipam": map[string]any{"type": "static",
			"addresses": []map[string]string{{"address": guest.String() + "/30", "gateway": gw.String()}},
			"routes":    []map[string]string{{"dst": "0.0.0.0/0"}}},
	}
	b, _ := json.Marshal(c)
	return string(b)
}

// Up builds the session's network; its namespaces (GatewayNS and each link's) must exist.
func Up(ctx context.Context, r Runner, s Session) error {
	if s.Uplink < 0 || s.Uplink >= MaxUplinks {
		return fmt.Errorf("netsetup: uplink index %d out of range", s.Uplink)
	}
	if len(s.Links) == 0 || len(s.Links) > MaxLinks {
		return fmt.Errorf("netsetup: %d links", len(s.Links))
	}
	rootAddr, gwAddr := UplinkAddrs(s.Uplink)
	gw := func(args ...string) []string { return append([]string{"netns", "exec", s.GatewayNS}, args...) }
	run := func(stdin string, name string, args ...string) (string, error) {
		out, err := r.Run(ctx, stdin, name, args...)
		if err != nil {
			return "", fmt.Errorf("netsetup %s: %w", strings.Join(append([]string{name}, args...), " "), err)
		}
		return out, nil
	}
	for _, st := range [][]string{
		// no forwarding in the gateway namespace (nftables is the second layer); the gateway's
		// unprivileged user may bind 53 and 443
		gw("sysctl", "-q", "-w", "net.ipv4.ip_forward=0", "net.ipv4.ip_unprivileged_port_start=0"),
		{"link", "add", RootIf(s.Uplink), "type", "veth", "peer", "name", UplinkIf, "netns", s.GatewayNS},
		{"addr", "add", rootAddr.String() + "/30", "dev", RootIf(s.Uplink)},
		{"link", "set", RootIf(s.Uplink), "up"},
		gw("ip", "addr", "add", gwAddr.String()+"/30", "dev", UplinkIf),
		gw("ip", "link", "set", UplinkIf, "up"),
		gw("ip", "route", "add", "default", "via", rootAddr.String()),
	} {
		if _, err := run("", "ip", st...); err != nil {
			return err
		}
	}
	// the rules go in before any link exists
	if _, err := run(GatewayRules(s), "ip", gw("nft", "-f", "-")...); err != nil {
		return err
	}
	for _, l := range s.Links {
		if l.Index < 0 || l.Index >= MaxLinks {
			return fmt.Errorf("netsetup: link index %d out of range", l.Index)
		}
		// ptp, run in the gateway namespace with the microVM's as CNI_NETNS: neither end is in the
		// VM root namespace
		if _, err := run(ptpConfig(l.Index), "ip", gw("env", "CNI_COMMAND=ADD", "CNI_CONTAINERID="+l.Name,
			"CNI_NETNS=/var/run/netns/"+l.NS, "CNI_IFNAME="+GuestIf, "CNI_PATH="+CNIPath, CNIPath+"/ptp")...); err != nil {
			return err
		}
		_, guest := LinkAddrs(l.Index)
		out, err := run("", "ip", gw("ip", "-o", "route", "get", guest.String())...)
		if err != nil {
			return err
		}
		ifname := routeDev(out)
		if ifname == "" || ifname == UplinkIf || ifname == "lo" {
			return fmt.Errorf("netsetup: no link interface for %s in %q", guest, out)
		}
		if _, err := run(strings.Join(linkRules(s, ifname, l.Index), "\n")+"\n", "ip", gw("nft", "-f", "-")...); err != nil {
			return err
		}
	}
	return nil
}

// routeDev is the interface in `ip -o route get` output ("10.200.0.2 dev vethX src ...").
func routeDev(out string) string {
	f := strings.Fields(out)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "dev" {
			return f[i+1]
		}
	}
	return ""
}
