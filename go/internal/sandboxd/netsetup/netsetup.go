// Package netsetup builds a session's network (design 5.8.1, 5.8.2): egress by topology. Each
// session gets a gateway namespace with one link to its agent's microVM namespace (the CNI ptp
// plugin, run inside the gateway namespace so neither end is in the VM root namespace, S1) and one
// NAT'd uplink to the VM root namespace. nftables in the gateway namespace accept from the link
// only the gateway's listeners and resolver, drop and log the rest, forward nothing, and refuse
// connections to blocked CIDRs on output (S5); the root namespace drops all input from uplinks.
//
// Addresses repeat across sessions (every gateway namespace is separate): the agent is 10.200.0.2
// and its gateway 10.200.0.1. Uplinks are /30s in 10.201.0.0/16, one per live session.
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

// Fixed addresses inside each session's namespaces.
var (
	GatewayAddr = netip.MustParseAddr("10.200.0.1")
	AgentAddr   = netip.MustParseAddr("10.200.0.2")
	uplinkNet   = netip.MustParsePrefix("10.201.0.0/16")
)

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
	GatewayNS  string // namespace names
	AgentNS    string
	Uplink     int // the uplink's index (0..MaxUplinks-1)
	Ports      []int
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

// Runner runs a command with optional stdin.
type Runner interface {
	Run(ctx context.Context, stdin string, name string, args ...string) error
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
	fmt.Fprintf(&b, `	chain input {
		type filter hook input priority filter; policy drop;
		iif lo accept
		iifname %q ct state established,related accept
		%s ip saddr != %s counter log prefix "sbx-spoof " drop
		%s ip daddr != %s counter log prefix "sbx-weakhost " drop
		%s tcp dport { %s } accept
		%s meta l4proto { tcp, udp } th dport 53 accept
		counter log prefix "sbx-drop " drop
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
		counter log prefix "sbx-forward " drop
	}
	chain output {
		type filter hook output priority filter; policy accept;
`, UplinkIf, links, AgentAddr, links, GatewayAddr, links, joinInts(ports), links)
	for _, r := range s.Resolvers {
		fmt.Fprintf(&b, "\t\tip daddr %s meta l4proto { tcp, udp } th dport 53 accept\n", r)
	}
	if strings.Contains(b.String(), "set blocked4") {
		b.WriteString("\t\tip daddr @blocked4 counter log prefix \"sbx-blocked \" reject\n")
	}
	if strings.Contains(b.String(), "set blocked6") {
		b.WriteString("\t\tip6 daddr @blocked6 counter log prefix \"sbx-blocked \" reject\n")
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

// ptpConfig is the CNI configuration of the agent's link.
func ptpConfig() string {
	c := map[string]any{
		"cniVersion": "1.0.0", "name": "sandbox", "type": "ptp", "ipMasq": false, "mtu": 1500,
		"ipam": map[string]any{"type": "static",
			"addresses": []map[string]string{{"address": AgentAddr.String() + "/30", "gateway": GatewayAddr.String()}},
			"routes":    []map[string]string{{"dst": "0.0.0.0/0"}}},
	}
	b, _ := json.Marshal(c)
	return string(b)
}

// Up builds the session's network; its namespaces (GatewayNS, AgentNS) must exist.
func Up(ctx context.Context, r Runner, s Session) error {
	if s.Uplink < 0 || s.Uplink >= MaxUplinks {
		return fmt.Errorf("netsetup: uplink index %d out of range", s.Uplink)
	}
	rootAddr, gwAddr := UplinkAddrs(s.Uplink)
	gw := func(args ...string) []string { return append([]string{"netns", "exec", s.GatewayNS}, args...) }
	steps := []struct {
		stdin string
		name  string
		args  []string
	}{
		// no forwarding in the gateway namespace (nftables is the second layer); the gateway's
		// unprivileged user may bind 53 and 443
		{"", "ip", gw("sysctl", "-q", "-w", "net.ipv4.ip_forward=0", "net.ipv4.ip_unprivileged_port_start=0")},
		{"", "ip", []string{"link", "add", RootIf(s.Uplink), "type", "veth", "peer", "name", UplinkIf, "netns", s.GatewayNS}},
		{"", "ip", []string{"addr", "add", rootAddr.String() + "/30", "dev", RootIf(s.Uplink)}},
		{"", "ip", []string{"link", "set", RootIf(s.Uplink), "up"}},
		{"", "ip", gw("ip", "addr", "add", gwAddr.String()+"/30", "dev", UplinkIf)},
		{"", "ip", gw("ip", "link", "set", UplinkIf, "up")},
		{"", "ip", gw("ip", "route", "add", "default", "via", rootAddr.String())},
		// the rules go in before the link exists
		{GatewayRules(s), "ip", gw("nft", "-f", "-")},
		// the agent's link: ptp, run in the gateway namespace with the agent's as CNI_NETNS
		{ptpConfig(), "ip", gw("env", "CNI_COMMAND=ADD", "CNI_CONTAINERID="+s.ID, "CNI_NETNS=/var/run/netns/"+s.AgentNS,
			"CNI_IFNAME="+GuestIf, "CNI_PATH="+CNIPath, CNIPath+"/ptp")},
	}
	for _, st := range steps {
		if err := r.Run(ctx, st.stdin, st.name, st.args...); err != nil {
			return fmt.Errorf("netsetup %s: %w", strings.Join(append([]string{st.name}, st.args...), " "), err)
		}
	}
	return nil
}
