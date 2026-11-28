package netsetup

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func session() Session {
	return Session{ID: "s-net", GatewayNS: "sbx-s-net-g", Links: []Link{{0, "sbx-s-net-a", "s-net"}, {1, "sbx-s-net-d-db", "s-net--db"}},
		Uplink: 3, Ports: []int{443, 8443, 5432},
		BlockCIDRs: []string{"169.254.0.0/16", "10.0.0.0/8", "fd00::/8"}, Resolvers: []netip.Addr{netip.MustParseAddr("10.0.2.3")}}
}

func TestUplinkAddrs(t *testing.T) {
	for n, want := range map[int][2]string{0: {"10.201.0.1", "10.201.0.2"}, 3: {"10.201.0.13", "10.201.0.14"}, 64: {"10.201.1.1", "10.201.1.2"}} {
		r, g := UplinkAddrs(n)
		if r.String() != want[0] || g.String() != want[1] {
			t.Errorf("%d: %s %s", n, r, g)
		}
	}
	if len(RootIf(MaxUplinks-1)) > 15 {
		t.Error("interface name too long")
	}
}

func TestGatewayRules(t *testing.T) {
	r := GatewayRules(session())
	for _, want := range []string{"policy drop", "tcp dport { 443, 5432, 8443 } accept",
		"ip daddr 10.0.2.3 meta l4proto { tcp, udp } th dport 53 accept", "ip daddr @blocked4", "ip6 daddr @blocked6",
		`log prefix "sbx s-net forward "`, `log prefix "sbx s-net drop "`} {
		if !strings.Contains(r, want) {
			t.Errorf("rules lack %q:\n%s", want, r)
		}
	}
	// the resolver exemption comes before the CIDR block
	if strings.Index(r, "10.0.2.3") > strings.Index(r, "@blocked4 counter") {
		t.Error("the resolver exemption is after the block")
	}
}

type logRunner struct{ cmds []string }

func (l *logRunner) Run(_ context.Context, stdin string, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	if strings.HasPrefix(stdin, "insert rule") {
		cmd += " <<< " + stdin
	}
	l.cmds = append(l.cmds, cmd)
	if i := strings.Index(cmd, "route get 10.200."); i >= 0 {
		n := strings.Split(cmd[i+len("route get "):], ".")[2]
		return "10.200." + n + ".2 dev veth" + n + " src 10.200." + n + ".1 uid 0", nil
	}
	return "", nil
}

func TestPlan(t *testing.T) {
	var l logRunner
	if err := Up(context.Background(), &l, session()); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(l.cmds, "\n")
	for _, want := range []string{"net.ipv4.ip_forward=0", "link add sbxu3 type veth peer name uplink netns sbx-s-net-g",
		"addr add 10.201.0.13/30 dev sbxu3", "route add default via 10.201.0.13", "nft -f -", "CNI_NETNS=/var/run/netns/sbx-s-net-a",
		"CNI_NETNS=/var/run/netns/sbx-s-net-d-db", `iifname "veth0" ip daddr != 10.200.0.1`, `iifname "veth0" ip saddr != 10.200.0.2`,
		`iifname "veth1" ip daddr != 10.200.1.1`, `iifname "veth1" ip saddr != 10.200.1.2`} {
		if !strings.Contains(all, want) {
			t.Errorf("plan lacks %q:\n%s", want, all)
		}
	}
	if strings.Index(all, "nft -f -") > strings.Index(all, "ptp") {
		t.Error("the link exists before its rules")
	}
	if err := Up(context.Background(), &l, Session{Uplink: MaxUplinks}); err == nil {
		t.Error("an out-of-range uplink was accepted")
	}
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, stdin, name string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, name, args...)
	c.Stdin = strings.NewReader(stdin)
	out, err := c.CombinedOutput()
	if err != nil {
		return "", &runErr{err, string(out)}
	}
	return string(out), nil
}

type runErr struct {
	err error
	out string
}

func (e *runErr) Error() string { return e.err.Error() + ": " + e.out }

func sh(t *testing.T, cmd string) (string, error) {
	t.Helper()
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// TestOnLinux builds the network for real (root, SANDBOX_NET_TEST=1, CNI plugins in CNI_DIR or
// /opt/cni/bin) and checks what the topology promises, with a shell standing in for the microVM.
func TestOnLinux(t *testing.T) {
	if os.Getenv("SANDBOX_NET_TEST") == "" || os.Geteuid() != 0 {
		t.Skip("needs root and SANDBOX_NET_TEST=1")
	}
	if _, err := os.Stat(CNIPath + "/ptp"); err != nil {
		t.Skip("no CNI ptp plugin in " + CNIPath)
	}
	s := session()
	s.Uplink = 4000
	s.BlockCIDRs = []string{"169.254.0.0/16"}
	res, _ := sh(t, `awk '/^nameserver/{print $2; exit}' /run/systemd/resolve/resolv.conf`)
	s.Resolvers = []netip.Addr{netip.MustParseAddr(res)}
	for _, ns := range []string{s.GatewayNS, s.Links[0].NS, s.Links[1].NS} {
		sh(t, "ip netns del "+ns)
		if out, err := sh(t, "ip netns add "+ns+" && ip -n "+ns+" link set lo up"); err != nil {
			t.Fatal(out)
		}
		defer sh(t, "ip netns del "+ns)
	}
	sh(t, "sysctl -q -w net.ipv4.ip_forward=1")
	if _, err := (execRunner{}).Run(context.Background(), RootRules(), "nft", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	if err := Up(context.Background(), execRunner{}, s); err != nil {
		t.Fatal(err)
	}
	ag := "ip netns exec " + s.Links[0].NS + " "
	dep := "ip netns exec " + s.Links[1].NS + " "
	gw := "ip netns exec " + s.GatewayNS + " "
	rootAddr, _ := UplinkAddrs(s.Uplink)
	// a listener on every gateway address, as Envoy will be: the rules, not the listener, decide
	go sh(t, gw+`timeout 25 python3 -c '
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 443)); s.listen()
while True:
    c,_=s.accept(); c.send(b"gw\n"); c.close()
'`)
	sh(t, "sleep 1")
	if out, err := sh(t, ag+"ip -4 -o addr show dev eth0"); err != nil || !strings.Contains(out, "10.200.0.2/30") {
		t.Errorf("agent address: %s %v", out, err)
	}
	if out, err := sh(t, dep+"ip -4 -o addr show dev eth0"); err != nil || !strings.Contains(out, "10.200.1.2/30") {
		t.Errorf("dependency address: %s %v", out, err)
	}
	if out, err := sh(t, ag+`timeout 3 bash -c 'exec 3<>/dev/tcp/10.200.0.1/443; head -1 <&3'`); err != nil || out != "gw" {
		t.Errorf("the gateway listener is not reachable: %q %v", out, err)
	}
	if out, err := sh(t, dep+`timeout 3 bash -c 'exec 3<>/dev/tcp/10.200.1.1/443; head -1 <&3'`); err != nil || out != "gw" {
		t.Errorf("the dependency cannot reach its own gateway address: %q %v", out, err)
	}
	// the gateway reaches a dependency (it forwards the agent's connections to it, 5.8.6)
	go sh(t, dep+`timeout 6 python3 -c 'import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("10.200.1.2",5432));s.listen();c,_=s.accept();c.send(b"db\n")'`)
	sh(t, "sleep 1")
	if out, err := sh(t, gw+`timeout 3 bash -c 'exec 3<>/dev/tcp/10.200.1.2/5432; head -1 <&3'`); err != nil || out != "db" {
		t.Errorf("the gateway cannot reach the dependency: %q %v", out, err)
	}
	for name, cmd := range map[string]string{
		"internet through the gateway":                    ag + `timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'`,
		"the uplink's root address":                       ag + `timeout 3 bash -c 'exec 3<>/dev/tcp/` + rootAddr.String() + `/22'`,
		"another gateway port":                            ag + `timeout 3 bash -c 'exec 3<>/dev/tcp/10.200.0.1/22'`,
		"VM sshd from the gateway":                        gw + `timeout 3 bash -c 'exec 3<>/dev/tcp/` + rootAddr.String() + `/22'`,
		"a blocked CIDR from the gateway":                 gw + `timeout 3 bash -c 'exec 3<>/dev/tcp/169.254.169.254/80'`,
		"the dependency's gateway address from the agent": ag + `timeout 3 bash -c 'exec 3<>/dev/tcp/10.200.1.1/443'`,
		"the agent's gateway address from the dependency": dep + `timeout 3 bash -c 'exec 3<>/dev/tcp/10.200.0.1/443'`,
		"the agent from the dependency":                   dep + `timeout 3 bash -c 'exec 3<>/dev/tcp/10.200.0.2/443'`,
	} {
		if out, err := sh(t, cmd); err == nil {
			t.Errorf("%s: reachable (%s)", name, out)
		}
	}
	if out, err := sh(t, gw+`timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' && echo ok`); err != nil {
		t.Errorf("the gateway cannot reach the internet: %s %v", out, err)
	}
	// the refusals came from the rules, not from closed ports: their counters moved
	fired := regexp.MustCompile(`counter packets [1-9]`)
	for _, c := range []string{gw + "nft list chain inet sbx forward", gw + "nft list chain inet sbx output", "nft list chain inet sandbox input"} {
		if out, _ := sh(t, c); !fired.MatchString(out) {
			t.Errorf("%s: no drop counted:\n%s", c, out)
		}
	}
}

// TestHostEndpointsScript (design 5.2.6): the root table refuses a declared host endpoint from any
// uplink but its session's, and the script replaces both sets whole; an endpoint two sessions
// declare is listed once with both owners; a bad one is refused.
func TestHostEndpointsScript(t *testing.T) {
	root := RootRules()
	for _, want := range []string{"set hostep { type ipv4_addr . inet_service; }", "set hostep_owner { type ifname . ipv4_addr . inet_service; }",
		`iifname "sbxu*" meta l4proto { tcp, udp } ip daddr . th dport @hostep iifname . ip daddr . th dport != @hostep_owner counter log prefix "sbx hostep " reject`} {
		if !strings.Contains(root, want) {
			t.Errorf("root rules lack %q", want)
		}
	}
	a := netip.MustParseAddr("192.168.1.178")
	got, err := HostEndpointsScript([]HostEndpoint{{Uplink: 0, Addr: a, Port: 6443}, {Uplink: 3, Addr: a, Port: 6443}, {Uplink: 3, Addr: a, Port: 8200}})
	want := "flush set inet sandbox hostep\nflush set inet sandbox hostep_owner\n" +
		"add element inet sandbox hostep { 192.168.1.178 . 6443, 192.168.1.178 . 8200 }\n" +
		`add element inet sandbox hostep_owner { "sbxu0" . 192.168.1.178 . 6443, "sbxu3" . 192.168.1.178 . 6443, "sbxu3" . 192.168.1.178 . 8200 }` + "\n"
	if err != nil || got != want {
		t.Errorf("%v\n%s", err, got)
	}
	if got, _ := HostEndpointsScript(nil); got != "flush set inet sandbox hostep\nflush set inet sandbox hostep_owner\n" {
		t.Errorf("none: %q", got)
	}
	for _, bad := range []HostEndpoint{{Uplink: 0, Addr: netip.MustParseAddr("::1"), Port: 1}, {Uplink: 0, Addr: a, Port: 0}, {Uplink: MaxUplinks, Addr: a, Port: 1}} {
		if _, err := HostEndpointsScript([]HostEndpoint{bad}); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}
