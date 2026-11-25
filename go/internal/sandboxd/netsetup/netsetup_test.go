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
	return Session{ID: "s-net", GatewayNS: "sbx-s-net-g", AgentNS: "sbx-s-net-a", Uplink: 3, Ports: []int{443, 8443},
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
	for _, want := range []string{"policy drop", "tcp dport { 443, 8443 } accept", "ip saddr != 10.200.0.2", "ip daddr != 10.200.0.1",
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

func (l *logRunner) Run(_ context.Context, _ string, name string, args ...string) error {
	l.cmds = append(l.cmds, name+" "+strings.Join(args, " "))
	return nil
}

func TestPlan(t *testing.T) {
	var l logRunner
	if err := Up(context.Background(), &l, session()); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(l.cmds, "\n")
	for _, want := range []string{"net.ipv4.ip_forward=0", "link add sbxu3 type veth peer name uplink netns sbx-s-net-g",
		"addr add 10.201.0.13/30 dev sbxu3", "route add default via 10.201.0.13", "nft -f -", "CNI_NETNS=/var/run/netns/sbx-s-net-a"} {
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

func (execRunner) Run(ctx context.Context, stdin, name string, args ...string) error {
	c := exec.CommandContext(ctx, name, args...)
	c.Stdin = strings.NewReader(stdin)
	if out, err := c.CombinedOutput(); err != nil {
		return &runErr{err, string(out)}
	}
	return nil
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
	for _, ns := range []string{s.GatewayNS, s.AgentNS} {
		sh(t, "ip netns del "+ns)
		if out, err := sh(t, "ip netns add "+ns+" && ip -n "+ns+" link set lo up"); err != nil {
			t.Fatal(out)
		}
		defer sh(t, "ip netns del "+ns)
	}
	sh(t, "sysctl -q -w net.ipv4.ip_forward=1")
	if err := (execRunner{}).Run(context.Background(), RootRules(), "nft", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	if err := Up(context.Background(), execRunner{}, s); err != nil {
		t.Fatal(err)
	}
	ag := "ip netns exec " + s.AgentNS + " "
	gw := "ip netns exec " + s.GatewayNS + " "
	rootAddr, _ := UplinkAddrs(s.Uplink)
	// a listener on the gateway's address, as Envoy will be
	go sh(t, gw+"timeout 8 python3 -c 'import socket;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((\"10.200.0.1\",443));s.listen();c,_=s.accept();c.send(b\"gw\\n\")'")
	sh(t, "sleep 1")
	if out, err := sh(t, ag+"ip -4 -o addr show dev eth0"); err != nil || !strings.Contains(out, "10.200.0.2/30") {
		t.Errorf("agent address: %s %v", out, err)
	}
	if out, err := sh(t, ag+`timeout 3 bash -c 'exec 3<>/dev/tcp/10.200.0.1/443; head -1 <&3'`); err != nil || out != "gw" {
		t.Errorf("the gateway listener is not reachable: %q %v", out, err)
	}
	for name, cmd := range map[string]string{
		"internet through the gateway":    ag + `timeout 3 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'`,
		"the uplink's root address":       ag + `timeout 3 bash -c 'exec 3<>/dev/tcp/` + rootAddr.String() + `/22'`,
		"another gateway port":            ag + `timeout 3 bash -c 'exec 3<>/dev/tcp/10.200.0.1/22'`,
		"VM sshd from the gateway":        gw + `timeout 3 bash -c 'exec 3<>/dev/tcp/` + rootAddr.String() + `/22'`,
		"a blocked CIDR from the gateway": gw + `timeout 3 bash -c 'exec 3<>/dev/tcp/169.254.169.254/80'`,
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
