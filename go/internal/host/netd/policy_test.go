package netd

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func fixedHost(p ...string) func() ([]netip.Prefix, error) {
	return func() ([]netip.Prefix, error) {
		var out []netip.Prefix
		for _, s := range p {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out, nil
	}
}

func TestRefuse(t *testing.T) {
	pol := Policy{
		HostPrefixes: fixedHost("127.0.0.1/8", "192.168.1.178/24", "10.8.0.5/32", "fe80::1/64", "fd00::5/64"),
		Declared: func() (map[netip.AddrPort]bool, error) {
			return map[netip.AddrPort]bool{netip.MustParseAddrPort("192.168.1.178:6443"): true}, nil
		},
	}
	cases := []struct {
		dst  string
		pass bool
	}{
		{"140.82.114.4:443", true},
		{"1.1.1.1:53", true},
		{"192.168.1.1:80", true},     // another machine on the LAN
		{"10.8.0.1:443", true},       // through a VPN, not the host's own address
		{"192.168.1.178:6443", true}, // declared
		{"192.168.1.178:6444", false},
		{"192.168.1.178:22", false},
		{"10.8.0.5:80", false}, // the host's VPN address
		{"192.168.1.255:9", false},
		{"255.255.255.255:67", false},
		{"224.0.0.251:5353", false},
		{"127.0.0.1:80", false},
		{"127.1.2.3:80", false},
		{"0.0.0.0:80", false},
		{"169.254.169.254:80", false},
		{"192.168.127.1:80", false},
		{"192.168.127.2:22", false},
		{"[::ffff:192.168.1.178]:80", false}, // a mapped address is the same address
		{"[::ffff:140.82.114.4]:443", true},
		{"[fd00::5]:80", false},
		{"[2606:4700::1]:443", false}, // no IPv6 at all
	}
	for _, c := range cases {
		why := pol.Refuse(netip.MustParseAddrPort(c.dst))
		if (why == "") != c.pass {
			t.Errorf("%s: refused=%q, want pass=%v", c.dst, why, c.pass)
		}
	}
	if pol.Refuse(netip.AddrPort{}) == "" {
		t.Error("the zero address passed")
	}
}

func TestRefuseFailsClosed(t *testing.T) {
	dst := netip.MustParseAddrPort("140.82.114.4:443")
	if (Policy{}).Refuse(dst) == "" {
		t.Error("a policy with no view of the host passed")
	}
	bad := Policy{HostPrefixes: func() ([]netip.Prefix, error) { return nil, errors.New("boom") }}
	if bad.Refuse(dst) == "" {
		t.Error("an unreadable host address list passed")
	}
	bad = Policy{HostPrefixes: fixedHost(), Declared: func() (map[netip.AddrPort]bool, error) { return nil, errors.New("boom") }}
	if bad.Refuse(dst) == "" {
		t.Error("an unreadable endpoint list passed")
	}
}

func TestBroadcast(t *testing.T) {
	for p, want := range map[string]string{"192.168.1.178/24": "192.168.1.255", "10.0.0.1/8": "10.255.255.255",
		"172.16.5.4/20": "172.16.15.255", "192.168.1.178/30": "192.168.1.179", "0.0.0.0/0": "255.255.255.255"} {
		if b, ok := broadcast(netip.MustParsePrefix(p)); !ok || b.String() != want {
			t.Errorf("%s: %v %v, want %s", p, b, ok, want)
		}
	}
	for _, p := range []string{"10.0.0.1/31", "10.0.0.1/32", "fd00::1/64"} {
		if _, ok := broadcast(netip.MustParsePrefix(p)); ok {
			t.Errorf("%s has a broadcast", p)
		}
	}
}

func TestHostPrefixesSeesLoopback(t *testing.T) {
	p, err := HostPrefixes()
	if err != nil {
		t.Fatal(err)
	}
	pol := Policy{HostPrefixes: func() ([]netip.Prefix, error) { return p, nil }}
	for _, h := range p {
		if h.Addr().Is4() && pol.Refuse(netip.AddrPortFrom(h.Addr(), 80)) == "" {
			t.Errorf("this host's address %v passed", h.Addr())
		}
	}
}

func TestEndpointsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoints")
	e := &EndpointsFile{Path: path}
	if s, err := e.Read(); err != nil || len(s) != 0 {
		t.Fatalf("missing file: %v %v", s, err)
	}
	os.WriteFile(path, []byte("# k3d\n192.168.1.178:6443\n\n10.0.0.2:5432 # db\n"), 0o600)
	s, err := e.Read()
	if err != nil || len(s) != 2 || !s[netip.MustParseAddrPort("10.0.0.2:5432")] {
		t.Fatalf("%v %v", s, err)
	}
	os.WriteFile(path, []byte("192.168.1.178:6443\nlocalhost:80\n"), 0o600)
	os.Chtimes(path, time.Now().Add(time.Minute), time.Now().Add(time.Minute))
	if _, err := e.Read(); err == nil {
		t.Error("a bad line was accepted")
	}
	pol := Policy{HostPrefixes: fixedHost(), Declared: e.Read}
	if pol.Refuse(netip.MustParseAddrPort("140.82.114.4:443")) == "" {
		t.Error("a broken endpoint file did not fail closed")
	}
	for _, bad := range []string{"[::1]:80\n", "1.2.3.4:0\n", "1.2.3.4\n"} {
		os.WriteFile(path, []byte(bad), 0o600)
		os.Chtimes(path, time.Now().Add(2*time.Minute), time.Now().Add(2*time.Minute))
		if _, err := e.Read(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	os.Remove(path)
	if s, err := e.Read(); err != nil || len(s) != 0 {
		t.Errorf("removed file: %v %v", s, err)
	}
}
