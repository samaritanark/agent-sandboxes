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

// TestDeclare (design 5.2.6): a launch declares its endpoints under its session with an expiry;
// the worker allows them until then, and the host's release closes a session that is no longer
// live, keeps a live one's, and keeps the operator's own entries; an expired entry is closed even
// before the host removes it, and an unparseable file is never overwritten.
func TestDeclare(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, EndpointsName)
	os.WriteFile(path, []byte("10.0.0.2:5432 # the operator's\n"), 0o600)
	now := time.Unix(1800000000, 0)
	k3d, other := netip.MustParseAddrPort("192.168.1.178:6443"), netip.MustParseAddrPort("192.168.1.178:8443")
	a, b := "ses-20270115-080000-beef", "ses-20270115-080100-cafe"
	if err := Declare(dir, a, []netip.AddrPort{k3d}, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := Declare(dir, b, []netip.AddrPort{other}, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	clock := now
	e := &EndpointsFile{Path: path, Now: func() time.Time { return clock }}
	s, err := e.Read()
	if err != nil || len(s) != 3 || !s[k3d] || !s[other] {
		t.Fatalf("%v %v", s, err)
	}
	if got, _ := Declared(dir); len(got) != 2 || got[0] != a || got[1] != b {
		t.Errorf("declared %q", got)
	}
	// re-declaring replaces the session's endpoints
	Declare(dir, a, []netip.AddrPort{k3d, k3d}, now.Add(time.Hour), now)
	if es, _ := ReadEndpoints(path); len(es) != 4 {
		t.Errorf("%+v", es)
	}
	Declare(dir, a, []netip.AddrPort{k3d}, now.Add(time.Hour), now)
	// the host releases a session that is no longer live
	if err := Release(dir, func(id string) bool { return id == b }, now); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(path, now.Add(time.Minute), now.Add(time.Minute))
	if s, _ := e.Read(); s[k3d] || !s[other] || !s[netip.MustParseAddrPort("10.0.0.2:5432")] {
		t.Errorf("after release: %v", s)
	}
	// past its expiry, an entry is closed before anyone removes it, and then removed
	clock = now.Add(2 * time.Hour)
	if s, _ := e.Read(); s[other] || len(s) != 1 {
		t.Errorf("expired: %v", s)
	}
	Release(dir, func(string) bool { return true }, clock)
	if es, _ := ReadEndpoints(path); len(es) != 1 || es[0].Session != "" {
		t.Errorf("%+v", es)
	}
	// releasing the last entry removes the file
	os.Remove(path)
	Declare(dir, a, []netip.AddrPort{k3d}, now.Add(time.Hour), now)
	Release(dir, func(string) bool { return false }, now)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file left: %v", err)
	}
	for _, c := range []struct {
		session string
		ep      netip.AddrPort
	}{{"bad id!", k3d}, {a, netip.MustParseAddrPort("[::1]:80")}, {a, netip.MustParseAddrPort("1.2.3.4:0")}} {
		if Declare(dir, c.session, []netip.AddrPort{c.ep}, now.Add(time.Hour), now) == nil {
			t.Errorf("declared %q %v", c.session, c.ep)
		}
	}
	os.WriteFile(path, []byte("garbage\n"), 0o600)
	if Declare(dir, a, []netip.AddrPort{k3d}, now.Add(time.Hour), now) == nil {
		t.Error("an unparseable file was overwritten")
	}
	for _, bad := range []string{"1.2.3.4:80 session=a session=b\n", "1.2.3.4:80 expires=1 expires=2\n", "1.2.3.4:80 expires=x\n", "1.2.3.4:80 colour=red\n", "1.2.3.4:80 session=a/b\n"} {
		os.WriteFile(path, []byte(bad), 0o600)
		if _, err := ReadEndpoints(path); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
