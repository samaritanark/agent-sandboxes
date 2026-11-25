package resolver

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var pol = &Policy{
	Allow:        []string{"api.anthropic.com", "*.github.com", "github.com"},
	BlockDomains: []string{"*.gist.github.com"},
	Dependencies: []string{"postgres"},
	Gateway:      netip.MustParseAddr("10.200.0.1"),
}

func TestAnswer(t *testing.T) {
	cases := []struct {
		name  string
		qtype uint16
		rcode int
		addr  string
	}{
		{"api.anthropic.com.", dns.TypeA, dns.RcodeSuccess, "10.200.0.1"},
		{"API.Anthropic.COM.", dns.TypeA, dns.RcodeSuccess, "10.200.0.1"},
		{"api.github.com.", dns.TypeA, dns.RcodeSuccess, "10.200.0.1"},
		{"github.com.", dns.TypeA, dns.RcodeSuccess, "10.200.0.1"},
		{"api.anthropic.com.", dns.TypeAAAA, dns.RcodeSuccess, ""},
		{"api.anthropic.com.", dns.TypeTXT, dns.RcodeSuccess, ""},
		{"x.gist.github.com.", dns.TypeA, dns.RcodeNameError, ""}, // blocked: deny wins
		{"a.b.github.com.", dns.TypeA, dns.RcodeNameError, ""},    // one label only
		{"anthropic.com.", dns.TypeA, dns.RcodeNameError, ""},
		{"exfil-data-here.evil.com.", dns.TypeTXT, dns.RcodeNameError, ""},
		{"postgres.deps.sandbox.internal.", dns.TypeA, dns.RcodeSuccess, "10.200.0.1"},
		{"redis.deps.sandbox.internal.", dns.TypeA, dns.RcodeNameError, ""},
		{"deps.sandbox.internal.", dns.TypeA, dns.RcodeNameError, ""},
	}
	for _, c := range cases {
		rcode, addrs := pol.Answer(c.name, c.qtype)
		got := ""
		if len(addrs) > 0 {
			got = addrs[0].String()
		}
		if rcode != c.rcode || got != c.addr {
			t.Errorf("%s %s: %s %q", c.name, dns.TypeToString[c.qtype], dns.RcodeToString[rcode], got)
		}
	}
	v6 := *pol
	v6.Gateway6 = netip.MustParseAddr("fd00::1")
	if _, a := v6.Answer("api.anthropic.com.", dns.TypeAAAA); len(a) != 1 || a[0].String() != "fd00::1" {
		t.Errorf("AAAA with IPv6: %v", a)
	}
}

func TestServer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	srv := &dns.Server{PacketConn: pc, Handler: s}
	go srv.ActivateAndServe()
	defer srv.Shutdown()
	c := &dns.Client{Timeout: 2 * time.Second}
	ask := func(name string, qtype uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		r, _, err := c.Exchange(m, pc.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := ask("api.anthropic.com.", dns.TypeA); r.Rcode != dns.RcodeRefused {
		t.Errorf("no policy yet: %s", dns.RcodeToString[r.Rcode])
	}
	s.SetPolicy(pol)
	r := ask("api.anthropic.com.", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "10.200.0.1" || r.Answer[0].Header().Ttl != TTL {
		t.Errorf("allowed: %v", r)
	}
	if r := ask("evil.com.", dns.TypeA); r.Rcode != dns.RcodeNameError || len(r.Answer) != 0 {
		t.Errorf("denied: %v", r)
	}
	two := new(dns.Msg)
	two.SetQuestion("api.anthropic.com.", dns.TypeA)
	two.Question = append(two.Question, dns.Question{Name: "evil.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if r, _, err := c.Exchange(two, pc.LocalAddr().String()); err != nil || r.Rcode != dns.RcodeFormatError || len(r.Answer) != 0 {
		t.Errorf("two questions: %v %v", r, err)
	}
	ch := new(dns.Msg)
	ch.SetQuestion("version.bind.", dns.TypeTXT)
	ch.Question[0].Qclass = dns.ClassCHAOS
	if r, _, err := c.Exchange(ch, pc.LocalAddr().String()); err != nil || r.Rcode != dns.RcodeRefused {
		t.Errorf("CHAOS: %v %v", r, err)
	}
	// a policy change applies at once
	s.SetPolicy(&Policy{Allow: []string{"evil.com"}, Gateway: pol.Gateway})
	if r := ask("evil.com.", dns.TypeA); r.Rcode != dns.RcodeSuccess {
		t.Errorf("after the policy change: %v", r)
	}
}
