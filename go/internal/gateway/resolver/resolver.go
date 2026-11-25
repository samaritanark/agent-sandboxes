// Package resolver is a session's filtering DNS resolver (design 5.8.3). It answers from the
// session's policy alone and forwards nothing: a name the session may reach (allowed, and not
// blocked: deny wins) resolves to the gateway's link address, and the gateway then makes the real
// connection after its own checks (5.8.4). Dependency names (<dep>.deps.sandbox.internal) resolve
// to the gateway too. Everything else is NXDOMAIN, so DNS cannot carry data out of the session
// and a blocked name never reaches an upstream resolver.
package resolver

import (
	"net"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"

	"github.com/samaritanark/agent-sandboxes/go/internal/egressmatch"
)

// DepZone is the zone of dependency names.
const DepZone = "deps.sandbox.internal"

// TTL is short: the policy can change during a session (hot allowlist extension, 5.8.8).
const TTL = 5

// Policy is what the resolver answers from.
type Policy struct {
	Allow        []string
	BlockDomains []string
	Dependencies []string   // names of the session's dependencies
	Gateway      netip.Addr // the gateway's link address (IPv4)
	Gateway6     netip.Addr // its IPv6 address, if IPv6 is enabled
}

// Answer is the resolver's decision for one question: an address (for A or AAAA), an empty
// NOERROR answer, or NXDOMAIN.
func (p *Policy) Answer(name string, qtype uint16) (rcode int, addrs []netip.Addr) {
	n := egressmatch.Normalize(name)
	known := false
	if dep, ok := strings.CutSuffix(n, "."+DepZone); ok {
		for _, d := range p.Dependencies {
			known = known || d == dep
		}
	} else {
		known = egressmatch.Decide(n, p.Allow, p.BlockDomains)
	}
	if !known {
		return dns.RcodeNameError, nil
	}
	switch qtype {
	case dns.TypeA:
		return dns.RcodeSuccess, []netip.Addr{p.Gateway}
	case dns.TypeAAAA:
		if p.Gateway6.IsValid() {
			return dns.RcodeSuccess, []netip.Addr{p.Gateway6}
		}
	}
	return dns.RcodeSuccess, nil // the name exists; no record of that type
}

// Server serves the policy, which may be replaced while it runs.
type Server struct {
	policy atomic.Pointer[Policy]
}

// SetPolicy replaces the policy (hot allowlist extension).
func (s *Server) SetPolicy(p *Policy) { s.policy.Store(p) }

// ServeDNS answers one query. Only single-question IN queries get an answer; anything else is
// refused or reported as unsupported, and nothing is forwarded.
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative, m.RecursionAvailable = true, false
	p := s.policy.Load()
	switch {
	case req.Opcode != dns.OpcodeQuery:
		m.Rcode = dns.RcodeNotImplemented
	case len(req.Question) != 1:
		m.Rcode = dns.RcodeFormatError
	case p == nil || req.Question[0].Qclass != dns.ClassINET:
		m.Rcode = dns.RcodeRefused // no policy yet: fail closed
	default:
		q := req.Question[0]
		rcode, addrs := p.Answer(q.Name, q.Qtype)
		m.Rcode = rcode
		for _, a := range addrs {
			hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: TTL}
			if a.Is4() {
				hdr.Rrtype = dns.TypeA
				m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.IP(a.AsSlice())})
			} else {
				hdr.Rrtype = dns.TypeAAAA
				m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: net.IP(a.AsSlice())})
			}
		}
	}
	w.WriteMsg(m)
}

// ListenAndServe serves DNS on addr (UDP and TCP) until one of them fails.
func (s *Server) ListenAndServe(addr string) error {
	errs := make(chan error, 2)
	for _, n := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: addr, Net: n, Handler: s}
		go func() { errs <- srv.ListenAndServe() }()
	}
	return <-errs
}
