// Package authz is the gateway's connection check (design 5.8.4 item 1): Envoy asks it, through
// its network ext_authz filter, before it forwards each connection, and it answers with the policy
// of the microVM whose link the connection came in on (the gateway address it was made to: the
// agent's or a dependency's, 5.8.6), using the same matching as the resolver and the policy layer
// (egressmatch).
// A connection with no SNI is denied; so is everything while no policy is loaded. Envoy is
// configured to fail closed if this service cannot answer.
package authz

import (
	"context"
	"net/netip"
	"sync/atomic"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/samaritanark/agent-sandboxes/go/internal/egressmatch"
)

// Policy is the session's egress policy as the gateway enforces it.
type Policy struct {
	Allow        []string
	BlockDomains []string
}

// Decision is one check's outcome, for the audit log.
type Decision struct {
	Link    netip.Addr // the gateway address the connection came in on
	SNI     string
	Allowed bool
	Reason  string
}

// Server implements Envoy's Authorization service.
type Server struct {
	authv3.UnimplementedAuthorizationServer
	policies atomic.Pointer[map[netip.Addr]*Policy]
	// Record, if set, receives every decision (the session's audit log).
	Record func(Decision)
}

// SetPolicies replaces every link's policy, keyed by the gateway address of the link (hot
// allowlist extension, 5.8.8).
func (s *Server) SetPolicies(p map[netip.Addr]*Policy) { s.policies.Store(&p) }

// Decide is the check itself, for a connection to the gateway address link.
func (s *Server) Decide(link netip.Addr, sni string) Decision {
	d := Decision{Link: link, SNI: sni}
	var p *Policy
	if m := s.policies.Load(); m != nil {
		p = (*m)[link]
	}
	switch {
	case p == nil:
		d.Reason = "no policy for this link"
	case sni == "":
		d.Reason = "no SNI"
	case !egressmatch.Decide(sni, p.Allow, p.BlockDomains):
		d.Reason = "not allowed"
	default:
		d.Allowed, d.Reason = true, "allowed"
	}
	return d
}

// Check answers Envoy.
func (s *Server) Check(_ context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	link, _ := netip.ParseAddr(req.GetAttributes().GetDestination().GetAddress().GetSocketAddress().GetAddress())
	d := s.Decide(link.Unmap(), req.GetAttributes().GetTlsSession().GetSni())
	if s.Record != nil {
		s.Record(d)
	}
	if !d.Allowed {
		return &authv3.CheckResponse{Status: &status.Status{Code: int32(codes.PermissionDenied), Message: d.Reason}}, nil
	}
	return &authv3.CheckResponse{Status: &status.Status{Code: int32(codes.OK)}}, nil
}
