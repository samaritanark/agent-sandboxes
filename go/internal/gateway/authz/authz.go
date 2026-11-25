// Package authz is the gateway's connection check (design 5.8.4 item 1): Envoy asks it, through
// its network ext_authz filter, before it forwards each connection, and it answers with the
// session's policy using the same matching as the resolver and the policy layer (egressmatch).
// A connection with no SNI is denied; so is everything while no policy is loaded. Envoy is
// configured to fail closed if this service cannot answer.
package authz

import (
	"context"
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
	SNI     string
	Allowed bool
	Reason  string
}

// Server implements Envoy's Authorization service.
type Server struct {
	authv3.UnimplementedAuthorizationServer
	policy atomic.Pointer[Policy]
	// Record, if set, receives every decision (the session's audit log).
	Record func(Decision)
}

// SetPolicy replaces the policy (hot allowlist extension, 5.8.8).
func (s *Server) SetPolicy(p *Policy) { s.policy.Store(p) }

// Decide is the check itself.
func (s *Server) Decide(sni string) Decision {
	p := s.policy.Load()
	switch {
	case p == nil:
		return Decision{SNI: sni, Reason: "no policy loaded"}
	case sni == "":
		return Decision{SNI: sni, Reason: "no SNI"}
	case !egressmatch.Decide(sni, p.Allow, p.BlockDomains):
		return Decision{SNI: sni, Reason: "not allowed"}
	}
	return Decision{SNI: sni, Allowed: true, Reason: "allowed"}
}

// Check answers Envoy.
func (s *Server) Check(_ context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	d := s.Decide(req.GetAttributes().GetTlsSession().GetSni())
	if s.Record != nil {
		s.Record(d)
	}
	if !d.Allowed {
		return &authv3.CheckResponse{Status: &status.Status{Code: int32(codes.PermissionDenied), Message: d.Reason}}, nil
	}
	return &authv3.CheckResponse{Status: &status.Status{Code: int32(codes.OK)}}, nil
}
