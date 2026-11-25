package authz

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
)

var agentGW, depGW = netip.MustParseAddr("10.200.0.1"), netip.MustParseAddr("10.200.1.1")

func req(link netip.Addr, sni string) *authv3.CheckRequest {
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{
		TlsSession:  &authv3.AttributeContext_TLSSession{Sni: sni},
		Destination: &authv3.AttributeContext_Peer{Address: &corev3.Address{Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{Address: link.String()}}}},
	}}
}

func TestDecide(t *testing.T) {
	s := &Server{}
	if d := s.Decide(agentGW, "api.github.com"); d.Allowed {
		t.Error("allowed with no policy")
	}
	s.SetPolicies(map[netip.Addr]*Policy{
		agentGW: {Allow: []string{"*.github.com", "api.anthropic.com"}, BlockDomains: []string{"*.gist.github.com", "*pastebin.com"}},
		depGW:   {Allow: []string{"registry.npmjs.org"}},
	})
	for sni, want := range map[string]bool{
		"api.github.com": true, "API.ANTHROPIC.COM": true, "": false, "gist.github.com": false,
		"a.b.github.com": false, "github.com": false, "evil.com": false, "10.0.0.1": false, "registry.npmjs.org": false,
	} {
		if d := s.Decide(agentGW, sni); d.Allowed != want {
			t.Errorf("agent %q: %+v", sni, d)
		}
	}
	// a dependency has its own allowlist, not the agent's
	if !s.Decide(depGW, "registry.npmjs.org").Allowed || s.Decide(depGW, "api.github.com").Allowed {
		t.Error("the dependency's policy")
	}
	if s.Decide(netip.MustParseAddr("10.200.9.1"), "api.github.com").Allowed {
		t.Error("an unknown link was allowed")
	}
}

// TestGRPC is the service as Envoy reaches it: gRPC over a Unix socket.
func TestGRPC(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "authz.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var seen []Decision
	s := &Server{Record: func(d Decision) { seen = append(seen, d) }}
	s.SetPolicies(map[netip.Addr]*Policy{agentGW: {Allow: []string{"api.anthropic.com"}}})
	g := grpc.NewServer()
	authv3.RegisterAuthorizationServer(g, s)
	go g.Serve(ln)
	defer g.Stop()
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := authv3.NewAuthorizationClient(conn)
	for sni, code := range map[string]codes.Code{"api.anthropic.com": codes.OK, "evil.com": codes.PermissionDenied, "": codes.PermissionDenied} {
		r, err := c.Check(context.Background(), req(agentGW, sni))
		if err != nil || codes.Code(r.GetStatus().GetCode()) != code {
			t.Errorf("%q: %v %v", sni, r, err)
		}
	}
	if len(seen) != 3 {
		t.Errorf("recorded %v", seen)
	}
}
