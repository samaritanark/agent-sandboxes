package authz

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
)

func req(sni string) *authv3.CheckRequest {
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{TlsSession: &authv3.AttributeContext_TLSSession{Sni: sni}}}
}

func TestDecide(t *testing.T) {
	s := &Server{}
	if d := s.Decide("api.github.com"); d.Allowed {
		t.Error("allowed with no policy")
	}
	s.SetPolicy(&Policy{Allow: []string{"*.github.com", "api.anthropic.com"}, BlockDomains: []string{"*.gist.github.com", "*pastebin.com"}})
	for sni, want := range map[string]bool{
		"api.github.com": true, "API.ANTHROPIC.COM": true, "": false, "gist.github.com": false,
		"a.b.github.com": false, "github.com": false, "evil.com": false, "10.0.0.1": false,
	} {
		if d := s.Decide(sni); d.Allowed != want {
			t.Errorf("%q: %+v", sni, d)
		}
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
	s.SetPolicy(&Policy{Allow: []string{"api.anthropic.com"}})
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
		r, err := c.Check(context.Background(), req(sni))
		if err != nil || codes.Code(r.GetStatus().GetCode()) != code {
			t.Errorf("%q: %v %v", sni, r, err)
		}
	}
	if len(seen) != 3 {
		t.Errorf("recorded %v", seen)
	}
}
