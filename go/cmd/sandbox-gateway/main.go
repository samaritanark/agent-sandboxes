//go:build linux

// Command sandbox-gateway is one session's egress gateway (design 5.8): the filtering resolver,
// the connection check Envoy asks, and Envoy itself, all in the session's gateway namespace as an
// unprivileged user. sandboxd starts it; it exits when any part fails, so the session is left with
// no egress (fail closed, 5.8.4 item 8), and stops Envoy when it is told to stop.
//
//	sandbox-gateway --policy POLICY.json --dir DIR [--envoy /usr/local/bin/envoy]
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"

	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/authz"
	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/envoyconf"
	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/resolver"
)

// Policy is what sandboxd writes for the gateway (from the session spec).
type Policy struct {
	Listen       netip.Addr   `json:"listen"`
	Ports        []int        `json:"ports"`
	Allow        []string     `json:"allow"`
	BlockDomains []string     `json:"block_domains"`
	Dependencies []string     `json:"dependencies"`
	Resolvers    []netip.Addr `json:"resolvers"`
}

func main() {
	if err := run(); err != nil {
		log.Printf("sandbox-gateway: %v", err)
		os.Exit(1)
	}
}

func run() error {
	policyPath := flag.String("policy", "", "the session's gateway policy")
	dir := flag.String("dir", "", "the gateway's own directory (sockets, configuration, logs)")
	envoyBin := flag.String("envoy", "/usr/local/bin/envoy", "the Envoy binary")
	flag.Parse()
	if *policyPath == "" || *dir == "" {
		return errors.New("usage: sandbox-gateway --policy FILE --dir DIR")
	}
	b, err := os.ReadFile(*policyPath)
	if err != nil {
		return err
	}
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	if !p.Listen.IsValid() || len(p.Ports) == 0 || len(p.Resolvers) == 0 {
		return errors.New("policy: listen address, ports, and resolvers are required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	failed := make(chan error, 4)

	// the filtering resolver on the gateway's address
	res := &resolver.Server{}
	res.SetPolicy(&resolver.Policy{Allow: p.Allow, BlockDomains: p.BlockDomains, Dependencies: p.Dependencies, Gateway: p.Listen})
	go func() {
		failed <- fmt.Errorf("resolver: %w", res.ListenAndServe(net.JoinHostPort(p.Listen.String(), "53")))
	}()

	// the connection check, on a socket only this user can reach
	sock := filepath.Join(*dir, "authz.sock")
	os.Remove(sock)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	os.Chmod(sock, 0o600)
	az := &authz.Server{Record: func(d authz.Decision) {
		if !d.Allowed {
			log.Printf("refused %q: %s", d.SNI, d.Reason)
		}
	}}
	az.SetPolicy(&authz.Policy{Allow: p.Allow, BlockDomains: p.BlockDomains})
	g := grpc.NewServer()
	authv3.RegisterAuthorizationServer(g, az)
	go func() { failed <- fmt.Errorf("authz: %w", g.Serve(ln)) }()
	defer g.Stop()

	// Envoy
	conf := envoyconf.Config{Allow: p.Allow, BlockDomains: p.BlockDomains, Listen: p.Listen, Ports: p.Ports,
		AuthzSocket: sock, AdminSocket: filepath.Join(*dir, "admin.sock"), Resolvers: p.Resolvers,
		AccessLog: filepath.Join(*dir, "connections.log")}
	bs, err := conf.Bootstrap()
	if err != nil {
		return err
	}
	confPath := filepath.Join(*dir, "envoy.json")
	if err := os.WriteFile(confPath, bs, 0o600); err != nil {
		return err
	}
	e := exec.Command(*envoyBin, envoyconf.Args(confPath)...)
	e.Stdout, e.Stderr = os.Stderr, os.Stderr
	e.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL} // never outlive the gateway
	if err := e.Start(); err != nil {
		return err
	}
	go func() { failed <- fmt.Errorf("envoy exited: %v", e.Wait()) }()
	log.Printf("serving on %s (ports %v)", p.Listen, p.Ports)

	select {
	case <-ctx.Done():
		e.Process.Signal(syscall.SIGTERM)
		return nil
	case err := <-failed:
		e.Process.Kill()
		return err
	}
}
