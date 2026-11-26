//go:build linux

// Command sandbox-gateway is one session's egress gateway (design 5.8): the filtering resolver,
// the connection check Envoy asks, and Envoy itself, all in the session's gateway namespace as an
// unprivileged user. sandboxd starts it; it exits when any part fails, so the session is left with
// no egress (fail closed, 5.8.4 item 8), and stops Envoy when it is told to stop.
//
//	sandbox-gateway --policy POLICY.json --dir DIR [--envoy /usr/local/bin/envoy]
package main

import (
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
	"sync"
	"syscall"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"

	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/authz"
	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/broker"
	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/envoyconf"
	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/gwpolicy"
	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/resolver"
)

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
	p, err := gwpolicy.Decode(b)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	failed := make(chan error, 4)

	// a filtering resolver on each link's gateway address, with that microVM's own policy: only the
	// agent resolves dependency names
	var deps []string
	for _, d := range p.Deps {
		deps = append(deps, d.Name)
	}
	for i, l := range p.Links {
		res := &resolver.Server{}
		rp := &resolver.Policy{Allow: l.Allow, BlockDomains: l.BlockDomains, Gateway: l.Listen}
		if i == 0 {
			rp.Dependencies = deps
		}
		res.SetPolicy(rp)
		addr := net.JoinHostPort(l.Listen.String(), "53")
		go func() { failed <- fmt.Errorf("resolver %s: %w", addr, res.ListenAndServe(addr)) }()
	}

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
			log.Printf("refused %q on %s: %s", d.SNI, d.Link, d.Reason)
		}
	}}
	pols := map[netip.Addr]*authz.Policy{}
	for _, l := range p.Links {
		pols[l.Listen] = &authz.Policy{Allow: l.Allow, BlockDomains: l.BlockDomains}
	}
	az.SetPolicies(pols)
	g := grpc.NewServer()
	authv3.RegisterAuthorizationServer(g, az)
	go func() { failed <- fmt.Errorf("authz: %w", g.Serve(ln)) }()
	defer g.Stop()

	// the credential brokers, one per link with bindings; their events go to broker.log, which
	// sandboxd collects into the session's audit log
	blog, err := os.OpenFile(filepath.Join(*dir, "broker.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer blog.Close()
	var bmu sync.Mutex
	record := func(e broker.Event) {
		b, _ := json.Marshal(map[string]string{"type": e.Type, "ref": e.Ref, "host": e.Host, "method": e.Method, "path": e.Path, "reason": e.Reason})
		bmu.Lock()
		blog.Write(append(b, '\n'))
		bmu.Unlock()
	}
	brokerSockets, stopBrokers, err := startBrokers(*dir, p, record, failed)
	if err != nil {
		return err
	}
	defer stopBrokers()

	// Envoy
	conf := envoyconf.Config{AuthzSocket: sock, AdminSocket: filepath.Join(*dir, "admin.sock"), Resolvers: p.Resolvers,
		AccessLog: filepath.Join(*dir, "connections.log"), UpstreamCAs: p.UpstreamCAs}
	for _, l := range p.Links {
		el := envoyconf.Link{Addr: l.Listen, Ports: l.Ports, Allow: l.Allow, BlockDomains: l.BlockDomains, BrokerSocket: brokerSockets[len(conf.Links)]}
		for _, ic := range l.Intercept {
			ei := envoyconf.Intercept{Name: ic.Name, CertChain: ic.CertChain, PrivateKey: ic.PrivateKey, SDS: ic.SDS, Rules: l.L7}
			if ic.SDS != "" {
				// the leaf is read through this file, so sandboxd can renew it in place
				b, err := envoyconf.SDSSecret(ei)
				if err != nil {
					return err
				}
				if err := os.WriteFile(ic.SDS, b, 0o600); err != nil {
					return err
				}
			}
			el.Intercept = append(el.Intercept, ei)
		}
		conf.Links = append(conf.Links, el)
	}
	for _, d := range p.Deps {
		conf.Deps = append(conf.Deps, envoyconf.Dep{Name: d.Name, Port: d.Port, Addr: d.Addr})
	}
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
	log.Printf("serving %d links, %d dependencies", len(p.Links), len(p.Deps))

	select {
	case <-ctx.Done():
		e.Process.Signal(syscall.SIGTERM)
		return nil
	case err := <-failed:
		e.Process.Kill()
		return err
	}
}
