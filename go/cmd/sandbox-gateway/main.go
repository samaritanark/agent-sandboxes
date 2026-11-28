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
	"strconv"
	"sync"
	"syscall"
	"time"

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
	resolvers := make([]*resolver.Server, len(p.Links))
	resolverPolicies := func(p *gwpolicy.Policy) {
		for i, l := range p.Links {
			rp := &resolver.Policy{Allow: l.Allow, BlockDomains: l.BlockDomains, Gateway: l.Listen}
			if i == 0 {
				rp.Dependencies = deps
			}
			resolvers[i].SetPolicy(rp)
		}
	}
	for i, l := range p.Links {
		res := &resolver.Server{}
		resolvers[i] = res
		addr := net.JoinHostPort(l.Listen.String(), "53")
		go func() { failed <- fmt.Errorf("resolver %s: %w", addr, res.ListenAndServe(addr)) }()
	}
	resolverPolicies(p)

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
	authzPolicies := func(p *gwpolicy.Policy) {
		pols := map[netip.Addr]*authz.Policy{}
		for _, l := range p.Links {
			pols[l.Listen] = &authz.Policy{Allow: l.Allow, BlockDomains: l.BlockDomains}
		}
		az.SetPolicies(pols)
	}
	authzPolicies(p)
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

	// Envoy, restarted with a new configuration when the policy is reloaded
	envoyConf := func(p *gwpolicy.Policy) (string, error) {
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
						return "", err
					}
					if err := os.WriteFile(ic.SDS, b, 0o600); err != nil {
						return "", err
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
			return "", err
		}
		confPath := filepath.Join(*dir, "envoy.json")
		return confPath, os.WriteFile(confPath, bs, 0o600)
	}
	startEnvoy := func(confPath string) (*exec.Cmd, chan error, error) {
		e := exec.Command(*envoyBin, envoyconf.Args(confPath)...)
		e.Stdout, e.Stderr = os.Stderr, os.Stderr
		e.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL} // never outlive the gateway
		if err := e.Start(); err != nil {
			return nil, nil, err
		}
		done := make(chan error, 1)
		go func() { done <- e.Wait() }()
		return e, done, nil
	}
	confPath, err := envoyConf(p)
	if err != nil {
		return err
	}
	e, envoyDone, err := startEnvoy(confPath)
	if err != nil {
		return err
	}
	log.Printf("serving %d links, %d dependencies", len(p.Links), len(p.Deps))

	// SIGHUP: reload the policy (sandbox allow). Only the allowlists may change (SameShape): the
	// resolvers and the connection check take them at once, and Envoy, whose filter chains hold
	// them, is restarted, which resets the connections open through it; the brokers and the
	// session stay.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	for {
		select {
		case <-ctx.Done():
			e.Process.Signal(syscall.SIGTERM)
			return nil
		case err := <-failed:
			e.Process.Kill()
			return err
		case err := <-envoyDone:
			return fmt.Errorf("envoy exited: %v", err)
		case <-hup:
			np, err := reload(*policyPath, p)
			if err != nil {
				log.Printf("policy not reloaded: %v", err)
				continue
			}
			resolverPolicies(np)
			authzPolicies(np)
			confPath, err := envoyConf(np)
			if err != nil {
				log.Printf("policy not reloaded: %v", err)
				continue
			}
			e.Process.Signal(syscall.SIGTERM)
			select {
			case <-envoyDone:
			case <-time.After(10 * time.Second):
				e.Process.Kill()
				<-envoyDone
			}
			if e, envoyDone, err = startEnvoy(confPath); err != nil {
				return fmt.Errorf("envoy did not restart: %w", err)
			}
			p = np
			os.WriteFile(filepath.Join(*dir, gwpolicy.ReloadedFile), []byte(strconv.Itoa(p.Generation)+"\n"), 0o600)
			log.Printf("reloaded the policy (generation %d)", p.Generation)
		}
	}
}

// reload reads the policy file again and accepts it only if it changes nothing but what a
// running gateway can take (gwpolicy.Policy.SameShape).
func reload(path string, cur *gwpolicy.Policy) (*gwpolicy.Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	np, err := gwpolicy.Decode(b)
	if err != nil {
		return nil, err
	}
	if err := cur.SameShape(np); err != nil {
		return nil, err
	}
	return np, nil
}
