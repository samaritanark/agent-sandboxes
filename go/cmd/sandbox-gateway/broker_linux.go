//go:build linux

package main

// The session's credential brokers: one ext_proc service per link that has bindings, and the
// handover socket through which sandboxd's short-lived helper delivers the values (design 5.9.2).
// The values never pass through a command line, the environment, or a file; only root may hand
// them over; until it has, every request to a bound destination is refused (the broker answers
// "not ready" and Envoy fails closed).

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"syscall"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"

	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/broker"
	"github.com/samaritanark/agent-sandboxes/go/internal/gateway/gwpolicy"
)

// startBrokers serves a broker for each link with bindings and returns their sockets (by link)
// and a stop function.
func startBrokers(dir string, p *gwpolicy.Policy, record func(broker.Event), failed chan<- error) ([]string, func(), error) {
	sockets := make([]string, len(p.Links))
	servers := make([]*broker.Server, len(p.Links))
	var stops []func()
	stop := func() {
		for _, f := range stops {
			f()
		}
	}
	any := false
	for i, l := range p.Links {
		if len(l.Bindings) == 0 {
			continue
		}
		any = true
		sock := filepath.Join(dir, fmt.Sprintf("broker-%d.sock", i))
		os.Remove(sock)
		ln, err := net.Listen("unix", sock)
		if err != nil {
			stop()
			return nil, nil, err
		}
		os.Chmod(sock, 0o600)
		servers[i] = &broker.Server{Record: record}
		g := grpc.NewServer()
		extprocv3.RegisterExternalProcessorServer(g, servers[i])
		go func() { failed <- fmt.Errorf("broker %d: %w", i, g.Serve(ln)) }()
		stops = append(stops, g.Stop)
		sockets[i] = sock
	}
	if !any {
		return sockets, stop, nil
	}
	hsock := filepath.Join(dir, gwpolicy.HandoverSocket)
	os.Remove(hsock)
	ln, err := net.Listen("unix", hsock)
	if err != nil {
		stop()
		return nil, nil, err
	}
	os.Chmod(hsock, 0o600) // the gateway's own; root passes the mode
	stops = append(stops, func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			err = receive(c, p, servers)
			if err != nil {
				log.Printf("handover refused: %v", err)
				fmt.Fprintf(c, "error: %v\n", err)
			} else {
				log.Printf("credentials handed over")
				io.WriteString(c, "ok\n")
			}
			c.Close()
		}
	}()
	return sockets, stop, nil
}

// receive reads one handover from root and gives each link's broker its bindings with values.
func receive(c net.Conn, p *gwpolicy.Policy, servers []*broker.Server) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *syscall.Ucred
	var cerr error
	raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if cerr != nil || cred == nil || cred.Uid != 0 {
		return errors.New("only root may hand credentials over")
	}
	var h gwpolicy.Handover
	dec := json.NewDecoder(io.LimitReader(bufio.NewReader(c), 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return fmt.Errorf("unreadable handover: %w", err)
	}
	defer func() {
		for _, m := range h.Links {
			for _, v := range m {
				for i := range v {
					v[i] = 0
				}
			}
		}
	}()
	if len(h.Links) != len(p.Links) {
		return errors.New("the handover does not match the policy's links")
	}
	sets := make([]*broker.Set, len(p.Links))
	for i, l := range p.Links {
		if servers[i] == nil {
			if len(h.Links[i]) > 0 {
				return fmt.Errorf("link %d has no bindings but was handed values", i)
			}
			continue
		}
		var bs []broker.Binding
		for _, b := range l.Bindings {
			v, ok := h.Links[i][b.Ref]
			if !ok || len(v) == 0 {
				return fmt.Errorf("link %d: no value for %s", i, b.Ref)
			}
			bs = append(bs, broker.Binding{Ref: b.Ref, Hosts: b.Hosts, Inject: b.Inject, Placeholder: b.Placeholder, Prefix: b.Prefix, Value: string(v),
				RatePerMinute: b.RatePerMinute, Burst: b.Burst, Quota: b.Quota})
		}
		if len(h.Links[i]) != len(l.Bindings) {
			return fmt.Errorf("link %d: values for references it does not bind", i)
		}
		set, err := broker.NewSet(bs)
		if err != nil {
			return err
		}
		sets[i] = set
	}
	for i, s := range sets {
		if s != nil {
			servers[i].SetBindings(s)
		}
	}
	return nil
}
