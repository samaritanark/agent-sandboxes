package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

// MaxRequest bounds one request (a session spec is a few KiB).
const MaxRequest = 1 << 20

// Request is one call on sandboxd's socket. One request per connection.
type Request struct {
	Op     string          `json:"op"` // start, stop, heartbeat, list, broker-key, broker-put, broker-delete, broker-list
	Spec   json.RawMessage `json:"spec,omitempty"`
	ID     string          `json:"id,omitempty"` // a session, or for broker-put and broker-delete a credential reference
	Reason string          `json:"reason,omitempty"`
	Key    []byte          `json:"key,omitempty"`    // broker-key: the store key (from the host keychain)
	Sealed []byte          `json:"sealed,omitempty"` // broker-put: an entry the host sealed
}

// Response answers a Request.
type Response struct {
	OK       bool      `json:"ok"`
	Error    string    `json:"error,omitempty"`
	ID       string    `json:"id,omitempty"`
	Sessions []Summary `json:"sessions,omitempty"`
	Refs     []string  `json:"refs,omitempty"`
}

// Authorize decides whether a connection's peer may use sandboxd (SO_PEERCRED on Linux).
type Authorize func(net.Conn) error

// Serve answers requests on ln until ctx ends. Every connection is authorized first.
func (d *Daemon) Serve(ctx context.Context, ln net.Listener, auth Authorize) error {
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go d.handle(ctx, c, auth)
	}
}

func (d *Daemon) handle(ctx context.Context, c net.Conn, auth Authorize) {
	defer c.Close()
	reply := func(r Response) { json.NewEncoder(c).Encode(r) }
	if auth != nil {
		if err := auth(c); err != nil {
			d.logf("refused a connection: %v", err)
			reply(Response{Error: "not allowed: " + err.Error()})
			return
		}
	}
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	dec := json.NewDecoder(io.LimitReader(bufio.NewReader(c), MaxRequest))
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		reply(Response{Error: "bad request: " + err.Error()})
		return
	}
	c.SetReadDeadline(time.Time{})
	reply(d.call(ctx, req))
}

func (d *Daemon) call(ctx context.Context, req Request) Response {
	fail := func(err error) Response { return Response{Error: err.Error()} }
	switch req.Op {
	case "start":
		id, err := d.Start(ctx, req.Spec)
		if err != nil {
			return fail(err)
		}
		return Response{OK: true, ID: id}
	case "stop":
		reason := req.Reason
		if reason == "" {
			reason = "operator stop"
		}
		if err := d.Stop(ctx, req.ID, reason); err != nil {
			return fail(err)
		}
		return Response{OK: true, ID: req.ID}
	case "heartbeat":
		if err := d.Heartbeat(req.ID); err != nil {
			return fail(err)
		}
		return Response{OK: true, ID: req.ID}
	case "list":
		l, err := d.List()
		if err != nil {
			return fail(err)
		}
		return Response{OK: true, Sessions: l}
	case "broker-key", "broker-put", "broker-delete", "broker-list":
		if d.Broker == nil {
			return fail(errors.New("sandboxd has no broker store"))
		}
		var err error
		var refs []string
		switch req.Op {
		case "broker-key":
			err = d.Broker.SetKey(req.Key)
			for i := range req.Key {
				req.Key[i] = 0
			}
		case "broker-put":
			err = d.Broker.Put(req.ID, req.Sealed)
		case "broker-delete":
			err = d.Broker.Delete(req.ID)
		case "broker-list":
			refs, err = d.Broker.List()
		}
		if err != nil {
			return fail(err)
		}
		return Response{OK: true, ID: req.ID, Refs: refs}
	}
	return fail(errors.New("unknown op " + req.Op))
}

// Call sends one request to sandboxd's socket and returns its response.
func Call(ctx context.Context, socket string, req Request) (Response, error) {
	var dl net.Dialer
	c, err := dl.DialContext(ctx, "unix", socket)
	if err != nil {
		return Response{}, err
	}
	defer c.Close()
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return Response{}, err
	}
	var r Response
	if err := json.NewDecoder(io.LimitReader(c, MaxRequest)).Decode(&r); err != nil {
		return Response{}, err
	}
	return r, nil
}
