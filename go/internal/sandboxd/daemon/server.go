package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"time"
)

// MaxRequest bounds one request (a session spec is a few KiB).
const MaxRequest = 1 << 20

// Request is one call on sandboxd's socket. One request per connection.
type Request struct {
	Op     string          `json:"op"` // start, stop, heartbeat, list, attach, broker-key, broker-put, broker-delete, broker-list
	Spec   json.RawMessage `json:"spec,omitempty"`
	ID     string          `json:"id,omitempty"` // a session, or for broker-put and broker-delete a credential reference
	Reason string          `json:"reason,omitempty"`
	Key    []byte          `json:"key,omitempty"`    // broker-key: the store key (from the host keychain)
	Sealed []byte          `json:"sealed,omitempty"` // broker-put: an entry the host sealed
	// attach: the command, whether it gets a terminal, and the first window size (columns, rows);
	// the client's stdin, stdout, and stderr travel with the request (SCM_RIGHTS), and window
	// sizes follow it on the connection as Control messages
	Args []string  `json:"args,omitempty"`
	TTY  bool      `json:"tty,omitempty"`
	Size [2]uint16 `json:"size,omitempty"`
}

// Control is a message from an attached client after its request.
type Control struct {
	Resize *[2]uint16 `json:"resize,omitempty"` // columns, rows
}

// Response answers a Request.
type Response struct {
	OK       bool      `json:"ok"`
	Error    string    `json:"error,omitempty"`
	ID       string    `json:"id,omitempty"`
	Sessions []Summary `json:"sessions,omitempty"`
	Refs     []string  `json:"refs,omitempty"`
	Exit     *int      `json:"exit,omitempty"` // attach: the command's exit status
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
	// the first read takes any descriptors the client sent with its request (attach)
	var in io.Reader = c
	var files []*os.File
	if uc, ok := c.(*net.UnixConn); ok {
		buf, oob := make([]byte, 64<<10), make([]byte, syscall.CmsgSpace(3*4))
		n, oobn, _, _, err := uc.ReadMsgUnix(buf, oob)
		if err != nil {
			reply(Response{Error: "bad request: " + err.Error()})
			return
		}
		files = receivedFiles(oob[:oobn])
		in = io.MultiReader(bytes.NewReader(buf[:n]), c)
	}
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	limit := &io.LimitedReader{R: bufio.NewReader(in), N: MaxRequest}
	dec := json.NewDecoder(limit)
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		reply(Response{Error: "bad request: " + err.Error()})
		return
	}
	c.SetReadDeadline(time.Time{})
	if req.Op == "attach" {
		limit.N = 1 << 62 // the window sizes go on for as long as the terminal is attached
		reply(d.serveAttach(ctx, req, files, dec))
		return
	}
	reply(d.call(ctx, req))
}

// receivedFiles are the descriptors in a message's control data.
func receivedFiles(oob []byte) []*os.File {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil
	}
	var out []*os.File
	for _, m := range msgs {
		fds, err := syscall.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			out = append(out, os.NewFile(uintptr(fd), "client"))
		}
	}
	return out
}

// serveAttach runs an attach for a connected client: its stdio are the three descriptors it sent.
func (d *Daemon) serveAttach(ctx context.Context, req Request, files []*os.File, dec *json.Decoder) Response {
	if len(files) != 3 {
		return Response{Error: "attach needs the client's stdin, stdout, and stderr"}
	}
	resize, gone := make(chan [2]uint16, 8), make(chan struct{})
	go func() {
		defer close(gone)
		for {
			var m Control
			if dec.Decode(&m) != nil {
				return // the client went away
			}
			if m.Resize != nil {
				select {
				case resize <- *m.Resize:
				default: // a burst of resizes: the latest that fits will do
				}
			}
		}
	}()
	code, err := d.Attach(ctx, req.ID, req.Args, req.TTY, AttachIO{Stdin: files[0], Stdout: files[1], Stderr: files[2]}, req.Size, resize, gone)
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Response{OK: true, ID: req.ID, Exit: &code}
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

// AttachCall attaches stdio to a command in a session's agent microVM and returns its exit
// status. The descriptors travel with the request; each window size from resize is sent on.
func AttachCall(ctx context.Context, socket string, req Request, stdio [3]*os.File, resize <-chan [2]uint16) (int, error) {
	var dl net.Dialer
	c, err := dl.DialContext(ctx, "unix", socket)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("not a unix socket")
	}
	stop := context.AfterFunc(ctx, func() { c.Close() }) // the client is going away: so is the attach
	defer stop()
	b, err := json.Marshal(req)
	if err != nil {
		return 0, err
	}
	fds := []int{int(stdio[0].Fd()), int(stdio[1].Fd()), int(stdio[2].Fd())}
	if _, _, err := uc.WriteMsgUnix(append(b, '\n'), syscall.UnixRights(fds...), nil); err != nil {
		return 0, err
	}
	go func() {
		enc := json.NewEncoder(c)
		for sz := range resize {
			if enc.Encode(Control{Resize: &sz}) != nil {
				return
			}
		}
	}()
	var r Response
	if err := json.NewDecoder(c).Decode(&r); err != nil {
		return 0, err
	}
	if !r.OK {
		return 0, errors.New(r.Error)
	}
	if r.Exit == nil {
		return 0, errors.New("sandboxd gave no exit status")
	}
	return *r.Exit, nil
}
