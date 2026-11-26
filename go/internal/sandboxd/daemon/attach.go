package daemon

// Attaching a terminal (design 5.4.3 items 1 and 4). As in v2, where `kubectl exec -it` ran the
// agent in a pod whose own process slept, an attach runs a command in the session's agent
// microVM as the microVM's process runs (its user, environment, and confinement), with the
// client's terminal as its stdio. The client hands sandboxd its stdin, stdout, and stderr over
// the socket (SCM_RIGHTS) with the request, then sends window sizes on the same connection;
// sandboxd answers with the exit status. While a terminal is attached it holds the session's
// lease; when the client goes away (its SSH connection dropped, so the policy CLI died), the
// command gets SIGHUP, then SIGKILL, and the lease grace starts.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"syscall"
	"time"
)

// AttachIO is the client's terminal.
type AttachIO struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

// HangupGrace is how long a detached command has between SIGHUP and SIGKILL.
const HangupGrace = 5 * time.Second

// Attach runs args in session id's agent microVM with tty and stdio, until it exits; size is the
// first window size (columns, rows; zeros for none), resize carries later ones, and gone closes
// when the client goes away. It returns the command's exit status.
func (d *Daemon) Attach(ctx context.Context, id string, args []string, tty bool, stdio AttachIO, size [2]uint16, resize <-chan [2]uint16, gone <-chan struct{}) (int, error) {
	if len(args) == 0 {
		return 0, errors.New("attach needs a command")
	}
	d.mu.Lock()
	t, ok := d.live[id]
	if !ok {
		d.mu.Unlock()
		return 0, fmt.Errorf("no running session %s", id)
	}
	if d.attached == nil {
		d.attached = map[string]int{}
	}
	d.attached[id]++
	d.attachSeq++
	execID := fmt.Sprintf("attach-%d", d.attachSeq)
	t.Attached = true
	d.mu.Unlock()
	d.audit(id, "events.jsonl", "attached", map[string]any{"command": args[0], "tty": tty})
	code := -1
	defer func() {
		d.mu.Lock()
		d.attached[id]--
		if d.attached[id] == 0 {
			now := d.now()
			t.Attached, t.LastDetached, t.LastHeartbeat = false, now, now
		}
		d.mu.Unlock()
		d.audit(id, "events.jsonl", "detached", map[string]any{"exit": code})
	}()

	d.mu.Lock()
	readable := d.readable[id]
	d.mu.Unlock()
	run := args
	if len(readable) > 0 {
		run = readableWrap(readable, args)
	}
	p, err := d.Runtime.Exec(ctx, id, execID, run, tty, stdio.Stdin, stdio.Stdout, stdio.Stderr)
	if err != nil && len(readable) > 0 && noShell(err) {
		// an image without a shell: the readable secrets are files only (<VAR>_FILE)
		d.audit(id, "events.jsonl", "secret_readable_file_only", map[string]any{"env_vars": readable})
		p, err = d.Runtime.Exec(ctx, id, execID+"-noshell", args, tty, stdio.Stdin, stdio.Stdout, stdio.Stderr)
	}
	if err != nil {
		d.logf("session %s: attach: %v", id, err)
		return 0, errors.New("attach: " + firstLine(err)) // Kata appends a stack backtrace

	}
	if size[0] > 0 && size[1] > 0 {
		p.Resize(ctx, uint32(size[0]), uint32(size[1]))
	}
	type result struct {
		code int
		err  error
	}
	done := make(chan result, 1)
	go func() {
		c, err := p.Wait(context.WithoutCancel(ctx))
		done <- result{c, err}
	}()
	var kill <-chan time.Time
	for {
		select {
		case sz, ok := <-resize:
			if !ok {
				resize = nil
				continue
			}
			p.Resize(ctx, uint32(sz[0]), uint32(sz[1]))
		case <-gone:
			gone = nil
			p.Kill(ctx, syscall.SIGHUP)
			kill = time.After(HangupGrace)
		case <-kill:
			p.Kill(ctx, syscall.SIGKILL)
		case r := <-done:
			code = r.code
			return r.code, r.err
		}
	}
}
