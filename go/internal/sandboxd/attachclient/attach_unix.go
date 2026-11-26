//go:build linux || darwin

// Package attachclient is the client half of attaching a terminal to a session (design 5.4.3):
// `sandboxd ctl attach` and the policy CLI's run and resume use it to hand sandboxd this process's
// stdio and follow its window size.
package attachclient

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/daemon"
	"github.com/samaritanark/agent-sandboxes/go/internal/tty"
)

// HungUp is the status Attach returns when the client's own connection went away (its stdout has
// no reader): sandboxd hangs up on the command.
const HungUp = 129

// Attach runs args in session id's agent microVM with this process's terminal (raw, its size
// followed) through sandboxd's socket, and returns the command's exit status.
func Attach(socket, id string, args []string) (int, error) {
	term := tty.Is(os.Stdin) && tty.Is(os.Stdout)
	req := daemon.Request{Op: "attach", ID: id, Args: args, TTY: term}
	resize := make(chan [2]uint16, 1)
	if term {
		if c, r, err := tty.Size(os.Stdout); err == nil {
			req.Size = [2]uint16{c, r}
		}
		restore, err := tty.MakeRaw(os.Stdin)
		if err != nil {
			return 1, err
		}
		defer restore()
		winch := make(chan os.Signal, 1)
		signal.Notify(winch, syscall.SIGWINCH)
		defer signal.Stop(winch)
		go func() {
			for range winch {
				if c, r, err := tty.Size(os.Stdout); err == nil {
					select {
					case resize <- [2]uint16{c, r}:
					default:
					}
				}
			}
		}()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hung := make(chan struct{})
	go func() { waitHangup(os.Stdout); close(hung); cancel() }()
	code, err := daemon.AttachCall(ctx, socket, req, [3]*os.File{os.Stdin, os.Stdout, os.Stderr}, resize)
	select {
	case <-hung:
		return HungUp, nil
	default:
	}
	if err != nil {
		return 1, err
	}
	return code, nil
}
