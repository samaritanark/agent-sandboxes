//go:build linux || darwin

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/daemon"
	"github.com/samaritanark/agent-sandboxes/go/internal/tty"
)

// ctlAttach is `sandboxd ctl attach ID -- COMMAND...`: run COMMAND in the session's agent
// microVM with this terminal (raw, its size followed) and exit with its status. The policy CLI's
// run and resume attach the same way (daemon.AttachCall).
func ctlAttach(id string, args []string) int {
	term := tty.Is(os.Stdin) && tty.Is(os.Stdout)
	req := daemon.Request{Op: "attach", ID: id, Args: args, TTY: term}
	resize := make(chan [2]uint16, 1)
	if term {
		if c, r, err := tty.Size(os.Stdout); err == nil {
			req.Size = [2]uint16{c, r}
		}
		restore, err := tty.MakeRaw(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sandboxd: %v\n", err)
			return 1
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
	code, err := daemon.AttachCall(ctx, Socket, req, [3]*os.File{os.Stdin, os.Stdout, os.Stderr}, resize)
	select {
	case <-hung:
		return 129 // the host went away; sandboxd hangs up on the command
	default:
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "\r\nsandboxd: %v\r\n", err)
		return 1
	}
	return code
}
