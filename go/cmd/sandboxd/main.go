// Command sandboxd is the appliance VM's session supervisor (design 5.4.3): a root systemd
// service that runs each session's Kata microVMs through containerd, journals everything it
// owns, and tears sessions down on every end. It is never reachable from a microVM.
//
//	sandboxd serve                  run the service (systemd)
//	sandboxd ctl start SPEC.json    start a session from a session spec
//	sandboxd ctl stop ID [REASON]   stop a session
//	sandboxd ctl heartbeat ID       renew a session's attach lease
//	sandboxd ctl list               list sessions
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/daemon"
)

// Socket is sandboxd's API socket.
const Socket = "/run/sandboxd.sock"

func usage() int {
	fmt.Fprintln(os.Stderr, "usage: sandboxd serve | sandboxd ctl start SPEC.json | stop ID [REASON] | heartbeat ID | list")
	return 2
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "serve":
		if err := serve(); err != nil {
			fmt.Fprintf(os.Stderr, "sandboxd: %v\n", err)
			return 1
		}
		return 0
	case "ctl":
		return ctl(args[1:])
	}
	return usage()
}

func ctl(args []string) int {
	if len(args) == 0 {
		return usage()
	}
	var req daemon.Request
	switch {
	case args[0] == "start" && len(args) == 2:
		b, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		req = daemon.Request{Op: "start", Spec: b}
	case args[0] == "stop" && (len(args) == 2 || len(args) == 3):
		req = daemon.Request{Op: "stop", ID: args[1]}
		if len(args) == 3 {
			req.Reason = args[2]
		}
	case args[0] == "heartbeat" && len(args) == 2:
		req = daemon.Request{Op: "heartbeat", ID: args[1]}
	case args[0] == "list" && len(args) == 1:
		req = daemon.Request{Op: "list"}
	default:
		return usage()
	}
	resp, err := daemon.Call(context.Background(), Socket, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandboxd: %v\n", err)
		return 1
	}
	if !resp.OK {
		fmt.Fprintf(os.Stderr, "sandboxd: %s\n", strings.TrimSpace(resp.Error))
		return 1
	}
	if req.Op == "list" {
		for _, s := range resp.Sessions {
			fmt.Printf("%s\t%s\t%s\t%s\n", s.ID, s.Name, s.State, s.EndReason)
		}
		return 0
	}
	out, _ := json.Marshal(resp)
	fmt.Println(string(out))
	return 0
}
