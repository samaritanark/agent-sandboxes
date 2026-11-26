// Command sandboxd is the appliance VM's session supervisor (design 5.4.3): a root systemd
// service that runs each session's Kata microVMs through containerd, journals everything it
// owns, and tears sessions down on every end. It is never reachable from a microVM.
//
//	sandboxd serve                  run the service (systemd)
//	sandboxd ctl start SPEC.json    start a session from a session spec
//	sandboxd ctl stop ID [REASON]   stop a session
//	sandboxd ctl heartbeat ID       renew a session's attach lease
//	sandboxd ctl list               list sessions
//	sandboxd ctl attach ID -- CMD...  run CMD in the session's agent microVM with this terminal
//	sandboxd ctl broker-key         take the broker store key on stdin (the host pushes it)
//	sandboxd ctl broker-put REF     store REF's entry, sealed by the host, from stdin
//	sandboxd ctl broker-delete REF  remove REF's entry
//	sandboxd ctl broker-list        list the stored references
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/brokerstore"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/daemon"
)

// Socket is sandboxd's API socket.
const Socket = "/run/sandboxd.sock"

func usage() int {
	fmt.Fprintln(os.Stderr, "usage: sandboxd serve | sandboxd ctl start SPEC.json | stop ID [REASON] | heartbeat ID | list | attach ID -- CMD... |\n"+
		"       broker-key < KEY | broker-put REF < SEALED | broker-delete REF | broker-list")
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
	case "__broker-handover":
		return brokerHandover()
	}
	return usage()
}

func ctl(args []string) int {
	if len(args) == 0 {
		return usage()
	}
	if args[0] == "attach" {
		if len(args) < 4 || args[2] != "--" {
			return usage()
		}
		return ctlAttach(args[1], args[3:])
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
	case args[0] == "broker-key" && len(args) == 1:
		// the store key's 32 raw bytes on stdin: never in an argument list or a file
		k, err := io.ReadAll(io.LimitReader(os.Stdin, 64))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer brokerstore.Wipe(k)
		req = daemon.Request{Op: "broker-key", Key: k}
	case args[0] == "broker-put" && len(args) == 2:
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		req = daemon.Request{Op: "broker-put", ID: args[1], Sealed: b}
	case args[0] == "broker-delete" && len(args) == 2:
		req = daemon.Request{Op: "broker-delete", ID: args[1]}
	case args[0] == "broker-list" && len(args) == 1:
		req = daemon.Request{Op: "broker-list"}
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
	if req.Op == "broker-list" {
		for _, r := range resp.Refs {
			fmt.Println(r)
		}
		return 0
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
