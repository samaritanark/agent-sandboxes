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
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	fmt.Fprintln(os.Stderr, "usage: sandboxd serve | sandboxd ctl start SPEC.json | stop ID [REASON] | heartbeat ID | list |\n"+
		"       broker-key KEYFILE | broker-put REF SEALEDFILE | broker-delete REF | broker-list")
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
	case "__seal":
		// development only: seal stdin as REF's entry under the key in KEYFILE (the host binary
		// seals entries itself, so the VM never sees a value to store it)
		if len(args) != 3 {
			return usage()
		}
		k, err1 := os.ReadFile(args[1])
		v, err2 := io.ReadAll(os.Stdin)
		if err := errors.Join(err1, err2); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		b, err := brokerstore.Seal(k, args[2], bytes.TrimRight(v, "\n"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		os.Stdout.Write(b)
		return 0
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
	case args[0] == "broker-key" && len(args) == 2:
		// the store key's 32 raw bytes, from a file (the host binary pushes it from its keychain)
		k, err := os.ReadFile(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		req = daemon.Request{Op: "broker-key", Key: k}
	case args[0] == "broker-put" && len(args) == 3:
		b, err := os.ReadFile(args[2])
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
