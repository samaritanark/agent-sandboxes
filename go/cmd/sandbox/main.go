// Command sandbox is the v3 host binary (design 5.1): VM lifecycle, the version handshake, host
// operations, and proxying every other command to the in-VM sandbox. It implements no policy; the
// import-graph test holds its dependency closure to the host-safe packages.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/app"
)

func isTTY(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: cannot find the home directory: %v\n", err)
		os.Exit(1)
	}
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	d, tr, err := wire(home)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	// Ctrl-C reaches the whole foreground process group. ssh forwards it to the VM, so the host
	// process catches and discards it (a caught signal, unlike an ignored one, is reset to the
	// default in the ssh child) and returns the remote exit code when ssh ends.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	go func() {
		for range sigs {
		}
	}()
	os.Exit(app.Run(context.Background(), os.Args[1:], app.Env{
		Driver: d, Transport: tr, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		StdinTTY: isTTY(os.Stdin), StateDir: filepath.Join(home, ".sandbox"), User: name,
	}))
}
