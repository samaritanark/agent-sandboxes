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
	"runtime"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/app"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/brokerkey"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/netd"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/netdvm"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/proxycert"
	"github.com/samaritanark/agent-sandboxes/go/internal/secretcmd"
	"github.com/samaritanark/agent-sandboxes/go/internal/tty"
)

func main() {
	// netd's processes (design D-31): started by the vfkit and qemu drivers, never by a user.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "__netd":
			os.Exit(netdvm.NetdMain(os.Args[2:]))
		case "__netd-worker":
			os.Exit(netd.WorkerMain(os.Args[2:]))
		}
	}
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
	state := filepath.Join(home, ".sandbox")
	ttyIs := tty.Is
	tty := ttyIs(os.Stdin)
	os.Exit(app.Run(context.Background(), os.Args[1:], app.Env{
		Driver: d, Transport: tr, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		StdinTTY: tty, StateDir: state, User: name,
		Install:   installDeps(home),
		BrokerKey: brokerkey.Default(state), SecretsDir: os.Getenv("SANDBOX_SECRETS_DIR"),
		HostCommands: map[string]func(context.Context, []string) int{
			// the secret store stays on the host (design 5.1.4); run's pre-pass pushes from it
			"secret": func(_ context.Context, args []string) int {
				_, noColor := os.LookupEnv("NO_COLOR")
				dir := os.Getenv("SANDBOX_SECRETS_DIR")
				if dir == "" {
					dir = filepath.Join(state, "secrets")
				}
				return secretcmd.Run(args, secretcmd.Env{Dir: dir, Home: home, Stdin: os.Stdin, StdinTTY: tty,
					StderrTTY: ttyIs(os.Stderr), NoColor: noColor && os.Getenv("NO_COLOR") != "", Getenv: os.Getenv},
					os.Stdout, os.Stderr)
			},
			"setup-proxy-cert": func(ctx context.Context, args []string) int {
				env := proxycert.System(runtime.GOOS)
				env.Stdin, env.Stdout, env.Stderr, env.StdinTTY = os.Stdin, os.Stdout, os.Stderr, tty
				env.DefaultOutput = filepath.Join(state, "extra-ca-certs", "proxy-ca.crt")
				return proxycert.Run(ctx, args, env)
			},
		},
	}))
}
