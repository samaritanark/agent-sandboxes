// Package app is the host binary's command dispatcher (design 5.1.6). Host-only commands run
// here; every other command, known or not, is proxied to the in-VM sandbox after the version
// handshake (5.1.7), so the in-VM CLI answers it exactly as v2 did. The host implements no
// policy (5.1.1): it never interprets a proxied command's arguments beyond what 5.1.1 item 3
// allows (translating host paths), and the import-graph test holds it to the host-safe packages.
package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/auditpull"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/brokerkey"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/release"
	"github.com/samaritanark/agent-sandboxes/go/internal/opstate"
)

// Transport runs commands in the VM over the driver's SSH endpoint.
type Transport interface {
	// Run runs argv (a login shell when argv is empty) with stdio attached and returns its exit
	// code; tty asks for a pseudo-terminal, with signals and window-size changes forwarded.
	Run(ctx context.Context, ep driver.SSHEndpoint, argv []string, stdin io.Reader, stdout, stderr io.Writer, tty bool) (int, error)
	// Output runs argv without a terminal and returns its stdout, at most max bytes.
	Output(ctx context.Context, ep driver.SSHEndpoint, argv []string, max int) ([]byte, error)
}

// Env is everything the dispatcher touches.
type Env struct {
	// Kubectl runs the host's kubectl with args and returns its output and error text (tests; nil
	// runs kubectl).
	Kubectl func(args []string) ([]byte, string, error)
	// HostAddrs and LookupHost are this machine's addresses and resolver (tests; nil: the real ones).
	HostAddrs  func() ([]netip.Prefix, error)
	LookupHost func(string) ([]netip.Addr, error)
	Driver     driver.Driver
	Transport  Transport
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	StdinTTY   bool
	StateDir   string // ~/.sandbox
	User       string
	Now        func() time.Time
	// HostCommands are the host operations of 5.1.3 that run without the VM, by name; each gets
	// the arguments after its name and returns the exit code.
	HostCommands map[string]func(ctx context.Context, args []string) int
	// Install is what install and uninstall need beyond the rest of Env.
	Install InstallDeps
	// BrokerKey keeps the credential broker's store key (D-32); nil leaves the broker without one.
	BrokerKey brokerkey.Keeper
	// SecretsDir is the host-side secret store (SANDBOX_SECRETS_DIR; "" is StateDir/secrets).
	SecretsDir string
	// Home is the operator's home directory, which the VM mirrors (proxied commands run with it as
	// HOME, so "~" and host paths mean what they mean on the host); "" keeps the VM's own.
	Home string
	// Getenv is the host's environment, for what proxied commands take from it (opencode's key and
	// endpoint); nil reads nothing.
	Getenv func(string) string
	// Migration is what the v2 migration reads of the machine (zero: the real one).
	Migration MigrationDeps
	// CodexLogin runs Codex's device login and returns its auth.json (onboard); nil runs codex.
	CodexLogin func() ([]byte, error)
	// FetchModels asks an OpenAI-compatible endpoint for its models (opencode); nil uses HTTP.
	FetchModels func(ctx context.Context, base, key string) ([]byte, error)
}

// ReleasePath is the image's release file (5.1.7).
const ReleasePath = "/etc/sandbox/release"

// VMCommand is the in-VM CLI every proxied command runs.
const VMCommand = "sandbox"

type exitCode int

// removed are the v2 host commands design section 6 removes; each fails naming its replacement.
var removed = map[string]string{
	"configure-network": "the VM follows host networking",
}

// notYet are host-only commands this build does not implement yet.
var notYet = map[string]bool{
	"upgrade": true, "ca": true,
}

// Run executes one command line and returns the exit code.
func Run(ctx context.Context, args []string, env Env) (rc int) {
	if env.Now == nil {
		env.Now = time.Now
	}
	defer func() {
		if r := recover(); r != nil {
			c, ok := r.(exitCode)
			if !ok {
				panic(r)
			}
			rc = int(c)
		}
	}()
	a := &app{env: env, ctx: ctx}
	if len(args) > 0 {
		if why, ok := removed[args[0]]; ok {
			a.die("'sandbox %s' was removed in v3: %s.", args[0], why)
		}
		if notYet[args[0]] {
			a.die("'sandbox %s' is not available in this build of the v3 host binary yet.", args[0])
		}
		switch args[0] {
		case "vm":
			return a.vm(args[1:])
		case "install", "setup": // setup remains an alias (5.1.6)
			return a.install(args[1:])
		case "uninstall":
			return a.uninstall(args[1:])
		case "sync":
			return a.sync(args[1:])
		case "doctor":
			return a.doctor(args[1:])
		case BrokerPut:
			return a.brokerPut(args[1:])
		case "onboard":
			return a.onboard(args[1:])
		case "migrate":
			return a.migrate(args[1:])
		case "flows":
			return a.flows(args[1:])
		case "status":
			return a.vm([]string{"status"})
		}
		if f, ok := env.HostCommands[args[0]]; ok {
			return f(ctx, args[1:])
		}
	}
	return a.proxy(args)
}

type app struct {
	env Env
	ctx context.Context
}

func (a *app) die(f string, v ...interface{}) {
	fmt.Fprintf(a.env.Stderr, "ERROR: %s\n", fmt.Sprintf(f, v...))
	panic(exitCode(1))
}

// running returns the endpoint of a running VM, or dies saying how to get one.
func (a *app) running() driver.SSHEndpoint {
	st, err := a.env.Driver.Status(a.ctx)
	if err != nil {
		a.die("cannot read the sandbox VM's state: %v", err)
	}
	switch st {
	case driver.NotCreated:
		a.die("the sandbox VM has not been created. Run: sandbox install")
	case driver.Stopped:
		a.die("the sandbox VM is stopped. Start it with: sandbox vm start")
	case driver.Broken:
		a.die("the sandbox VM is in a broken state. See: sandbox vm status")
	}
	if no, ok := a.env.Driver.(driver.NetworkOwner); ok {
		if rep := no.Network(a.ctx); !rep.Running {
			a.die("%s", rep.Detail)
		}
	}
	ep, err := a.env.Driver.Endpoint(a.ctx)
	if err != nil {
		a.die("cannot reach the sandbox VM: %v", err)
	}
	return ep
}

// checkRelease reads the image's release file and checks its control API (5.1.7).
func (a *app) checkRelease(ep driver.SSHEndpoint) (release.Info, error) {
	b, err := a.env.Transport.Output(a.ctx, ep, []string{"cat", ReleasePath}, release.MaxSize+1)
	if err != nil {
		return release.Info{}, fmt.Errorf("cannot read %s in the sandbox VM: %w", ReleasePath, err)
	}
	info, err := release.Parse(b)
	if err != nil {
		return release.Info{}, fmt.Errorf("the sandbox VM's %s is invalid: %w", ReleasePath, err)
	}
	return info, release.Check(info)
}

// handshake is checkRelease, dying on failure.
func (a *app) handshake(ep driver.SSHEndpoint) release.Info {
	info, err := a.checkRelease(ep)
	if err != nil {
		a.die("%v", err)
	}
	return info
}

// pushState sends the operator state (design 5.1.4) before a proxied command, and returns it.
func (a *app) pushState(ep driver.SSHEndpoint) []byte {
	archive, warnings, err := opstate.BuildWith(a.env.StateDir, a.localOverlay())
	if err != nil {
		a.die("cannot collect the operator state in ~/.sandbox: %v", err)
	}
	for _, w := range warnings {
		fmt.Fprintf(a.env.Stderr, "WARNING: %s\n", w)
	}
	var errb strings.Builder
	argv := []string{VMCommand, ReceiveOperatorState}
	if h := a.mirrorHome(); h != "" {
		argv = append(argv, h) // the VM links <home>/.sandbox to the pushed state
	}
	rc, err := a.env.Transport.Run(a.ctx, ep, argv, bytes.NewReader(archive), io.Discard, &errb, false)
	if err != nil || rc != 0 {
		a.die("could not push the operator state to the sandbox VM: %v %s", err, strings.TrimSpace(errb.String()))
	}
	return archive
}

// ReceiveOperatorState is the in-VM entry point that takes the pushed state.
const ReceiveOperatorState = "__receive-operator-state"

func (a *app) proxy(args []string) int {
	ep := a.running()
	a.handshake(ep)
	archive := a.pushState(ep)
	var extra []string
	if len(args) > 0 && args[0] == "run" {
		wd, err := os.Getwd()
		if err != nil {
			a.die("%v", err)
		}
		args = append([]string{"run"}, absRepos(args[1:], wd)...)
		prep := a.prepareRun(ep, args[1:], archive)
		if prep.opencodeConfig != "" {
			extra = append(extra, OpencodeConfigEnv+"="+prep.opencodeConfig)
		}
		if prep.kube != "" {
			extra = append(extra, prep.kube)
		}
		extra = append(extra, a.declareEndpoints(prep.endpoints)...)
		live := a.startLiveSync(ep, prep.synced)
		defer live.finish()
	}
	if len(args) > 1 && args[0] == "resume" {
		if id := resumeSessionID(args[1:]); id != "" {
			live := a.startLiveSync(ep, a.prepareResume(ep, id))
			defer live.finish()
		}
	}
	rc, err := a.env.Transport.Run(a.ctx, ep, a.vmArgvEnv(extra, args...), a.env.Stdin, a.env.Stdout, a.env.Stderr, a.env.StdinTTY)
	a.releaseEndpoints(ep) // a session that ended (this one, or a detached one) closes its endpoints
	if err != nil {
		a.die("cannot run the command in the sandbox VM: %v", err)
	}
	a.pullAudit(ep)
	return rc
}

// pullAudit brings the sessions' new audit records to ~/.sandbox/logs (design 5.1.5, 5.12). A
// failure is a warning: the next pull continues from the last record the host holds, and records
// the gap if any are lost.
func (a *app) pullAudit(ep driver.SSHEndpoint) {
	run := func(ctx context.Context, argv []string, max int) ([]byte, error) {
		return a.env.Transport.Output(ctx, ep, argv, max)
	}
	rep, err := auditpull.Pull(a.ctx, run, VMCommand, filepath.Join(a.env.StateDir, "logs"), a.env.Now)
	if err != nil {
		fmt.Fprintf(a.env.Stderr, "WARNING: could not pull the session audit logs: %v\n", err)
		return
	}
	if rep.Gaps > 0 || len(rep.Refused) > 0 {
		fmt.Fprintf(a.env.Stderr, "WARNING: the session audit logs had %d gap(s) and %d refused record(s); see ~/.sandbox/logs\n", rep.Gaps, len(rep.Refused))
	}
}

const vmUsage = `Usage: sandbox vm <start|stop|status|shell>

  start    Boot the sandbox VM
  stop     Shut the sandbox VM down
  status   Show the VM's state and image version
  shell    Open a root shell in the VM for debugging (recorded in ~/.sandbox/logs/vm-shell.log)
`

func (a *app) vm(args []string) int {
	if len(args) != 1 {
		fmt.Fprint(a.env.Stderr, vmUsage)
		return 1
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(a.env.Stdout, vmUsage)
		return 0
	case "start":
		st, err := a.env.Driver.Status(a.ctx)
		if err != nil {
			a.die("cannot read the sandbox VM's state: %v", err)
		}
		if st == driver.Running {
			no, owns := a.env.Driver.(driver.NetworkOwner)
			if !owns || no.Network(a.ctx).Running {
				a.warnBrokerKey(a.running())
				fmt.Fprintln(a.env.Stdout, "The sandbox VM is already running.")
				return 0
			}
			// netd died and took the VM's network with it: only a restart brings it back.
			fmt.Fprintln(a.env.Stdout, "==> sandbox netd is not running; restarting the sandbox VM...")
			if err := a.env.Driver.Stop(a.ctx); err != nil {
				a.die("could not stop the sandbox VM: %v", err)
			}
		}
		if st == driver.NotCreated {
			a.die("the sandbox VM has not been created. Run: sandbox install")
		}
		fmt.Fprintln(a.env.Stdout, "==> Starting the sandbox VM...")
		if err := a.env.Driver.Start(a.ctx); err != nil {
			a.die("could not start the sandbox VM: %v", err)
		}
		// The guest's sshd can restart once while it boots (the seed unit applies the pinned
		// host key), so the first handshake is retried as install's is.
		if _, err := a.waitReady(); err != nil {
			a.die("the sandbox VM started but is not answering: %v\n  See: sandbox vm status", err)
		}
		a.warnBrokerKey(a.running())
		fmt.Fprintln(a.env.Stdout, "The sandbox VM is running.")
		return 0
	case "stop":
		st, err := a.env.Driver.Status(a.ctx)
		if err != nil {
			a.die("cannot read the sandbox VM's state: %v", err)
		}
		if st != driver.Running {
			fmt.Fprintf(a.env.Stdout, "The sandbox VM is %s.\n", st)
			return 0
		}
		if ep, err := a.env.Driver.Endpoint(a.ctx); err == nil {
			a.pullAudit(ep) // before the VM goes
		}
		fmt.Fprintln(a.env.Stdout, "==> Stopping the sandbox VM...")
		if err := a.env.Driver.Stop(a.ctx); err != nil {
			a.die("could not stop the sandbox VM: %v", err)
		}
		a.releaseAllEndpoints()
		fmt.Fprintln(a.env.Stdout, "The sandbox VM is stopped.")
		return 0
	case "status":
		st, err := a.env.Driver.Status(a.ctx)
		if err != nil {
			a.die("cannot read the sandbox VM's state: %v", err)
		}
		fmt.Fprintf(a.env.Stdout, "VM:     %s (driver %s)\n", st, a.env.Driver.Name())
		if no, ok := a.env.Driver.(driver.NetworkOwner); ok && st == driver.Running {
			rep := no.Network(a.ctx)
			fmt.Fprintf(a.env.Stdout, "netd:   %s\n", rep.Detail)
			if !rep.Running {
				return 1
			}
		}
		if st == driver.Running {
			info := a.handshake(a.running())
			fmt.Fprintf(a.env.Stdout, "Image:  %s (control API %d)\n", info.ImageVersion, info.ControlAPI)
		}
		if hr, err := a.env.Driver.HostReach(a.ctx); err == nil && hr.Mechanism != "" {
			fmt.Fprintf(a.env.Stdout, "Host reach control: %s\n", hr.Mechanism)
		}
		return 0
	case "shell":
		return a.shell()
	}
	fmt.Fprint(a.env.Stderr, vmUsage)
	return 1
}

// shell is `sandbox vm shell`: a root debug shell, recorded on the host before and after it runs,
// because a record kept in the VM can be erased by VM root (5.1.6).
func (a *app) shell() int {
	ep := a.running()
	logf, err := openShellLog(a.env.StateDir)
	if err != nil {
		a.die("cannot record the VM shell: %v (refusing to open an unrecorded root shell)", err)
	}
	defer logf.Close()
	stamp := func() string { return a.env.Now().UTC().Format(time.RFC3339) }
	if _, err := fmt.Fprintf(logf, "%s start user=%q\n", stamp(), a.env.User); err != nil {
		a.die("cannot record the VM shell: %v (refusing to open an unrecorded root shell)", err)
	}
	rc, err := a.env.Transport.Run(a.ctx, ep, nil, a.env.Stdin, a.env.Stdout, a.env.Stderr, true)
	if err != nil {
		fmt.Fprintf(logf, "%s end error=%q\n", stamp(), err.Error())
		a.die("VM shell failed: %v", err)
	}
	fmt.Fprintf(logf, "%s end rc=%d\n", stamp(), rc)
	return rc
}

// openShellLog opens <state>/logs/vm-shell.log for appending only, creating it 0600.
func openShellLog(stateDir string) (*os.File, error) {
	if stateDir == "" {
		return nil, errors.New("no state directory")
	}
	dir := filepath.Join(stateDir, "logs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(dir, "vm-shell.log"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
}
