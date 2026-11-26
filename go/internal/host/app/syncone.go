package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncengine"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncgate"
)

// WorkspacesDir is where the VM keeps one copy of each synced repository (design 5.6.1).
const WorkspacesDir = "/var/lib/sandbox/workspaces"

// SyncUser is the VM user the sync agent runs as (design 5.6.2 rule 5).
const SyncUser = "sandbox-sync"

// copyEpoch makes the VM copy ws if it is missing and returns its epoch: a random token root writes
// beside a copy (ws.epoch) when the copy has none, so a copy made again (a reinstalled VM) has a
// new one and the host sets aside the state it kept for the old copy (syncengine.Engine.Copy).
func (a *app) copyEpoch(ep driver.SSHEndpoint, ws string) (string, error) {
	script := `set -e; [ -d "$0" ] || { rm -f "$0.epoch"; install -d -o ` + SyncUser + ` -g ` + SyncUser + ` -m 0700 "$0"; }; ` +
		`[ -s "$0.epoch" ] || od -An -N16 -tx1 /dev/urandom | tr -d ' \n' > "$0.epoch"; cat "$0.epoch"`
	out, err := a.env.Transport.Output(a.ctx, ep, []string{"sh", "-c", script, ws}, 128)
	if err != nil {
		return "", fmt.Errorf("cannot read the VM copy's epoch: %v", err)
	}
	e := strings.TrimSpace(string(out))
	if !epochRE.MatchString(e) {
		return "", fmt.Errorf("the VM copy's epoch %q is not one", e)
	}
	return e, nil
}

var epochRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// LiveSyncInterval is how often a repository is synced while a session runs (polling, as decided:
// the host has no file watcher yet).
var LiveSyncInterval = 3 * time.Second

// syncRepo is one engine pass between host repository repo (absolute) and its VM copy, ws.
func (a *app) syncRepo(ep driver.SSHEndpoint, repo string) (string, syncengine.Report, error) {
	return a.syncLoop(ep, repo, nil, nil)
}

// syncLoop is syncRepo, but with live set it passes every LiveSyncInterval until live ends,
// reporting each pass to each, and then makes one final pass, whose report it returns: the last
// changes before a session ended still reach the host.
func (a *app) syncLoop(ep driver.SSHEndpoint, repo string, live context.Context, each func(syncengine.Report, error)) (string, syncengine.Report, error) {
	if st, err := os.Lstat(filepath.Join(repo, ".git")); err != nil || !st.IsDir() {
		return "", syncengine.Report{}, fmt.Errorf("%s is not the top of a git work tree", repo)
	}
	id, err := syncgate.RepoID(repo)
	if err != nil {
		return "", syncengine.Report{}, err
	}
	ws := WorkspacesDir + "/" + id
	epoch, err := a.copyEpoch(ep, ws)
	if err != nil {
		return "", syncengine.Report{}, err
	}
	// root creates the copy's directory; the agent itself runs unprivileged
	script := `set -e; install -d -o ` + SyncUser + ` -g ` + SyncUser + ` -m 0700 "$0"; exec runuser -u ` + SyncUser + ` -- sandbox __sync-agent "$0"`
	toAgentR, toAgentW := io.Pipe()
	fromAgentR, fromAgentW := io.Pipe()
	var agentErr strings.Builder
	done := make(chan error, 1)
	go func() {
		rc, err := a.env.Transport.Run(a.ctx, ep, []string{"sh", "-c", script, ws}, toAgentR, fromAgentW, &agentErr, false)
		if err == nil && rc != 0 {
			err = fmt.Errorf("the sync agent exited with %d: %s", rc, strings.TrimSpace(agentErr.String()))
		}
		if err == nil {
			err = fmt.Errorf("the sync agent ended: %s", strings.TrimSpace(agentErr.String()))
		}
		// both directions fail from here, so the engine never waits on an agent that is gone
		fromAgentW.CloseWithError(err)
		toAgentR.CloseWithError(err)
		done <- err
	}()
	e := &syncengine.Engine{
		Repo:      repo,
		Host:      syncgate.ProbeHost(repo),
		StateFile: filepath.Join(a.env.StateDir, "sync", id, "state.json"),
		Store:     &syncgate.Store{Dir: filepath.Join(a.env.StateDir, "quarantine")},
		VM:        &syncengine.StreamVM{W: toAgentW, R: fromAgentR},
		Copy:      epoch,
	}
	if live != nil {
		e.Run(live, LiveSyncInterval, each)
	}
	rep, err := e.Sync()
	toAgentW.Close()
	if aerr := <-done; err != nil && aerr != nil {
		err = fmt.Errorf("%v (%v)", err, aerr)
	}
	if err != nil {
		return "", syncengine.Report{}, fmt.Errorf("sync of %s failed: %v", repo, err)
	}
	return ws, rep, nil
}

// syncOnce is `sandbox sync once --repo PATH`: one engine pass between a host repository and its
// VM copy, for use before `sandbox run` drives the sync itself.
func (a *app) syncOnce(args []string) int {
	if len(args) != 2 || args[0] != "--repo" {
		fmt.Fprint(a.env.Stderr, syncUsage)
		return 1
	}
	repo, err := filepath.Abs(args[1])
	if err != nil {
		a.die("%v", err)
	}
	ep := a.running()
	a.handshake(ep)
	ws, rep, err := a.syncRepo(ep, repo)
	if err != nil {
		a.die("%v", err)
	}
	fmt.Fprintf(a.env.Stdout, "Synced %s (VM copy %s): %d to the VM, %d to the host, %d withheld, %d conflicts.\n",
		repo, ws, len(rep.ToVM), len(rep.ToHost), len(rep.Quarantined), len(rep.Conflicts))
	for _, l := range rep.Ledger {
		fmt.Fprintf(a.env.Stdout, "  %s\n", l)
	}
	for _, n := range rep.Notes {
		fmt.Fprintf(a.env.Stdout, "  note: %s\n", n)
	}
	if len(rep.Quarantined)+len(rep.Conflicts) > 0 {
		fmt.Fprintln(a.env.Stdout, "  See: sandbox sync review")
	}
	return 0
}
