package app

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncengine"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncgate"
)

// WorkspacesDir is where the VM keeps one copy of each synced repository (design 5.6.1).
const WorkspacesDir = "/var/lib/sandbox/workspaces"

// SyncUser is the VM user the sync agent runs as (design 5.6.2 rule 5).
const SyncUser = "sandbox-sync"

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
	if st, err := os.Lstat(filepath.Join(repo, ".git")); err != nil || !st.IsDir() {
		a.die("%s is not the top of a git work tree", repo)
	}
	id, err := syncgate.RepoID(repo)
	if err != nil {
		a.die("%v", err)
	}
	ep := a.running()
	a.handshake(ep)
	ws := WorkspacesDir + "/" + id
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
	}
	rep, err := e.Sync()
	toAgentW.Close()
	if aerr := <-done; err != nil && aerr != nil {
		err = fmt.Errorf("%v (%v)", err, aerr)
	}
	if err != nil {
		a.die("sync of %s failed: %v", repo, err)
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
