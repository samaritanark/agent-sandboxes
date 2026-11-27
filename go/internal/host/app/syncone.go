package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncengine"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncgate"
)

// WorkspacesDir is where the VM keeps one copy of each synced repository (design 5.6.1).
const WorkspacesDir = "/var/lib/sandbox/workspaces"

// SyncCacheDir is where the VM's sync agent keeps each copy's fingerprint cache
// (sessionspec.SyncCacheStore): made here for the sync user, and never mounted into a microVM.
const SyncCacheDir = "/var/lib/sandbox/sync-cache"

// SyncUser is the VM user the sync agent runs as (design 5.6.2 rule 5).
const SyncUser = "sandbox-sync"

// CopyMode is a VM copy's directory mode: the sync user's, readable by its group, whose only other
// member is sandbox-git, the user the in-VM gates' git runs as (image/mkosi.postinst.chroot).
const CopyMode = "0750"

// copyEpoch makes the VM copy ws if it is missing and returns its epoch: a random token root writes
// beside a copy (ws.epoch) when the copy has none, so a copy made again (a reinstalled VM) has a
// new one and the host sets aside the state it kept for the old copy (syncengine.Engine.Copy).
func (a *app) copyEpoch(ep driver.SSHEndpoint, ws string) (string, error) {
	script := `set -e; [ -d "$0" ] || { rm -f "$0.epoch"; install -d -o ` + SyncUser + ` -g ` + SyncUser + ` -m ` + CopyMode + ` "$0"; }; ` +
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
//
// A sync's connection to the VM can fail (sshd drops connections past its limit of unauthenticated
// ones, the network can blip): while live runs, a failed or ended connection is made again, after
// a wait that doubles from syncRetryBase up to syncRetryMax, for as long as the session runs; after
// that (the one pass of syncRepo, the final pass) a failure is tried syncTries times. The engine's state
// file keeps the last good pass, so a new connection carries on where the old one stopped.
func (a *app) syncLoop(ep driver.SSHEndpoint, repo string, live context.Context, each func(syncengine.Report, error)) (string, syncengine.Report, error) {
	if st, err := os.Lstat(filepath.Join(repo, ".git")); err != nil || !st.IsDir() {
		return "", syncengine.Report{}, fmt.Errorf("%s is not the top of a git work tree", repo)
	}
	id, err := syncgate.RepoID(repo)
	if err != nil {
		return "", syncengine.Report{}, err
	}
	ws := WorkspacesDir + "/" + id
	wait, tries := syncRetryBase, 0
	for {
		rep, passed, err := a.syncConn(ep, repo, id, ws, live, each)
		if err == nil {
			return ws, rep, nil
		}
		tries++
		if passed {
			tries, wait = 0, syncRetryBase // the connection worked for a while: start counting again
		}
		if liveOn := live != nil && live.Err() == nil; !liveOn && tries >= syncTries {
			return "", syncengine.Report{}, fmt.Errorf("sync of %s failed: %v", repo, err)
		}
		select {
		case <-a.ctx.Done():
			return "", syncengine.Report{}, fmt.Errorf("sync of %s failed: %v", repo, err)
		case <-time.After(wait):
		}
		wait = min(2*wait, syncRetryMax)
	}
}

// How often a sync tries again (syncLoop), and how many repositories may set up their connection
// to the VM at once (syncSlots): the VM's sshd drops unauthenticated connections past its
// MaxStartups, and a session may have 128 repositories, each with its own connection.
var (
	syncTries     = 3
	syncRetryBase = time.Second
	syncRetryMax  = 30 * time.Second
	syncSlots     = make(chan struct{}, 6)
)

// errConnEnded is a sync connection that ended while its session still ran.
var errConnEnded = errors.New("the sync's connection to the VM ended")

// syncConn is one connection's worth of syncLoop: the copy's epoch, the agent, the passes while live
// runs, and the final pass. passed says a pass succeeded on it. A connection that ends while live
// still runs returns errConnEnded without a final pass, for the caller to connect again.
func (a *app) syncConn(ep driver.SSHEndpoint, repo, id, ws string, live context.Context, each func(syncengine.Report, error)) (rep syncengine.Report, passed bool, err error) {
	// hold a slot until the first pass is made, so that only a few connections are set up at once
	syncSlots <- struct{}{}
	var once sync.Once
	release := func() { once.Do(func() { <-syncSlots }) }
	defer release()
	epoch, err := a.copyEpoch(ep, ws)
	if err != nil {
		return syncengine.Report{}, false, err
	}
	// root creates the copy's directory; the agent itself runs unprivileged. The sync group may
	// read the copy (CopyMode), as the in-VM gates' git does as sandbox-git
	script := `set -e; install -d -o ` + SyncUser + ` -g ` + SyncUser + ` -m ` + CopyMode + ` "$0"; ` +
		`install -d -o ` + SyncUser + ` -g ` + SyncUser + ` -m 0700 ` + SyncCacheDir + `; exec runuser -u ` + SyncUser + ` -- sandbox __sync-agent "$0"`
	toAgentR, toAgentW := io.Pipe()
	fromAgentR, fromAgentW := io.Pipe()
	var agentErr strings.Builder
	done, ended := make(chan error, 1), make(chan struct{})
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
		close(ended)
	}()
	e := &syncengine.Engine{
		Repo:      repo,
		Host:      syncgate.ProbeHost(repo),
		StateFile: filepath.Join(a.env.StateDir, "sync", id, "state.json"),
		CacheFile: filepath.Join(a.env.StateDir, "sync", id, "fpcache.json"),
		Store:     &syncgate.Store{Dir: filepath.Join(a.env.StateDir, "quarantine")},
		VM:        &syncengine.StreamVM{W: toAgentW, R: fromAgentR},
		Copy:      epoch,
	}
	finish := func(err error) error {
		toAgentW.Close()
		if aerr := <-done; err != nil && aerr != nil {
			err = fmt.Errorf("%v (%v)", err, aerr)
		}
		return err
	}
	if live != nil && live.Err() == nil {
	passes:
		for {
			start := time.Now()
			r, err := e.Sync()
			passed = passed || err == nil
			release()
			if each != nil {
				each(r, err)
			}
			select {
			case <-ended:
				if live.Err() == nil {
					return syncengine.Report{}, passed, finish(errConnEnded)
				}
				break passes
			case <-live.Done():
				break passes
			case <-time.After(syncengine.NextPass(LiveSyncInterval, time.Since(start))):
			}
		}
	}
	rep, err = e.Sync()
	if err == nil {
		e.SaveCache()
	}
	if err = finish(err); err != nil {
		return syncengine.Report{}, passed, err
	}
	return rep, true, nil
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
