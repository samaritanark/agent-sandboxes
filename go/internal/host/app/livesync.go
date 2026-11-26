package app

// The workspace sync while a session runs (design 5.6.1): from the launch until the run command
// ends, each repository of the session is synced every LiveSyncInterval, then once more. Nothing is
// printed meanwhile (the terminal belongs to the agent); a summary follows the session.

import (
	"context"
	"fmt"
	"sync"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncengine"
)

type liveSync struct {
	a      *app
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu               sync.Mutex
	toHost, withheld int
	errs             map[string]error // the last error of each repository
	failedFinal      map[string]bool
	repos            []string
}

// startLiveSync starts syncing repos until finish.
func (a *app) startLiveSync(ep driver.SSHEndpoint, repos []string) *liveSync {
	ctx, cancel := context.WithCancel(a.ctx)
	l := &liveSync{a: a, cancel: cancel, errs: map[string]error{}, failedFinal: map[string]bool{}, repos: repos}
	for _, r := range repos {
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			_, rep, err := a.syncLoop(ep, r, ctx, func(rep syncengine.Report, err error) { l.add(r, rep, err) })
			l.add(r, rep, err)
			if err != nil {
				l.mu.Lock()
				l.failedFinal[r] = true
				l.mu.Unlock()
			}
		}()
	}
	return l
}

func (l *liveSync) add(repo string, rep syncengine.Report, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		l.errs[repo] = err
		return
	}
	l.toHost += len(rep.ToHost)
	l.withheld += len(rep.Quarantined) + len(rep.Conflicts)
}

// finish stops the sync after a final pass and says what came back.
func (l *liveSync) finish() {
	if l == nil || len(l.repos) == 0 {
		return
	}
	l.cancel()
	l.wg.Wait()
	out, errOut := l.a.env.Stdout, l.a.env.Stderr
	if l.toHost > 0 || l.withheld > 0 {
		fmt.Fprintf(out, "==> The session's changes synced to the host: %d file(s)", l.toHost)
		if l.withheld > 0 {
			fmt.Fprintf(out, ", %d withheld (see: sandbox sync review)", l.withheld)
		}
		fmt.Fprintln(out, ".")
	}
	for _, r := range l.repos {
		if err := l.errs[r]; err != nil && l.failedFinal[r] {
			fmt.Fprintf(errOut, "WARNING: the last sync of %s failed: %v\n  Its changes stay in the VM; run: sandbox sync once --repo %s\n", r, err, r)
		}
	}
}
