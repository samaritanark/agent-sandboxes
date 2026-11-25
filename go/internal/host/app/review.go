package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncgate"
)

const syncUsage = `Usage: sandbox sync review [--apply <id>] [--discard <id>]
       sandbox sync once --repo <path>

review  List workspace changes the sync gate withheld from your checkouts, with
        a diff against what is there now; apply or discard one by its id.
once    Run one sync pass between a repository and its copy in the VM.
`

func (a *app) sync(args []string) int {
	if len(args) > 0 && args[0] == "once" {
		return a.syncOnce(args[1:])
	}
	if len(args) == 0 || args[0] != "review" {
		if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
			fmt.Fprint(a.env.Stdout, syncUsage)
			return 0
		}
		fmt.Fprint(a.env.Stderr, syncUsage)
		return 1
	}
	args = args[1:]
	store := &syncgate.Store{Dir: filepath.Join(a.env.StateDir, "quarantine")}
	switch {
	case len(args) == 0:
		return a.reviewList(store)
	case len(args) == 1 && (args[0] == "-h" || args[0] == "--help"):
		fmt.Fprint(a.env.Stdout, syncUsage)
		return 0
	case len(args) == 2 && args[0] == "--discard":
		if err := store.Discard(args[1]); err != nil {
			a.die("%v", err)
		}
		fmt.Fprintf(a.env.Stdout, "Discarded %s.\n", args[1])
		return 0
	case len(args) == 2 && args[0] == "--apply":
		return a.reviewApply(store, args[1])
	}
	fmt.Fprint(a.env.Stderr, syncUsage)
	return 1
}

func (a *app) reviewList(store *syncgate.Store) int {
	held, err := store.List()
	if err != nil {
		a.die("cannot read the quarantine: %v", err)
	}
	if len(held) == 0 {
		fmt.Fprintln(a.env.Stdout, "No withheld workspace changes.")
		return 0
	}
	for _, h := range held {
		fmt.Fprintf(a.env.Stdout, "%s  %s\n  %s (%s): %s\n", h.ID, h.Repo, h.Path, h.Op, h.Reason)
		_, c, err := store.Get(h.ID)
		if err != nil {
			fmt.Fprintf(a.env.Stdout, "  (cannot read it: %v)\n\n", err)
			continue
		}
		if cmd, ok := syncgate.GitRefCommand(h, c.Data); ok {
			fmt.Fprintf(a.env.Stdout, "  a branch update; to apply it run:\n    %s\n\n", cmd)
			continue
		}
		switch c.Op {
		case syncgate.OpWrite:
			cur, _ := os.ReadFile(filepath.Join(h.Repo, filepath.FromSlash(h.Path)))
			for _, l := range strings.SplitAfter(strings.TrimSuffix(syncgate.LineDiff(cur, c.Data), "\n"), "\n") {
				fmt.Fprintf(a.env.Stdout, "    %s", l)
			}
			fmt.Fprintln(a.env.Stdout)
		case syncgate.OpSymlink:
			fmt.Fprintf(a.env.Stdout, "    symlink to %q\n", c.Target)
		}
		fmt.Fprintln(a.env.Stdout)
	}
	return 0
}

func (a *app) reviewApply(store *syncgate.Store, id string) int {
	h, c, err := store.Get(id)
	if err != nil {
		a.die("%v", err)
	}
	if cmd, ok := syncgate.GitRefCommand(h, c.Data); ok {
		fmt.Fprintf(a.env.Stdout, "%s is a branch update; the sandbox does not move your branches itself. Run:\n  %s\nthen: sandbox sync review --discard %s\n", id, cmd, id)
		return 0
	}
	ap := &syncgate.Applier{Repo: h.Repo, Host: syncgate.ProbeHost(h.Repo)}
	if err := ap.ApplyApproved(c); err != nil {
		a.die("cannot apply %s: %v", id, err)
	}
	if err := store.Discard(id); err != nil {
		a.die("applied, but could not remove it from the quarantine: %v", err)
	}
	fmt.Fprintf(a.env.Stdout, "Applied %s to %s.\n", h.Path, h.Repo)
	return 0
}
