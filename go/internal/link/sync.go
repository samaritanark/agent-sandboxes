package link

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
)

// SyncCtx is what the run-path sync needs beyond Ctx.
type SyncCtx struct {
	Ctx
	NoLinkCheck    bool          // $SANDBOX_NO_LINK_CHECK is set
	FetchTimeout   time.Duration // $LINK_FETCH_TIMEOUT_SECONDS (default 10s)
	SandboxVersion string        // $SANDBOX_VERSION ("" is "dev")
	Git            string        // the git binary; "" when git is not on PATH
}

// SyncResult is what link_sync_on_run prints, and Die when it ends the launch (the bash's die).
type SyncResult struct {
	Stdout, Stderr []string
	Die            string
}

func (c SyncCtx) git(dir string, args ...string) (string, error) {
	out, err := exec.Command(c.Git, append([]string{"-C", dir}, args...)...).Output()
	return string(out), err
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func (c SyncCtx) revParse(dir, rev string) string {
	out, err := c.git(dir, "rev-parse", "--verify", "--quiet", rev)
	if err != nil {
		return ""
	}
	return strings.TrimRight(out, "\n")
}

// SyncOnRun is link_sync_on_run: before a launch, advance the linked overlay to its pinned ref's
// tip, re-validate it, and record the new commit. Offline, a dirty clone, or an invalid new tree
// warns and keeps the current commit; an overlay that now needs a newer CLI rolls back and ends
// the launch.
func (c SyncCtx) SyncOnRun() SyncResult {
	var r SyncResult
	warn := func(s string) { r.Stderr = append(r.Stderr, "WARN: "+s) }
	if c.NoLinkCheck || c.Git == "" || !c.IsActive() {
		return r
	}
	dir := c.ActiveDir()
	ref := c.Ref()
	if dir == "" || ref == "" {
		return r
	}
	head := c.revParse(dir, "HEAD")
	ctx, cancel := context.WithTimeout(context.Background(), c.FetchTimeout)
	err := exec.CommandContext(ctx, c.Git, "-C", dir, "fetch", "--quiet", "--tags", "origin").Run()
	cancel()
	if err != nil {
		warn(fmt.Sprintf("linked overlay: could not fetch '%s' — launching from the current commit %s.", c.URL(), short(head)))
		return r
	}
	os.WriteFile(dir+"/.git/sandbox-last-fetch", nil, 0o666)
	target := c.revParse(dir, "origin/"+ref+"^{commit}")
	if target == "" {
		target = c.revParse(dir, ref+"^{commit}")
	}
	if head == "" || target == "" || head == target {
		return r
	}
	if st, _ := c.git(dir, "status", "--porcelain"); st != "" {
		shown := dir
		if c.Home != "" && strings.HasPrefix(dir, c.Home) {
			shown = "~" + dir[len(c.Home):]
		}
		warn(fmt.Sprintf("linked overlay is behind '%s' but has local uncommitted edits at %s; not auto-syncing. Commit, stash, or discard them, then run 'sandbox link sync'.", ref, shown))
		return r
	}
	r.Stdout = append(r.Stdout, fmt.Sprintf("==> Syncing linked overlay to '%s' (%s -> %s)", ref, short(head), short(target)))
	if stat, err := c.git(dir, "--no-pager", "diff", "--stat", head, target); err == nil && stat != "" {
		r.Stdout = append(r.Stdout, strings.Split(strings.TrimRight(stat, "\n"), "\n")...)
	}
	c.git(dir, "checkout", "--quiet", ref)
	rollback := func() { c.git(dir, "reset", "--hard", "--quiet", head) }
	if _, err := c.git(dir, "reset", "--hard", "--quiet", target); err != nil {
		rollback()
		warn(fmt.Sprintf("could not advance the linked overlay to %s; launching from %s.", short(target), short(head)))
		return r
	}
	if v := c.ValidateShape(dir); !v.OK {
		r.Stderr = append(r.Stderr, v.Stderr...)
		rollback()
		warn(fmt.Sprintf("updated overlay tree ('%s' @ %s) failed validation; rolled back — launching from %s. Review with 'sandbox link sync' once the overlay is fixed.", ref, short(target), short(head)))
		return r
	} else {
		r.Stderr = append(r.Stderr, v.Stderr...)
	}
	unmet, warns := config.OverlayMinVersionUnmet(dir, c.SandboxVersion)
	for _, w := range warns {
		warn(w)
	}
	if unmet != "" {
		rollback()
		ver := c.SandboxVersion
		if ver == "" {
			ver = "dev"
		}
		r.Die = fmt.Sprintf("linked overlay '%s' now requires agent-sandboxes >= %s, but this is %s. Run 'sandbox upgrade', then launch again. (Rolled back to %s; SANDBOX_NO_LINK_CHECK=1 skips the run-path sync entirely.)", ref, unmet, ver, short(head))
		return r
	}
	if err := c.WriteConfig(dir, c.URL(), ref, target); err != nil {
		r.Die = err.Error()
		return r
	}
	r.Stdout = append(r.Stdout, fmt.Sprintf("    linked overlay updated to '%s' (%s)", ref, short(target)))
	return r
}
