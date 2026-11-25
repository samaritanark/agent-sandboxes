package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/gate"
	"github.com/samaritanark/agent-sandboxes/go/internal/link"
)

func (c *cmdCtx) link() link.SyncCtx {
	dir := c.env.LinkOverlaysDir
	if dir == "" {
		dir = c.env.Home + "/.sandbox/overlays"
	}
	git, _ := exec.LookPath("git")
	return link.SyncCtx{Ctx: link.Ctx{Env: c.env.Env, OverlaysDir: dir}, FetchTimeout: 10 * time.Second,
		SandboxVersion: c.env.Version.Version, Git: git}
}

// paint is c_ok / c_warn: green or yellow on a terminal stdout.
func (c *cmdCtx) paint(code, s string) string {
	if c.env.StdoutTTY && !c.env.NoColor {
		return "\033[" + code + "m" + s + "\033[0m"
	}
	return s
}

func short12(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// activeDir is `dir="$(link_active_dir)"` under the bash's `set -e`: link_active_dir ends with
// `[[ -d "${dir}/.git" ]] && echo`, so a recorded clone that has lost its .git fails the
// assignment and ends the command with status 1 and no message. With LinkMissingCloneMessage the
// empty result reaches the callers' own messages.
func (c *cmdCtx) activeDir(l link.SyncCtx) string {
	d := l.ActiveDir()
	if d == "" && l.IsActive() && config.ExtractYAMLScalar(c.env.UserConfig, "overlay") != "" &&
		!deviation.Fixed(deviation.LinkMissingCloneMessage) {
		panic(exit(1))
	}
	return d
}

func (c *cmdCtx) requireGit(l link.SyncCtx) {
	if l.Git == "" {
		c.die("'git' is required for 'sandbox link' but was not found on PATH.")
	}
}

func gitRun(l link.SyncCtx, dir string, args ...string) (string, error) {
	out, err := exec.Command(l.Git, append([]string{"-C", dir}, args...)...).Output()
	return strings.TrimRight(string(out), "\n"), err
}

// cmdLink is cmd_link: clone a team overlay (the default), or status, sync, unlink.
func cmdLink(c *cmdCtx, args []string) {
	if len(args) == 0 {
		c.usage("usage_link")
	}
	switch args[0] {
	case "--help", "-h", "help":
		c.usage("usage_link")
	case "status":
		linkStatus(c, args[1:])
	case "sync":
		linkSync(c, args[1:])
	case "unlink":
		linkUnlink(c, args[1:])
	default:
		linkClone(c, args)
	}
}

func linkClone(c *cmdCtx, args []string) {
	url, name, ref := "", "", ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if v, ok := flagValue(c, args, &i, "--name"); ok {
			name = v
			continue
		}
		if v, ok := flagValue(c, args, &i, "--ref"); ok {
			ref = v
			continue
		}
		switch {
		case a == "--help" || a == "-h":
			c.usage("usage_link")
		case strings.HasPrefix(a, "-"):
			c.die("Unknown option for 'link': %s. Run 'sandbox link --help'.", a)
		default:
			if url != "" {
				c.die("Unexpected argument: %s", a)
			}
			url = a
		}
	}
	if url == "" {
		c.die("Usage: sandbox link <GIT-URL> [--name <NAME>] [--ref <REF>]")
	}
	l := c.link()
	c.requireGit(l)
	if l.IsActive() {
		c.die("A link is already active (%s). Run 'sandbox link unlink' first, or 'sandbox link sync' to update it.", l.URL())
	}
	if name == "" {
		if name = link.NameFromURL(url); name == "" {
			c.die("Could not derive a link name from '%s'. Pass --name <NAME>.", url)
		}
	}
	if !link.IsValidName(name) {
		c.die("Invalid link name '%s'. Use letters, digits, '.', '_', '-'; no '/', no leading '.'.", name)
	}
	dir := l.ManagedDir(name)
	if config.Exists(dir) {
		c.die("%s already exists. Choose another --name or remove it.", c.tilde(dir))
	}
	if ov := config.ExtractYAMLScalar(c.env.UserConfig, "overlay"); ov != "" {
		c.warn("existing 'overlay: %s' will be repointed at the linked clone.", ov)
	}
	c.out("==> Cloning %s", url)
	os.MkdirAll(l.OverlaysDir, 0o755)
	clone := exec.Command(l.Git, "clone", "--quiet", url, dir)
	clone.Stderr = c.stderr
	if clone.Run() != nil {
		os.RemoveAll(dir)
		c.die("git clone failed. Check the URL and your git credentials for private repos.")
	}
	if ref != "" {
		if _, err := gitRun(l, dir, "checkout", "--quiet", ref); err != nil {
			os.RemoveAll(dir)
			c.die("ref '%s' not found in %s.", ref, url)
		}
	} else if r, err := gitRun(l, dir, "rev-parse", "--abbrev-ref", "HEAD"); err == nil {
		ref = r
	} else {
		ref = "HEAD"
	}
	commit, _ := gitRun(l, dir, "rev-parse", "--verify", "--quiet", "HEAD")
	c.out("==> Validating overlay shape")
	v := l.ValidateShape(dir)
	for _, s := range v.Stderr {
		fmt.Fprintln(c.stderr, s)
	}
	if !v.OK {
		os.RemoveAll(dir)
		c.die("overlay at '%s' (%s) failed validation; nothing was linked.", url, ref)
	}
	unmet, warns := config.OverlayMinVersionUnmet(dir, c.env.Version.Version)
	for _, w := range warns {
		c.warn("%s", w)
	}
	if unmet != "" {
		os.RemoveAll(dir)
		c.die("overlay at '%s' (%s) requires agent-sandboxes >= %s, but this is %s. Run 'sandbox upgrade' first, then re-link.", url, ref, unmet, c.env.version())
	}
	l.WriteConfig(dir, url, ref, commit)
	c.out("Linked overlay '%s' → %s", name, c.tilde(dir))
	c.out("  ref:    %s", ref)
	c.out("  commit: %s", short12(commit))
	c.out("  pointer written to the 'overlay:' key in %s", c.tilde(c.env.UserConfig))
	gate.FetchLeakscanConfig(c.env.Env, gate.FetchEnv{}, func(m string) { c.warn("%s", m) }, c.stdout)
}

func linkStatus(c *cmdCtx, args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "--help", "-h":
			c.usage("usage_link")
		case "":
		default:
			c.die("Unexpected argument: %s", args[0])
		}
	}
	l := c.link()
	if !l.IsActive() {
		c.out("No linked overlay. Link one with: sandbox link <GIT-URL>")
		return
	}
	c.requireGit(l)
	url, ref, dir := l.URL(), l.Ref(), c.activeDir(l)
	c.out("Linked overlay")
	c.out("  %-8s %s", "url:", url)
	c.out("  %-8s %s", "ref:", ref)
	c.out("  %-8s %s", "commit:", l.Commit())
	if dir == "" {
		c.warn("recorded overlay pointer is not a git clone; the link record may be stale.")
		return
	}
	c.out("  %-8s %s", "path:", c.tilde(dir))
	if exec.Command(l.Git, "-C", dir, "fetch", "--quiet", "--tags", "origin").Run() != nil {
		c.out("  status:  %s — offline or credentials unavailable.", c.paint("33", "could not fetch"))
		return
	}
	head, _ := gitRun(l, dir, "rev-parse", "--verify", "--quiet", "HEAD")
	target, err := gitRun(l, dir, "rev-parse", "--verify", "--quiet", "origin/"+ref+"^{commit}")
	if err != nil || target == "" {
		target, _ = gitRun(l, dir, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	}
	if target != "" && head != target {
		behind, err := gitRun(l, dir, "rev-list", "--count", head+".."+target)
		if err != nil {
			behind = "?"
		}
		c.out("  status:  %s — run 'sandbox link sync'.", c.paint("33", behind+" commit(s) behind '"+ref+"'"))
	} else {
		c.out("  status:  %s with '%s'.", c.paint("32", "up to date"), ref)
	}
}

func linkSync(c *cmdCtx, args []string) {
	ref := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if v, ok := flagValue(c, args, &i, "--ref"); ok {
			ref = v
			continue
		}
		switch {
		case a == "--help" || a == "-h":
			c.usage("usage_link")
		case strings.HasPrefix(a, "-"):
			c.die("Unknown option for 'link sync': %s", a)
		default:
			c.die("Unexpected argument: %s", a)
		}
	}
	l := c.link()
	if !l.IsActive() {
		c.die("No linked overlay to sync. Link one with: sandbox link <GIT-URL>")
	}
	c.requireGit(l)
	dir := c.activeDir(l)
	if dir == "" {
		c.die("Linked overlay directory is missing or not a git clone; re-run 'sandbox link <GIT-URL>'.")
	}
	if st, _ := gitRun(l, dir, "status", "--porcelain"); st != "" {
		c.die("Linked overlay has local uncommitted changes at %s; refusing to overwrite them. Commit, stash, or discard them first.", c.tilde(dir))
	}
	if ref == "" {
		ref = l.Ref()
	}
	if ref == "" {
		c.die("No ref recorded for the link; pass --ref <TAG|BRANCH|COMMIT>.")
	}
	c.out("==> Fetching")
	if exec.Command(l.Git, "-C", dir, "fetch", "--quiet", "--tags", "origin").Run() != nil {
		c.die("git fetch failed (offline or credentials unavailable).")
	}
	old, _ := gitRun(l, dir, "rev-parse", "--verify", "--quiet", "HEAD")
	target, err := gitRun(l, dir, "rev-parse", "--verify", "--quiet", "origin/"+ref+"^{commit}")
	if err != nil || target == "" {
		target, _ = gitRun(l, dir, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	}
	if target == "" {
		c.die("ref '%s' did not resolve to a commit after fetch.", ref)
	}
	if old == target {
		l.WriteConfig(dir, l.URL(), ref, target)
		c.out("Already up to date with '%s' (%s).", ref, short12(target))
		return
	}
	c.out("==> Changes from %s to %s (%s):", short12(old), short12(target), ref)
	if stat, err := gitRun(l, dir, "--no-pager", "diff", "--stat", old, target); err == nil && stat != "" {
		c.out("%s", stat)
	}
	gitRun(l, dir, "checkout", "--quiet", ref)
	rollback := func() { gitRun(l, dir, "reset", "--hard", "--quiet", old) }
	reset := exec.Command(l.Git, "-C", dir, "reset", "--hard", "--quiet", target)
	reset.Stderr = c.stderr
	if reset.Run() != nil {
		rollback()
		c.die("Failed to advance the overlay to %s; left at %s.", short12(target), short12(old))
	}
	c.out("==> Validating overlay shape")
	v := l.ValidateShape(dir)
	for _, s := range v.Stderr {
		fmt.Fprintln(c.stderr, s)
	}
	if !v.OK {
		rollback()
		c.die("New overlay tree (%s @ %s) failed validation; rolled back to %s.", ref, short12(target), short12(old))
	}
	unmet, warns := config.OverlayMinVersionUnmet(dir, c.env.Version.Version)
	for _, w := range warns {
		c.warn("%s", w)
	}
	if unmet != "" {
		rollback()
		c.die("New overlay tree (%s @ %s) requires agent-sandboxes >= %s, but this is %s; rolled back to %s. Run 'sandbox upgrade', then sync again.", ref, short12(target), unmet, c.env.version(), short12(old))
	}
	l.WriteConfig(dir, l.URL(), ref, target)
	os.WriteFile(dir+"/.git/sandbox-last-fetch", nil, 0o666)
	c.out("Updated overlay to '%s' (%s).", ref, short12(target))
}

func linkUnlink(c *cmdCtx, args []string) {
	keep, yes := false, false
	for _, a := range args {
		switch {
		case a == "--help" || a == "-h":
			c.usage("usage_link")
		case a == "--keep-clone":
			keep = true
		case a == "--yes" || a == "-y":
			yes = true
		case strings.HasPrefix(a, "-"):
			c.die("Unknown option for 'link unlink': %s", a)
		default:
			c.die("Unexpected argument: %s", a)
		}
	}
	l := c.link()
	if !l.IsActive() {
		c.out("No linked overlay to remove.")
		return
	}
	dir := c.activeDir(l)
	if !yes {
		suffix := " and delete its clone"
		if keep {
			suffix = ""
		}
		fmt.Fprintf(c.stdout, "Unlink overlay '%s'%s? [y/N] ", l.URL(), suffix)
		switch c.readLine() {
		case "y", "Y", "yes", "YES":
		default:
			c.out("Aborted.")
			return
		}
	}
	l.ClearConfig(dir)
	if !keep && dir != "" && isDir(dir) {
		os.RemoveAll(dir)
		c.out("Removed clone %s.", c.tilde(dir))
	}
	c.out("Unlinked. The 'overlay:'/link keys were cleared from %s.", c.tilde(c.env.UserConfig))
}
