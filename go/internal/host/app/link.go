package app

// `sandbox link` on the host (design 5.1.3): the overlay clone lives in ~/.sandbox/overlays/<name>
// on this machine, fetched with the operator's own git and credentials (a private overlay repo
// needs them), and its tree goes to the VM with the operator state as the local overlay (hidden
// files, .git among them, are not pushed). The VM validates the tree's shape and minimum version
// (__link-check); the host records the link in ~/.sandbox/config.yaml (overlay, link_url,
// link_ref, link_commit), as v2 did, and runs the run-path sync before each launch.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/opstate"
)

// LinkedOverlaysDir is where in ~/.sandbox the linked clones live ($LINK_OVERLAYS_DIR).
const LinkedOverlaysDir = "overlays"

// LinkCheckCmd is the VM's half (cli.LinkCheck) and its exit status for an overlay that needs a
// newer sandbox.
const (
	LinkCheckCmd          = "__link-check"
	linkCheckNeedsVersion = 3
)

var linkNameChars = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func validLinkName(n string) bool {
	return n != "" && !strings.Contains(n, "/") && !strings.Contains(n, "..") && !strings.HasPrefix(n, ".") && linkNameChars.MatchString(n)
}

// linkNameFromURL is link_name_from_url.
func linkNameFromURL(url string) string {
	b := strings.TrimSuffix(url, "/")
	if i := strings.LastIndex(b, "/"); i >= 0 {
		b = b[i+1:]
	}
	if i := strings.LastIndex(b, ":"); i >= 0 {
		b = b[i+1:]
	}
	b = strings.TrimSuffix(b, ".git")
	if validLinkName(b) {
		return b
	}
	return ""
}

func (a *app) link(args []string) int {
	if len(args) == 0 {
		return a.proxy(append([]string{"link"}, args...)) // v2's usage
	}
	switch args[0] {
	case "--help", "-h", "help":
		return a.proxy(append([]string{"link"}, args...))
	case "status":
		return a.linkStatus(args[1:])
	case "sync":
		return a.linkSync(args[1:])
	case "unlink":
		return a.linkUnlink(args[1:])
	}
	return a.linkClone(args)
}

// userConfig is ~/.sandbox/config.yaml.
func (a *app) userConfig() string { return filepath.Join(a.env.StateDir, "config.yaml") }

// configScalar is extract_yaml_scalar for one top-level key of ~/.sandbox/config.yaml.
func (a *app) configScalar(key string) string {
	b, err := os.ReadFile(a.userConfig())
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `:[ \t]*([^\n]*)`)
	m := re.FindSubmatch(b)
	if m == nil {
		return ""
	}
	v := string(m[1])
	if i := strings.Index(v, " #"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(strings.NewReplacer(`"`, "", `'`, "").Replace(v))
}

// setConfig writes the link's keys into ~/.sandbox/config.yaml (config_upsert_yaml_scalar for
// each; a value "" removes the key), replacing the file whole.
func (a *app) setConfig(kv [][2]string) error {
	b, err := os.ReadFile(a.userConfig())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(b) == 0 {
		lines = nil
	}
	for _, p := range kv {
		key, val := p[0], p[1]
		if strings.ContainsAny(val, "\n\r\x00") {
			return fmt.Errorf("%s: a value with a line break", key)
		}
		var out []string
		done := false
		for _, l := range lines {
			if strings.HasPrefix(l, key+":") {
				if val != "" && !done {
					out = append(out, key+": "+val)
				}
				done = true
				continue
			}
			out = append(out, l)
		}
		if !done && val != "" {
			out = append(out, key+": "+val)
		}
		lines = out
	}
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	if err := os.MkdirAll(a.env.StateDir, 0o700); err != nil {
		return err
	}
	tmp := a.userConfig() + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.userConfig())
}

func (a *app) tilde(p string) string {
	if a.env.Home != "" && strings.HasPrefix(p, a.env.Home+"/") {
		return "~" + p[len(a.env.Home):]
	}
	return p
}

// git runs the operator's git (never in a repository a session shaped: a linked clone is fetched
// on this machine only).
func (a *app) git(dir string, args ...string) (string, error) {
	if a.env.Git != nil {
		return a.env.Git(dir, args...)
	}
	cmd := exec.CommandContext(a.ctx, "git", append([]string{"-C", dir}, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		err = fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimRight(out.String(), "\n"), err
}

func (a *app) gitFetch(dir string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(a.ctx, timeout)
	defer cancel()
	if a.env.Git != nil {
		_, err := a.env.Git(dir, "fetch", "--quiet", "--tags", "origin")
		return err
	}
	return exec.CommandContext(ctx, "git", "-C", dir, "fetch", "--quiet", "--tags", "origin").Run()
}

func (a *app) requireGit() {
	if a.env.Git != nil {
		return
	}
	if _, err := exec.LookPath("git"); err != nil {
		a.die("git is required for 'sandbox link' (it clones and fetches the overlay on this machine).")
	}
}

// linkCheck pushes the operator state with dir as the local overlay and has the VM validate it.
// It returns the VM's exit status and, for linkCheckNeedsVersion, the version the overlay needs.
func (a *app) linkCheck(ep driver.SSHEndpoint, dir string) (int, string) {
	archive, warnings, err := opstate.BuildWith(a.env.StateDir, dir)
	if err != nil {
		a.die("cannot collect the overlay for the sandbox VM: %v", err)
	}
	for _, w := range warnings {
		fmt.Fprintf(a.env.Stderr, "WARNING: %s\n", w)
	}
	argv := []string{VMCommand, ReceiveOperatorState}
	if h := a.mirrorHome(); h != "" {
		argv = append(argv, h)
	}
	var errb strings.Builder
	if rc, err := a.env.Transport.Run(a.ctx, ep, argv, bytes.NewReader(archive), io.Discard, &errb, false); err != nil || rc != 0 {
		a.die("could not push the overlay to the sandbox VM: %v %s", err, strings.TrimSpace(errb.String()))
	}
	pushed := opstate.OverlayLocal
	if h := a.mirrorHome(); h != "" {
		pushed = h + "/.sandbox/" + opstate.OverlayLocal
	}
	var out bytes.Buffer
	rc, err := a.env.Transport.Run(a.ctx, ep, a.vmArgvEnv(nil, LinkCheckCmd, pushed), nil, &out, a.env.Stderr, false)
	if err != nil {
		a.die("cannot validate the overlay in the sandbox VM: %v", err)
	}
	return rc, strings.TrimSpace(out.String())
}

func (a *app) linkClone(args []string) int {
	url, name, ref := "", "", ""
	for i := 0; i < len(args); i++ {
		switch v := args[i]; {
		case (v == "--name" || v == "--ref") && i+1 < len(args):
			if v == "--name" {
				name = args[i+1]
			} else {
				ref = args[i+1]
			}
			i++
		case strings.HasPrefix(v, "--name="):
			name = v[len("--name="):]
		case strings.HasPrefix(v, "--ref="):
			ref = v[len("--ref="):]
		case strings.HasPrefix(v, "-"):
			a.die("Unknown option for 'link': %s. Run 'sandbox link --help'.", v)
		default:
			if url != "" {
				a.die("Unexpected argument: %s", v)
			}
			url = v
		}
	}
	if url == "" {
		a.die("Usage: sandbox link <GIT-URL> [--name <NAME>] [--ref <REF>]")
	}
	a.requireGit()
	if cur := a.configScalar("link_url"); cur != "" {
		a.die("A link is already active (%s). Run 'sandbox link unlink' first, or 'sandbox link sync' to update it.", cur)
	}
	if name == "" {
		if name = linkNameFromURL(url); name == "" {
			a.die("Could not derive a link name from '%s'. Pass --name <NAME>.", url)
		}
	}
	if !validLinkName(name) {
		a.die("Invalid link name '%s'. Use letters, digits, '.', '_', '-'; no '/', no leading '.'.", name)
	}
	dir := filepath.Join(a.env.StateDir, LinkedOverlaysDir, name)
	if _, err := os.Lstat(dir); err == nil {
		a.die("%s already exists. Choose another --name or remove it.", a.tilde(dir))
	}
	if ov := a.configScalar("overlay"); ov != "" {
		fmt.Fprintf(a.env.Stderr, "WARN: existing 'overlay: %s' will be repointed at the linked clone.\n", ov)
	}
	ep := a.running()
	a.handshake(ep)
	fmt.Fprintf(a.env.Stdout, "==> Cloning %s\n", url)
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		a.die("%v", err)
	}
	if _, err := a.git(filepath.Dir(dir), "clone", "--quiet", "--", url, dir); err != nil {
		os.RemoveAll(dir)
		a.die("git clone failed. Check the URL and your git credentials for private repos. (%v)", err)
	}
	if ref != "" {
		if _, err := a.git(dir, "checkout", "--quiet", ref); err != nil {
			os.RemoveAll(dir)
			a.die("ref '%s' not found in %s.", ref, url)
		}
	} else if r, err := a.git(dir, "rev-parse", "--abbrev-ref", "HEAD"); err == nil && r != "" {
		ref = r
	} else {
		ref = "HEAD"
	}
	commit, _ := a.git(dir, "rev-parse", "--verify", "--quiet", "HEAD")
	fmt.Fprintln(a.env.Stdout, "==> Validating overlay shape")
	switch rc, need := a.linkCheck(ep, dir); rc {
	case 0:
	case linkCheckNeedsVersion:
		os.RemoveAll(dir)
		a.pushState(ep)
		a.die("overlay at '%s' (%s) requires agent-sandboxes >= %s, but the sandbox VM's is older. Upgrade the VM first (sandbox upgrade), then re-link.", url, ref, need)
	default:
		os.RemoveAll(dir)
		a.pushState(ep)
		a.die("overlay at '%s' (%s) failed validation; nothing was linked.", url, ref)
	}
	if err := a.setConfig([][2]string{{"overlay", dir}, {"link_url", url}, {"link_ref", ref}, {"link_commit", commit}}); err != nil {
		a.die("could not record the link in %s: %v", a.tilde(a.userConfig()), err)
	}
	fmt.Fprintf(a.env.Stdout, "Linked overlay '%s' → %s\n", name, a.tilde(dir))
	fmt.Fprintf(a.env.Stdout, "  ref:    %s\n", ref)
	fmt.Fprintf(a.env.Stdout, "  commit: %s\n", short(commit))
	fmt.Fprintf(a.env.Stdout, "  pointer written to the 'overlay:' key in %s\n", a.tilde(a.userConfig()))
	return 0
}

// linkedDir is the active link's clone: the overlay pointer when a link is active and it is a git
// working tree (link_active_dir).
func (a *app) linkedDir() string {
	if a.configScalar("link_url") == "" {
		return ""
	}
	d := a.configScalar("overlay")
	if strings.HasPrefix(d, "~") && a.env.Home != "" {
		d = a.env.Home + d[1:]
	}
	if d == "" {
		return ""
	}
	if st, err := os.Lstat(filepath.Join(d, ".git")); err == nil && st.IsDir() {
		return d
	}
	return ""
}

func (a *app) linkStatus(args []string) int {
	if len(args) > 0 {
		return a.proxy(append([]string{"link", "status"}, args...))
	}
	url := a.configScalar("link_url")
	if url == "" {
		fmt.Fprintln(a.env.Stdout, "No linked overlay. Link one with: sandbox link <GIT-URL>")
		return 0
	}
	a.requireGit()
	ref, dir := a.configScalar("link_ref"), a.linkedDir()
	fmt.Fprintln(a.env.Stdout, "Linked overlay")
	fmt.Fprintf(a.env.Stdout, "  %-8s %s\n  %-8s %s\n  %-8s %s\n", "url:", url, "ref:", ref, "commit:", a.configScalar("link_commit"))
	if dir == "" {
		fmt.Fprintln(a.env.Stderr, "WARN: recorded overlay pointer is not a git clone; the link record may be stale.")
		return 0
	}
	fmt.Fprintf(a.env.Stdout, "  %-8s %s\n", "path:", a.tilde(dir))
	if a.gitFetch(dir, a.linkFetchTimeout()) != nil {
		fmt.Fprintln(a.env.Stdout, "  status:  could not fetch — offline or credentials unavailable.")
		return 0
	}
	head, _ := a.git(dir, "rev-parse", "--verify", "--quiet", "HEAD")
	target := a.linkTarget(dir, ref)
	if target != "" && head != target {
		behind, err := a.git(dir, "rev-list", "--count", head+".."+target)
		if err != nil {
			behind = "?"
		}
		fmt.Fprintf(a.env.Stdout, "  status:  %s commit(s) behind '%s' — run 'sandbox link sync'.\n", behind, ref)
	} else {
		fmt.Fprintf(a.env.Stdout, "  status:  up to date with '%s'.\n", ref)
	}
	return 0
}

func (a *app) linkTarget(dir, ref string) string {
	t, err := a.git(dir, "rev-parse", "--verify", "--quiet", "origin/"+ref+"^{commit}")
	if err != nil || t == "" {
		t, _ = a.git(dir, "rev-parse", "--verify", "--quiet", ref+"^{commit}")
	}
	return t
}

func (a *app) linkFetchTimeout() time.Duration {
	if n, err := strconv.Atoi(a.getenv("LINK_FETCH_TIMEOUT_SECONDS")); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 10 * time.Second
}

// advance moves the clone from old to target, validates it in the VM, and records it; on failure
// it rolls back (and pushes the rolled-back tree) and returns why.
func (a *app) advance(ep driver.SSHEndpoint, dir, ref, old, target string) (string, error) {
	a.git(dir, "checkout", "--quiet", ref)
	rollback := func() {
		a.git(dir, "reset", "--hard", "--quiet", old)
		a.linkCheck(ep, dir)
	}
	if _, err := a.git(dir, "reset", "--hard", "--quiet", target); err != nil {
		rollback()
		return "", fmt.Errorf("failed to advance the overlay to %s; left at %s", short(target), short(old))
	}
	switch rc, need := a.linkCheck(ep, dir); rc {
	case 0:
	case linkCheckNeedsVersion:
		rollback()
		return need, fmt.Errorf("new overlay tree (%s @ %s) requires agent-sandboxes >= %s, but the sandbox VM's is older; rolled back to %s", ref, short(target), need, short(old))
	default:
		rollback()
		return "", fmt.Errorf("new overlay tree (%s @ %s) failed validation; rolled back to %s", ref, short(target), short(old))
	}
	if err := a.setConfig([][2]string{{"overlay", dir}, {"link_url", a.configScalar("link_url")}, {"link_ref", ref}, {"link_commit", target}}); err != nil {
		return "", err
	}
	return "", nil
}

func (a *app) linkSync(args []string) int {
	ref := ""
	for i := 0; i < len(args); i++ {
		switch v := args[i]; {
		case v == "--ref" && i+1 < len(args):
			ref = args[i+1]
			i++
		case strings.HasPrefix(v, "--ref="):
			ref = v[len("--ref="):]
		case strings.HasPrefix(v, "-"):
			if v == "--help" || v == "-h" {
				return a.proxy([]string{"link", "--help"})
			}
			a.die("Unknown option for 'link sync': %s", v)
		default:
			a.die("Unexpected argument: %s", v)
		}
	}
	if a.configScalar("link_url") == "" {
		a.die("No linked overlay to sync. Link one with: sandbox link <GIT-URL>")
	}
	a.requireGit()
	dir := a.linkedDir()
	if dir == "" {
		a.die("Linked overlay directory is missing or not a git clone; re-run 'sandbox link <GIT-URL>'.")
	}
	if st, _ := a.git(dir, "status", "--porcelain"); st != "" {
		a.die("Linked overlay has local uncommitted changes at %s; refusing to overwrite them. Commit, stash, or discard them first.", a.tilde(dir))
	}
	if ref == "" {
		ref = a.configScalar("link_ref")
	}
	if ref == "" {
		a.die("No ref recorded for the link; pass --ref <TAG|BRANCH|COMMIT>.")
	}
	ep := a.running()
	a.handshake(ep)
	fmt.Fprintln(a.env.Stdout, "==> Fetching")
	if a.gitFetch(dir, 5*time.Minute) != nil {
		a.die("git fetch failed (offline or credentials unavailable).")
	}
	old, _ := a.git(dir, "rev-parse", "--verify", "--quiet", "HEAD")
	target := a.linkTarget(dir, ref)
	if target == "" {
		a.die("ref '%s' did not resolve to a commit after fetch.", ref)
	}
	if old == target {
		a.setConfig([][2]string{{"link_ref", ref}, {"link_commit", target}})
		fmt.Fprintf(a.env.Stdout, "Already up to date with '%s' (%s).\n", ref, short(target))
		return 0
	}
	fmt.Fprintf(a.env.Stdout, "==> Changes from %s to %s (%s):\n", short(old), short(target), ref)
	if stat, err := a.git(dir, "--no-pager", "diff", "--stat", old, target); err == nil && stat != "" {
		fmt.Fprintln(a.env.Stdout, stat)
	}
	fmt.Fprintln(a.env.Stdout, "==> Validating overlay shape")
	if _, err := a.advance(ep, dir, ref, old, target); err != nil {
		a.die("%v.", err)
	}
	fmt.Fprintf(a.env.Stdout, "Updated overlay to '%s' (%s).\n", ref, short(target))
	return 0
}

func (a *app) linkUnlink(args []string) int {
	keep, yes := false, false
	for _, v := range args {
		switch v {
		case "--keep-clone":
			keep = true
		case "--yes", "-y":
			yes = true
		case "--help", "-h":
			return a.proxy([]string{"link", "--help"})
		default:
			if strings.HasPrefix(v, "-") {
				a.die("Unknown option for 'link unlink': %s", v)
			}
			a.die("Unexpected argument: %s", v)
		}
	}
	url := a.configScalar("link_url")
	if url == "" {
		fmt.Fprintln(a.env.Stdout, "No linked overlay to remove.")
		return 0
	}
	dir := a.linkedDir()
	if !yes {
		suffix := " and delete its clone"
		if keep {
			suffix = ""
		}
		fmt.Fprintf(a.env.Stdout, "Unlink overlay '%s'%s? [y/N] ", url, suffix)
		line, _ := readLine(a.env.Stdin)
		if l := strings.TrimSpace(line); l != "y" && l != "Y" && l != "yes" && l != "YES" {
			fmt.Fprintln(a.env.Stdout, "Aborted.")
			return 0
		}
	}
	kv := [][2]string{{"link_url", ""}, {"link_ref", ""}, {"link_commit", ""}}
	if cur := a.configScalar("overlay"); dir != "" && (cur == dir || strings.HasPrefix(cur, "~") && a.env.Home+cur[1:] == dir) {
		kv = append([][2]string{{"overlay", ""}}, kv...)
	}
	if err := a.setConfig(kv); err != nil {
		a.die("%v", err)
	}
	if !keep && dir != "" {
		if rel, err := filepath.Rel(filepath.Join(a.env.StateDir, LinkedOverlaysDir), dir); err == nil && !strings.HasPrefix(rel, "..") && !strings.Contains(rel, "/") {
			os.RemoveAll(dir)
			fmt.Fprintf(a.env.Stdout, "Removed clone %s.\n", a.tilde(dir))
		}
	}
	fmt.Fprintf(a.env.Stdout, "Unlinked. The 'overlay:'/link keys were cleared from %s.\n", a.tilde(a.userConfig()))
	return 0
}

func readLine(r io.Reader) (string, error) {
	if r == nil {
		return "", io.EOF
	}
	var b [1]byte
	var out []byte
	for {
		n, err := r.Read(b[:])
		if n == 1 {
			if b[0] == '\n' {
				return string(out), nil
			}
			out = append(out, b[0])
		}
		if err != nil {
			return string(out), err
		}
	}
}

// linkSyncOnRun is link_sync_on_run on the host: before a launch, advance the linked overlay to its
// ref's tip, have the VM validate it, and record it; offline, a dirty clone, or an invalid tree
// warns and keeps the current commit; an overlay that needs a newer sandbox rolls back and stops
// the launch.
func (a *app) linkSyncOnRun(ep driver.SSHEndpoint) {
	if a.getenv("SANDBOX_NO_LINK_CHECK") != "" {
		return
	}
	dir, ref := a.linkedDir(), a.configScalar("link_ref")
	if dir == "" || ref == "" {
		return
	}
	if a.env.Git == nil {
		if _, err := exec.LookPath("git"); err != nil {
			return
		}
	}
	head, _ := a.git(dir, "rev-parse", "--verify", "--quiet", "HEAD")
	if a.gitFetch(dir, a.linkFetchTimeout()) != nil {
		fmt.Fprintf(a.env.Stderr, "WARN: linked overlay: could not fetch '%s' — launching from the current commit %s.\n", a.configScalar("link_url"), short(head))
		return
	}
	target := a.linkTarget(dir, ref)
	if head == "" || target == "" || head == target {
		return
	}
	if st, _ := a.git(dir, "status", "--porcelain"); st != "" {
		fmt.Fprintf(a.env.Stderr, "WARN: linked overlay is behind '%s' but has local uncommitted edits at %s; not auto-syncing. Commit, stash, or discard them, then run 'sandbox link sync'.\n", ref, a.tilde(dir))
		return
	}
	fmt.Fprintf(a.env.Stdout, "==> Syncing linked overlay to '%s' (%s -> %s)\n", ref, short(head), short(target))
	if stat, err := a.git(dir, "--no-pager", "diff", "--stat", head, target); err == nil && stat != "" {
		fmt.Fprintln(a.env.Stdout, stat)
	}
	need, err := a.advance(ep, dir, ref, head, target)
	switch {
	case err != nil && need != "":
		a.die("linked overlay '%s' now requires agent-sandboxes >= %s. Upgrade the sandbox VM (sandbox upgrade), then launch again. (Rolled back to %s; SANDBOX_NO_LINK_CHECK=1 skips the run-path sync entirely.)", ref, need, short(head))
	case err != nil:
		fmt.Fprintf(a.env.Stderr, "WARN: %v — launching from %s. Review with 'sandbox link sync' once the overlay is fixed.\n", err, short(head))
	default:
		fmt.Fprintf(a.env.Stdout, "    linked overlay updated to '%s' (%s)\n", ref, short(target))
	}
}
