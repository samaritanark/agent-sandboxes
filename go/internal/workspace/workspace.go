// Package workspace is the repo-path half of lib/filesystem.sh outside the secret gate:
// validate_repo_path (which directories may be a workspace) and workspace_prescan (the warn-only
// filename heuristics).
package workspace

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

// Ctx is what the checks read: the environment, the install root (SANDBOX_ROOT), and whether the
// host is WSL.
type Ctx struct {
	config.Env
	SandboxRoot string
	IsWSL       bool
}

// ForbiddenPaths is FORBIDDEN_PATH_PATTERNS: credential directories never used as a workspace.
func (c Ctx) ForbiddenPaths() []string {
	h := c.Home
	return []string{h + "/.tsh", h + "/.kube", h + "/.ssh", h + "/.config/openstack", h + "/.aws",
		h + "/.config/gcloud", h + "/.azure"}
}

// realpath is GNU realpath's default mode: symlinks resolved, every component but the last must
// exist (ok is false otherwise).
func realpath(p string) (string, bool) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", false
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r, true
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", false
	}
	if _, err := os.Lstat(abs); err == nil {
		return "", false // it exists but could not be resolved (a symlink loop)
	}
	return filepath.Join(dir, filepath.Base(abs)), true
}

func realOr(p string) string {
	if r, ok := realpath(p); ok {
		return r
	}
	return p
}

// Refusal is validate_repo_path's refusal: the lines it prints before `exit 1`.
type Refusal struct{ Lines []string }

func (r *Refusal) Error() string { return strings.Join(r.Lines, "\n") }

func refuse(lines ...string) error { return &Refusal{Lines: lines} }

// ValidateRepoPath is validate_repo_path: nil when repo may be a workspace.
//
// With RepoPathCaseInsensitive the forbidden-directory, home, and overlap comparisons ignore case:
// macOS volumes do by default, and realpath keeps the case as typed, so `--repo ~/.SSH` passed and
// mounted ~/.ssh.
func (c Ctx) ValidateRepoPath(repo string) error {
	if st, err := os.Stat(repo); err != nil || !st.IsDir() {
		return refuse("ERROR: Repo path does not exist or is not a directory: "+repo, " ")
	}
	if exec.Command("git", "-C", repo, "rev-parse", "--git-dir").Run() != nil {
		return refuse("ERROR: Repo path is not a git repository: "+repo, "  Tier 2/3 requires a git repository.")
	}
	real, _ := realpath(repo)
	if c.IsWSL && strings.HasPrefix(real, "/mnt/") {
		b := bashcompat.Basename(repo)
		return refuse("ERROR: Windows-side repo path detected: "+repo,
			"  Paths under /mnt/ (Windows drives) cross the NTFS<->WSL boundary,",
			"  which makes Tier 2/3 sessions extremely slow. Clone the repo",
			"  inside the sandbox distro instead:",
			"    wsl -d sandbox-vm -- bash -c 'git clone <url> ~/repos/"+b+"'",
			"  Then re-run with --repo ~/repos/"+b)
	}
	fold := func(s string) string { return s }
	if deviation.Fixed(deviation.RepoPathCaseInsensitive) {
		fold = strings.ToLower
	}
	r := fold(real)
	under := func(p string) bool { return r == p || strings.HasPrefix(r, p+"/") }
	for _, f := range c.ForbiddenPaths() {
		if under(fold(realOr(f))) {
			return refuse("ERROR: Forbidden repo path: "+repo, "  '"+f+"' is not allowed as a workspace.")
		}
	}
	if h, _ := realpath(c.Home); r == fold(h) {
		return refuse("ERROR: Cannot use $HOME as workspace root.")
	}
	var protected []string
	if c.SandboxRoot != "" {
		protected = append(protected, c.SandboxRoot)
	}
	protected = append(protected, c.Home+"/.sandbox")
	if ov := config.ResolveOverlayPath(c.Env); ov != "" {
		protected = append(protected, ov)
	}
	for _, p := range protected {
		rp := fold(realOr(p))
		if under(rp) || strings.HasPrefix(rp, r+"/") {
			return refuse("ERROR: Workspace "+repo+" overlaps agent-sandboxes tooling or state: "+p,
				"  Mounting it into a pod would give the in-sandbox agent write access",
				"  to code or config that runs the next session. Use a separate repo.")
		}
	}
	return nil
}

// find is `find START -maxdepth 3 <match> -not -path '*/.git/*' -print0`: matching paths as find
// prints them, in walk order (os.ReadDir sorts names; GNU find uses directory order, so the corpus
// holds at most one match per search).
func find(start string, match func(name string) bool) []string {
	var out []string
	root := filepath.Clean(start)
	show := func(p string) string {
		if p == root {
			return start
		}
		rel := strings.TrimPrefix(p, root+"/")
		if strings.HasSuffix(start, "/") {
			return start + rel
		}
		return start + "/" + rel
	}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		depth := 0
		if p != root {
			depth = strings.Count(strings.TrimPrefix(p, root+"/"), "/") + 1
		}
		shown := show(p)
		if match(d.Name()) && !strings.Contains(shown, "/.git/") {
			out = append(out, shown)
		}
		if d.IsDir() && depth >= 3 {
			return filepath.SkipDir
		}
		return nil
	})
	return out
}

// credPatterns are workspace_prescan's credential-file name patterns.
var credPatterns = []string{"clouds.yaml", "kubeconfig", ".npmrc", "*-openrc.sh", "*.pem", "*.key", "*.pfx", "id_rsa", "id_ed25519"}

// Prescan is workspace_prescan: the lines it prints.
func Prescan(ws string) []string {
	out := []string{"  Scanning for sensitive files in: " + ws}
	issues := 0
	env := find(ws, func(n string) bool {
		return n == ".env" || bashcompat.Glob(".env.*", n) || bashcompat.Glob("*.env", n)
	})
	if len(env) > 0 {
		out = append(out, "  WARN: Found .env files (will be masked inside sandbox):")
		for _, f := range env {
			out = append(out, "    "+f)
		}
		issues++
	}
	for _, pat := range credPatterns {
		found := find(ws, func(n string) bool { return bashcompat.Glob(pat, n) })
		if len(found) > 0 {
			out = append(out, fmt.Sprintf("  WARN: Found potential credential file(s) matching '%s':", pat))
			for _, f := range found {
				out = append(out, "    "+f)
			}
			issues++
		}
	}
	if issues > 0 {
		out = append(out, "",
			fmt.Sprintf("  NOTICE: %d concern(s) found. Root-level matches of the masked", issues),
			"  set will be masked inside the sandbox; deeper matches and broader patterns",
			"  (.pem, .key, id_rsa, ...) are flagged for review but NOT masked —",
			"  remove or relocate them before launching if they contain real secrets.",
			"")
	} else {
		out = append(out, "  Pre-scan passed with no concerns.")
	}
	return out
}

// PathHasTrackedContent is path_has_tracked_content: relpath is in git's index, or in the history
// of any ref, so a mask hides the working copy only. Any git error reads as false (fails open; the
// result only decides whether to print an advisory).
func PathHasTrackedContent(repo, relpath string) bool {
	git := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", repo, "-c", "core.fsmonitor=", "-c", "core.hooksPath=/dev/null"}, args...)...)
		out, err := cmd.Output()
		if err != nil && len(out) == 0 {
			return ""
		}
		return string(out)
	}
	if strings.TrimSpace(firstLine(git("ls-files", "--", ":(literal)"+relpath))) != "" {
		return true
	}
	return strings.TrimRight(git("log", "--all", "-1", "--format=%H", "--", ":(literal)"+relpath), "\n") != ""
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i+1]
	}
	return s
}
