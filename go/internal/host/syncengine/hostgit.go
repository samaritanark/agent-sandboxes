package syncengine

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/gitref"
	"github.com/samaritanark/agent-sandboxes/go/internal/syncproto"
)

// hostGit is the host repository's git directory as the VM copy sees it: one directory, ".git/",
// in the VM. On the host that is the repository's .git directory, or, for a linked worktree
// (git worktree add) or a submodule checkout, the worktree's own git directory for its HEAD,
// index, and other per-worktree files plus the common directory it shares for objects, refs,
// and config. The VM copy is always an ordinary repository.
type hostGit struct {
	wt, common *os.Root
	gitDir     string // absolute
	commonDir  string // absolute; == gitDir unless this is a linked worktree
}

func openHostGit(repo *gitref.Repo) (*hostGit, error) {
	common, err := os.OpenRoot(repo.CommonDir)
	if err != nil {
		return nil, err
	}
	g := &hostGit{common: common, wt: common, gitDir: repo.GitDir, commonDir: repo.CommonDir}
	if g.linked() {
		if g.wt, err = os.OpenRoot(repo.GitDir); err != nil {
			common.Close()
			return nil, err
		}
	}
	return g, nil
}

func (g *hostGit) linked() bool { return !sameDir(g.gitDir, g.commonDir) }

// sameDir compares directories by identity, so a symlink in either path does not matter.
func sameDir(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}

func (g *hostGit) Close() {
	if g.wt != g.common {
		g.wt.Close()
	}
	g.common.Close()
}

// perWorktree reports whether rel (a path inside a git directory) belongs to one worktree rather
// than to the common directory: git's own rule (path.c, common_list).
func perWorktree(rel string) bool {
	under := func(dir string) bool { return rel == dir || strings.HasPrefix(rel, dir+"/") }
	for _, d := range []string{"logs/HEAD", "logs/refs/bisect", "logs/refs/rewritten", "logs/refs/worktree",
		"refs/bisect", "refs/rewritten", "refs/worktree", "info/sparse-checkout"} {
		if under(d) {
			return true
		}
	}
	for _, d := range []string{"branches", "common", "hooks", "info", "logs", "lost-found", "objects", "refs",
		"remotes", "worktrees", "rr-cache", "svn"} {
		if under(d) {
			return false
		}
	}
	switch rel {
	case "config", "gc.pid", "packed-refs", "shallow":
		return false
	}
	return true
}

// linkage files of a linked worktree's git directory: how it finds the rest, never synced.
func linkage(rel string) bool { return rel == "commondir" || rel == "gitdir" || rel == "locked" }

// loc maps a VM path (".git/...") to the host directory and path that hold it.
func (g *hostGit) loc(p string) (*os.Root, string, error) {
	rel, ok := strings.CutPrefix(p, ".git/")
	if !ok || rel == "" {
		return nil, "", fmt.Errorf("%s is not a .git path", p)
	}
	if g.linked() && perWorktree(rel) {
		return g.wt, rel, nil
	}
	return g.common, rel, nil
}

func (g *hostGit) ReadFile(p string) ([]byte, error) {
	r, rel, err := g.loc(p)
	if err != nil {
		return nil, err
	}
	return r.ReadFile(rel)
}

func (g *hostGit) writeAtomic(p string, data []byte) error {
	r, rel, err := g.loc(p)
	if err != nil {
		return err
	}
	return writeFileAtomic(r, rel, data, 0o644)
}

func (g *hostGit) writeObject(p string, data []byte) error {
	r, rel, err := g.loc(p)
	if err != nil {
		return err
	}
	return writeObject(r, rel, data)
}

// scan fingerprints the git directory as the VM sees it (objects by name only). Other worktrees'
// administrative files (worktrees/) are left out: they describe host paths and are not this
// copy's business.
func (g *hostGit) scan() map[string]string {
	out := map[string]string{}
	walk := func(r *os.Root, keep func(rel string) bool) {
		fs.WalkDir(r.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
			if err != nil || rel == "." {
				return nil
			}
			if d.IsDir() {
				if rel == "worktrees" {
					return fs.SkipDir
				}
				return nil
			}
			if !keep(rel) {
				return nil
			}
			p := path.Join(".git", rel)
			if syncproto.IsObjectPath(p) {
				out[p] = syncproto.ObjectFP
				return nil
			}
			if f, _, err := hostFP(r, rel); err == nil {
				out[p] = f
			}
			return nil
		})
	}
	if !g.linked() {
		walk(g.common, func(string) bool { return true })
		return out
	}
	walk(g.common, func(rel string) bool { return !perWorktree(rel) })
	walk(g.wt, func(rel string) bool { return perWorktree(rel) && !linkage(rel) })
	return out
}

// otherWorktreeBranches are the branches checked out in the repository's other worktrees. The
// VM must not move them: that worktree's index and files would no longer match its HEAD.
func (g *hostGit) otherWorktreeBranches() []string {
	var heads []string
	read := func(r *os.Root, rel string) {
		b, err := r.ReadFile(rel)
		if err != nil {
			return
		}
		if ref, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "ref: "); ok && strings.HasPrefix(ref, "refs/heads/") {
			heads = append(heads, ref)
		}
	}
	if g.linked() {
		read(g.common, "HEAD") // the main worktree
	}
	entries, _ := fs.ReadDir(g.common.FS(), "worktrees")
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if sameDir(filepath.Join(g.commonDir, "worktrees", e.Name()), g.gitDir) {
			continue // this worktree
		}
		read(g.common, path.Join("worktrees", e.Name(), "HEAD"))
	}
	return heads
}
