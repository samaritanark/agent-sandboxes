// Package mounts holds the workspace mount rules of a Tier 2/3 session: which paths in each repo
// are masked (an empty file over a sensitive file, an empty directory over a directory) and which
// host-exec vectors are mounted read-only. It is the decision half of v2's pod-manifest volume
// builders (lib/manifest.sh build_volume_mounts_block, _readonly_workspace_entries) and the tables
// in lib/filesystem.sh; in v3 the session spec carries the result to sandboxd (design 5.4.2), and
// the host-side sync gate shares the tables (5.4.1). Rendering Kubernetes volumes is not ported.
package mounts

import (
	"os"
	"sort"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/gate"
)

// ReadonlyPath is one READONLY_WORKSPACE_PATHS entry: a workspace-relative path and whether it is
// a directory.
type ReadonlyPath struct {
	Rel string
	Dir bool
}

// ReadonlyPaths is READONLY_WORKSPACE_PATHS (lib/filesystem.sh): git's config and hooks,
// submodules, and editor and devcontainer config, which the operator's own tools would execute.
var ReadonlyPaths = []ReadonlyPath{{".git/config", false}, {".git/hooks", true}, {".gitmodules", false},
	{".vscode", true}, {".idea", true}, {".devcontainer", true}}

// Kind is what a mount does.
type Kind int

const (
	MaskFile     Kind = iota // an empty file over a sensitive file
	MaskDir                  // an empty directory over a sensitive directory
	ReadonlyFile             // the real file, read-only
	ReadonlyDir              // the real directory, read-only
)

// Mount is one overlay in one repo. Index is the entry's position in its list: the line of a
// configured masked_paths entry (MaskDir from masked_paths), or the READONLY_WORKSPACE_PATHS index
// of a read-only one (len(ReadonlyPaths) for a .git pointer file); -1 otherwise.
type Mount struct {
	Repo  int
	Rel   string
	Kind  Kind
	Index int
	Kube  bool // the .kube directory mask (MaskedDirPath)
}

func isFile(p string) bool { st, err := os.Stat(p); return err == nil && st.Mode().IsRegular() }
func isDir(p string) bool  { st, err := os.Stat(p); return err == nil && st.IsDir() }

// openrcFiles is `find REPO -maxdepth 1 -name '*-openrc.sh' -type f | sort`: regular files (not
// links) directly in the repo, by name.
func openrcFiles(repo string) []string {
	ents, err := os.ReadDir(repo)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.Type().IsRegular() && bashcompat.Glob(gate.MaskedOpenrcPattern, e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// Masks is one repo's masks, in v2's mount order: the fixed sensitive files that exist ([[ -f ]],
// which follows a link), the *-openrc.sh files, the repo's configured masked_paths (a trailing
// slash is a directory; each entry only when it exists as that type), then .kube when it is a
// directory.
func Masks(i int, repo string) []Mount {
	var out []Mount
	for _, p := range gate.MaskedFilePaths {
		if isFile(repo + "/" + p) {
			out = append(out, Mount{Repo: i, Rel: p, Kind: MaskFile, Index: -1})
		}
	}
	for _, f := range openrcFiles(repo) {
		out = append(out, Mount{Repo: i, Rel: f, Kind: MaskFile, Index: -1})
	}
	for idx, mp := range config.LoadRepoMaskedPaths(repo) {
		switch {
		case mp == "":
		case strings.HasSuffix(mp, "/"):
			if isDir(repo + "/" + strings.TrimSuffix(mp, "/")) {
				out = append(out, Mount{Repo: i, Rel: strings.TrimSuffix(mp, "/"), Kind: MaskDir, Index: idx})
			}
		default:
			if isFile(repo + "/" + mp) {
				out = append(out, Mount{Repo: i, Rel: mp, Kind: MaskFile, Index: -1})
			}
		}
	}
	if isDir(repo + "/" + gate.MaskedDirPath) {
		out = append(out, Mount{Repo: i, Rel: gate.MaskedDirPath, Kind: MaskDir, Index: -1, Kube: true})
	}
	return out
}

// Readonly is _readonly_workspace_entries: each READONLY_WORKSPACE_PATHS entry that exists as its
// kind (following a link), then .git when it is a regular file (a linked worktree's or a
// submodule's pointer, which the agent must not repoint).
func Readonly(i int, repo string) []Mount {
	var out []Mount
	for idx, p := range ReadonlyPaths {
		full := repo + "/" + p.Rel
		switch {
		case !p.Dir && isFile(full):
			out = append(out, Mount{Repo: i, Rel: p.Rel, Kind: ReadonlyFile, Index: idx})
		case p.Dir && isDir(full):
			out = append(out, Mount{Repo: i, Rel: p.Rel, Kind: ReadonlyDir, Index: idx})
		}
	}
	if isFile(repo + "/.git") {
		out = append(out, Mount{Repo: i, Rel: ".git", Kind: ReadonlyFile, Index: len(ReadonlyPaths)})
	}
	return out
}

// MountPath is _workspace_mount_path: /workspace for one repo, /workspace/<basename> for several.
func MountPath(repo string, total int) string {
	if total == 1 {
		return "/workspace"
	}
	return "/workspace/" + bashcompat.Basename(repo)
}
