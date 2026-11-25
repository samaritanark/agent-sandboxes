package syncgate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/yamllist"
)

// RepoMaskedPaths reads the masked_paths: list from the host checkout's own .sandbox/config.yaml
// (the owner's decision, 2026-11-25: the host reads it itself, with the same reader the policy
// layer uses, because the VM's report of the list could be falsified). The file is read through
// os.Root without following a symlink; a symlinked, non-regular, or oversized file is an error, so
// the caller fails closed. A missing file is an empty list.
func RepoMaskedPaths(repo string) ([]string, error) {
	root, err := os.OpenRoot(repo)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	st, err := root.Lstat(yamllist.RepoConfig)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", yamllist.RepoConfig)
	}
	const max = 1 << 20
	if st.Size() > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", yamllist.RepoConfig, max)
	}
	f, err := root.Open(yamllist.RepoConfig)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	return yamllist.Extract(b, "masked_paths", false), nil
}

// RepoHooksPath is the host repository's effective core.hooksPath as a slash-separated path
// relative to the repository, or "" when it is unset or outside the repository (then the gate
// has nothing extra to protect: the default .git/hooks is always quarantined). It asks the host's
// git, which reads every config layer the operator's own git commands will (system, global,
// includes, the repository's .git/config, which the VM cannot change). git failing is an error,
// so the caller fails closed.
func RepoHooksPath(repo string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", repo, "config", "--get", "--path", "core.hooksPath")
	out, err := cmd.Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 {
		return "", nil // not set
	}
	if err != nil {
		return "", fmt.Errorf("git config core.hooksPath: %w", err)
	}
	return hooksRel(repo, strings.TrimRight(string(out), "\r\n"))
}

// hooksRel places a hooks path (absolute, or relative to the work tree as git reads it) inside
// repo, comparing real paths so a symlink on either side does not hide it.
func hooksRel(repo, p string) (string, error) {
	if p == "" {
		return "", nil
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(repo, p)
	}
	r, err := filepath.EvalSymlinks(repo)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(r, realPrefix(filepath.Clean(p)))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", nil
	}
	if rel == "." {
		return "", errors.New("core.hooksPath is the repository's own top directory, so any file there could be a hook; refusing to sync")
	}
	return filepath.ToSlash(rel), nil
}

// realPrefix resolves the symlinks of the longest existing prefix of p (a hooks directory need
// not exist yet).
func realPrefix(p string) string {
	rest := ""
	for q := p; ; q = filepath.Dir(q) {
		if r, err := filepath.EvalSymlinks(q); err == nil {
			return filepath.Join(r, rest)
		}
		if q == filepath.Dir(q) {
			return p
		}
		rest = filepath.Join(filepath.Base(q), rest)
	}
}
