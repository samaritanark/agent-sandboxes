// Package gitref is the host's own minimal reading and writing of a repository's git files for
// vetting attestation (design 5.1.3, D-20): the host binary learns HEAD's commit by parsing
// .git/HEAD, the ref file, and packed-refs as plain files, and writes the signed tag object and
// refs/tags/agent-vetted/<sha> itself, never running git against the host repository (a repo's
// config, hooks, and filters would otherwise run operator-side code chosen by the repo).
//
// The repository is untrusted input. Every file is read with a size cap; a symlink anywhere this
// package reads or writes is refused (git itself writes none there); anything it does not
// recognise is an error rather than a guess.
package gitref

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxSmall  = 4096     // HEAD, a ref file, a .git file, commondir, config
	maxPacked = 64 << 20 // packed-refs
)

// Repo is a repository's git directories: GitDir holds HEAD (a linked worktree has its own), and
// CommonDir holds refs, packed-refs, objects, and config.
type Repo struct {
	GitDir    string
	CommonDir string
	HashLen   int // 40 (sha1) or 64 (sha256)
}

func readSmall(p string, max int64) ([]byte, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink", p)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	if st.Size() > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", p, max)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err == nil && int64(len(b)) > max {
		err = fmt.Errorf("%s grew past %d bytes", p, max)
	}
	return b, err
}

func isDir(p string) bool {
	st, err := os.Lstat(p)
	return err == nil && st.IsDir()
}

// Open finds the git directories of the work tree at dir: a .git directory, or a .git file
// ("gitdir: <path>", as in linked worktrees and submodules), with commondir followed once.
func Open(dir string) (*Repo, error) {
	dotgit := filepath.Join(dir, ".git")
	st, err := os.Lstat(dotgit)
	if err != nil {
		return nil, fmt.Errorf("not a git work tree: %w", err)
	}
	var gitdir string
	switch {
	case st.Mode()&os.ModeSymlink != 0:
		return nil, fmt.Errorf("%s is a symlink", dotgit)
	case st.IsDir():
		gitdir = dotgit
	default:
		b, err := readSmall(dotgit, maxSmall)
		if err != nil {
			return nil, err
		}
		line := strings.TrimRight(string(b), "\r\n")
		p, ok := strings.CutPrefix(line, "gitdir: ")
		if !ok || p == "" || strings.ContainsAny(p, "\n\r\x00") {
			return nil, fmt.Errorf("%s is not a gitdir file", dotgit)
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		gitdir = filepath.Clean(p)
	}
	if !isDir(gitdir) {
		return nil, fmt.Errorf("%s is not a directory", gitdir)
	}
	r := &Repo{GitDir: gitdir, CommonDir: gitdir, HashLen: 40}
	if b, err := readSmall(filepath.Join(gitdir, "commondir"), maxSmall); err == nil {
		p := strings.TrimRight(string(b), "\r\n")
		if p == "" || strings.ContainsAny(p, "\n\r\x00") {
			return nil, errors.New("invalid commondir file")
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(gitdir, p)
		}
		r.CommonDir = filepath.Clean(p)
		if !isDir(r.CommonDir) {
			return nil, fmt.Errorf("%s is not a directory", r.CommonDir)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	n, err := objectFormat(r.CommonDir)
	if err != nil {
		return nil, err
	}
	r.HashLen = n
	return r, nil
}

// objectFormat reads extensions.objectformat from the repository config: sha1 unless it says
// sha256. Only that one key is read, with a deliberately small INI reader.
func objectFormat(common string) (int, error) {
	b, err := readSmall(filepath.Join(common, "config"), 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return 40, nil
	}
	if err != nil {
		return 0, err
	}
	section := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(l, "[") {
			section = strings.ToLower(strings.Trim(strings.Fields(strings.Trim(l, "[]") + " ")[0], `"`))
			continue
		}
		if section != "extensions" {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "objectformat") {
			switch strings.ToLower(strings.TrimSpace(v)) {
			case "sha1":
				return 40, nil
			case "sha256":
				return 64, nil
			}
			return 0, fmt.Errorf("unsupported object format %q", strings.TrimSpace(v))
		}
	}
	return 40, nil
}

func (r *Repo) validHash(s string) bool {
	if len(s) != r.HashLen {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// validRef is a refs/ name this package will follow: refs/..., no "..", no empty or dot-led
// component, and none of git's forbidden characters.
func validRef(name string) bool {
	if !strings.HasPrefix(name, "refs/") || strings.HasSuffix(name, "/") || strings.HasSuffix(name, ".lock") || strings.Contains(name, "..") || strings.Contains(name, "@{") {
		return false
	}
	for _, c := range strings.Split(name, "/") {
		if c == "" || strings.HasPrefix(c, ".") {
			return false
		}
	}
	for _, c := range name {
		if c <= ' ' || c == 0x7f || strings.ContainsRune(`~^:?*[\`, c) {
			return false
		}
	}
	return true
}

// Head is the commit HEAD names, following symbolic refs (at most five), loose refs before
// packed-refs. An unborn branch is an error.
func (r *Repo) Head() (string, error) {
	b, err := readSmall(filepath.Join(r.GitDir, "HEAD"), maxSmall)
	if err != nil {
		return "", err
	}
	v := strings.TrimRight(string(b), "\n")
	for depth := 0; depth < 5; depth++ {
		if r.validHash(v) {
			return v, nil
		}
		name, ok := strings.CutPrefix(v, "ref: ")
		if !ok || !validRef(name) {
			return "", fmt.Errorf("cannot read %q as a commit or a ref", v)
		}
		v, err = r.resolveOne(name)
		if err != nil {
			return "", err
		}
	}
	return "", errors.New("symbolic refs nest too deeply")
}

// resolveOne reads one ref: the loose file, then packed-refs. In a linked worktree git keeps
// refs/worktree/, refs/bisect/, and refs/rewritten/ in the worktree's own git dir (which has no
// packed-refs of its own) and every other ref in the common dir.
func (r *Repo) resolveOne(name string) (string, error) {
	dir := r.CommonDir
	for _, p := range []string{"refs/worktree/", "refs/bisect/", "refs/rewritten/"} {
		if strings.HasPrefix(name, p) {
			dir = r.GitDir
		}
	}
	b, err := readSmall(filepath.Join(dir, filepath.FromSlash(name)), maxSmall)
	if err == nil {
		return strings.TrimRight(string(b), "\n"), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if dir == r.GitDir && r.GitDir != r.CommonDir {
		return "", fmt.Errorf("ref %s does not exist", name)
	}
	return r.packed(name)
}

// packed looks name up in packed-refs.
func (r *Repo) packed(name string) (string, error) {
	b, err := readSmall(filepath.Join(r.CommonDir, "packed-refs"), maxPacked)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("ref %s does not exist (an unborn branch?)", name)
	}
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if l == "" || l[0] == '#' || l[0] == '^' {
			continue
		}
		h, n, ok := strings.Cut(l, " ")
		if !ok {
			return "", errors.New("malformed packed-refs line")
		}
		if n == name {
			if !r.validHash(h) {
				return "", fmt.Errorf("packed-refs entry for %s is not an object id", name)
			}
			return h, nil
		}
	}
	return "", fmt.Errorf("ref %s does not exist (an unborn branch?)", name)
}
