//go:build !windows

// Package hostbin checks the third-party binaries the host binary runs (limactl, vfkit) before
// each use (design 5.1.2).
package hostbin

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

// adminGID is macOS's admin group. Its members can become root, so a directory only they can
// write is as safe as a root-owned one; Homebrew's bin directory is group-writable by admin.
const adminGID = 80

// trustedGroup reports whether write access for group gid is no wider than root's.
func trustedGroup(gid uint32) bool {
	return gid == 0 || runtime.GOOS == "darwin" && gid == adminGID
}

// checkOne refuses a path entry that someone other than root or the operator could replace:
// owned by another account, writable by all, or writable by a group that is not root-equivalent.
func checkOne(p string, uid int) error {
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read its owner", p)
	}
	if int(sys.Uid) != 0 && int(sys.Uid) != uid {
		return fmt.Errorf("%s is owned by uid %d, neither root nor you", p, sys.Uid)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil // a link's own mode means nothing; its directory and target are checked
	}
	m := st.Mode().Perm()
	if m&0o002 != 0 {
		return fmt.Errorf("%s is writable by every user", p)
	}
	if m&0o020 != 0 && !trustedGroup(sys.Gid) {
		return fmt.Errorf("%s is writable by group %d", p, sys.Gid)
	}
	return nil
}

// checkChain checks p and every directory above it.
func checkChain(p string, uid int) error {
	for q := p; ; q = filepath.Dir(q) {
		if err := checkOne(q, uid); err != nil {
			return err
		}
		if q == filepath.Dir(q) {
			return nil
		}
	}
}

// Verify is design 5.1.2's check on a driver tool (name is "limactl", "vfkit", or "qemu", for
// messages): p must be absolute, and neither it nor the file it resolves to, nor any directory on
// the way to either, may be replaceable by anyone but root or the operator (uid). "User-writable"
// is read as "writable by another user": the operator is trusted (the threat model), and Homebrew
// installs these tools in directories the operator owns.
func Verify(name, p string, uid int) error { return verify(name, p, uid, true) }

// VerifyFile is Verify for a file the tool loads rather than runs (qemu's UEFI firmware).
func VerifyFile(name, p string, uid int) error { return verify(name, p, uid, false) }

func verify(name, p string, uid int, exe bool) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsRune(p, 0) {
		return fmt.Errorf("%s path %q is not a clean absolute path", name, p)
	}
	if err := checkChain(p, uid); err != nil {
		return fmt.Errorf("refusing %s: %w", name, err)
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return fmt.Errorf("refusing %s: %w", name, err)
	}
	if err := checkChain(real, uid); err != nil {
		return fmt.Errorf("refusing %s (%s): %w", name, real, err)
	}
	st, err := os.Stat(real)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || exe && st.Mode().Perm()&0o111 == 0 {
		what := "a regular file"
		if exe {
			what = "an executable file"
		}
		return fmt.Errorf("refusing %s: %s is not %s", name, real, what)
	}
	return nil
}
