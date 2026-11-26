package main

// Host paths mirrored in the VM (design 5.1.1 item 3, translating host paths): the in-VM CLI runs
// with HOME set to the operator's host home, so `~`, profile paths, and v2's messages behave as on
// the host. Root links <host home>/.sandbox to the pushed operator state, and each repository the
// host synced for a run to its workspace copy. Only those two kinds of target are linked, never
// over a path the VM's own system uses.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// mirrorPath is the hidden `sandbox __mirror-path HOSTPATH TARGET`.
const mirrorPath = "__mirror-path"

// OperatorDir is where the host pushes the operator state.
const OperatorDir = "/var/lib/sandbox/operator"

// reserved are the VM's own top-level directories, which no host path may be mirrored into.
var reserved = []string{"bin", "boot", "dev", "etc", "lib", "lib32", "lib64", "libx32", "opt", "proc", "root",
	"run", "sbin", "srv", "sys", "tmp", "usr", "var"}

var copyTarget = regexp.MustCompile(`^` + regexp.QuoteMeta(sessionspec.WorkspaceStore) + `/[0-9a-f]{16}$`)

// checkMirror refuses a host path that is not a clean absolute path outside the VM's own
// directories, or a target that is neither the operator state nor a workspace copy.
func checkMirror(hostPath, target string) error {
	if !filepath.IsAbs(hostPath) || filepath.Clean(hostPath) != hostPath || strings.ContainsAny(hostPath, "\x00\n") {
		return fmt.Errorf("%q is not a clean absolute path", hostPath)
	}
	parts := strings.Split(hostPath, "/")
	if len(parts) < 3 {
		return fmt.Errorf("%s is too near the root to mirror", hostPath)
	}
	for _, r := range reserved {
		if parts[1] == r {
			return fmt.Errorf("%s is inside the VM's own /%s", hostPath, r)
		}
	}
	if target != OperatorDir && !copyTarget.MatchString(target) {
		return fmt.Errorf("%s is not a mirror target", target)
	}
	return nil
}

// mirror links root+hostPath to target (an absolute VM path, written as is into the link). Each
// directory above it that exists must be a real directory, so a link cannot steer the mirror
// elsewhere; the missing ones are made. An existing link to target is kept; anything else there
// is refused.
func mirror(root, hostPath, target string) error {
	if err := checkMirror(hostPath, target); err != nil {
		return err
	}
	dir := root
	parts := strings.Split(hostPath, "/")
	for _, p := range parts[1 : len(parts)-1] {
		dir = filepath.Join(dir, p)
		st, err := os.Lstat(dir)
		switch {
		case errors.Is(err, os.ErrNotExist):
			if err := os.Mkdir(dir, 0o755); err != nil {
				return err
			}
		case err != nil:
			return err
		case !st.IsDir():
			return fmt.Errorf("%s: not a directory in the VM", strings.TrimPrefix(dir, root))
		}
	}
	link := filepath.Join(root, hostPath)
	if st, err := os.Lstat(link); err == nil {
		if cur, _ := os.Readlink(link); st.Mode()&os.ModeSymlink != 0 && cur == target {
			return nil
		}
		return fmt.Errorf("%s already exists in the VM and is not its mirror", hostPath)
	}
	return os.Symlink(target, link)
}
