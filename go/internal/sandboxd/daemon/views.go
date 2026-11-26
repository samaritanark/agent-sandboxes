package daemon

// Workspace views. Kata creates a microVM's bind mount points itself, in the guest, and a file
// mount point inside a workspace, which the guest shares live with the VM's copy, emptied the
// copy's own .git/config, .gitmodules, and the like at every session start (found on vfkit,
// 2026-11-26). So each workspace reaches the microVM as a view: a directory in the session's own
// tree with the copy bound on it, and the file overlays (file masks, read-only files) are bound
// over the view by the VM's kernel, which mounts over an existing file without touching it.
// Directory overlays still go to the microVM, where Kata enforces them and makes no file.
//
// Known limit: Kata shares a mount's source with a non-recursive bind, so the guest does not see
// the file covers in a view; they keep the copy whole but do not stop the agent writing those
// files. The host stays protected by the sync gate, which withholds VM changes to .git/config and
// every exec-vector file (syncgate.Classify).

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Mounter makes the views (bind mounts in the VM in production).
type Mounter interface {
	// View binds src, and the mounts under it, on dst, an empty directory it makes.
	View(src, dst string) error
	// Over makes rel, a path in view, read-only: covered by cover (an empty file or directory of
	// the same type), or, with cover "", as it is. rel is resolved within view without following
	// a link (the copy is the agent's to shape); when it is missing, is a link, or is not cover's
	// type, Over returns ErrNoTarget and changes nothing (making it would make it in the copy).
	Over(view, rel, cover string) error
	// Unmount detaches dst and every mount under it.
	Unmount(dst string) error
}

// ErrNoTarget is Mounter.Over's answer for a path the view does not have.
var ErrNoTarget = errors.New("no such path in the view")

func (d *Daemon) viewDir(id string) string { return filepath.Join(d.SessionRoot, id, "views") }

// view makes session id's view number n of workspace copy src, journaled by its number.
func (d *Daemon) view(id string, n int, src string) (string, error) {
	v := filepath.Join(d.viewDir(id), strconv.Itoa(n))
	err := d.step(id, KindView, strconv.Itoa(n), func() error {
		if err := os.MkdirAll(d.viewDir(id), 0o711); err != nil {
			return err
		}
		return d.Mounter.View(src, v)
	})
	return v, err
}

// dropView undoes a view: unmounted first, then its directory removed, never recursively, so a view
// still mounted can never lead a removal into the copy.
func (d *Daemon) dropView(id, n string) error {
	if _, err := strconv.Atoi(n); err != nil {
		return fmt.Errorf("view %q: not a view number", n)
	}
	v := filepath.Join(d.viewDir(id), n)
	if d.Mounter == nil {
		return fmt.Errorf("view %s: no mounter to unmount it", v)
	}
	if err := d.Mounter.Unmount(v); err != nil {
		return err
	}
	if err := os.Remove(v); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	os.Remove(filepath.Dir(v)) // the views directory, once empty
	return nil
}

// inView finds the view whose workspace target holds target, and target's path within it.
func inView(views map[string]string, target string) (view, rel string, ok bool) {
	for t, v := range views {
		if r, found := strings.CutPrefix(target, t+"/"); found && r != "" {
			return v, r, true
		}
	}
	return "", "", false
}
