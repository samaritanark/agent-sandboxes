package main

// The workspace views' mounts (daemon.Mounter, internal/sandboxd/daemon/views.go), made in the VM.
// The copy under a view is the agent's to shape, so a path in it is never followed through a link:
// each one is opened with openat2 beneath the view, without links, and mounted on by its open
// descriptor. A view is private, so nothing mounted in it reaches the copy (the state disk's mount
// is shared). Read-only binds go through a staging mount made read-only first, since a bind keeps
// its source mount's read-only flag.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/daemon"
)

// openat2's number is the same on amd64 and arm64 (the generic table).
const sysOpenat2 = 437

const (
	resolveNoSymlinks = 0x04
	resolveBeneath    = 0x08
	oPath             = 0x200000
)

type openHow struct{ flags, mode, resolve uint64 }

// openBeneath opens rel beneath the directory dirFd as an O_PATH descriptor, refusing any link on
// the way and any escape.
func openBeneath(dirFd int, rel string) (int, error) {
	p, err := syscall.BytePtrFromString(rel)
	if err != nil {
		return -1, err
	}
	how := openHow{flags: oPath | syscall.O_NOFOLLOW | syscall.O_CLOEXEC, resolve: resolveBeneath | resolveNoSymlinks}
	fd, _, e := syscall.Syscall6(sysOpenat2, uintptr(dirFd), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
	if e != 0 {
		return -1, e
	}
	return int(fd), nil
}

func fdPath(fd int) string { return "/proc/self/fd/" + strconv.Itoa(fd) }

type viewMounter struct {
	stage string // where staging mounts are made (root's own, outside any copy)
	seq   atomic.Int64
}

func (m *viewMounter) View(src, dst string) error {
	if err := os.Mkdir(dst, 0o700); err != nil {
		return err
	}
	if err := syscall.Mount(src, dst, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		os.Remove(dst)
		return fmt.Errorf("bind %s: %w", src, err)
	}
	if err := syscall.Mount("", dst, "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		syscall.Unmount(dst, syscall.MNT_DETACH)
		os.Remove(dst)
		return fmt.Errorf("make %s private: %w", dst, err)
	}
	return nil
}

func (m *viewMounter) Over(view, rel, cover string) error {
	vfd, err := syscall.Open(view, oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(vfd)
	tfd, err := openBeneath(vfd, rel)
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EXDEV) {
		return daemon.ErrNoTarget
	}
	if err != nil {
		return err
	}
	defer syscall.Close(tfd)
	var st syscall.Stat_t
	if err := syscall.Fstat(tfd, &st); err != nil {
		return err
	}
	dir := st.Mode&syscall.S_IFMT == syscall.S_IFDIR
	if !dir && st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return daemon.ErrNoTarget
	}
	src := fdPath(tfd)
	if cover != "" {
		ci, err := os.Lstat(cover)
		if err != nil {
			return err
		}
		if ci.IsDir() != dir {
			return daemon.ErrNoTarget
		}
		src = cover
	}
	// a read-only staging mount of the source, then a bind of it over the target
	if err := os.MkdirAll(m.stage, 0o700); err != nil {
		return err
	}
	stage := filepath.Join(m.stage, strconv.FormatInt(m.seq.Add(1), 10))
	if dir {
		err = os.Mkdir(stage, 0o700)
	} else {
		err = os.WriteFile(stage, nil, 0o600)
	}
	if err != nil {
		return err
	}
	defer os.Remove(stage)
	if err := syscall.Mount(src, stage, "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("stage %s: %w", rel, err)
	}
	defer syscall.Unmount(stage, syscall.MNT_DETACH)
	if err := syscall.Mount("", stage, "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("read-only %s: %w", rel, err)
	}
	if err := syscall.Mount(stage, fdPath(tfd), "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("cover %s: %w", rel, err)
	}
	return nil
}

func (m *viewMounter) Unmount(dst string) error {
	err := syscall.Unmount(dst, syscall.MNT_DETACH)
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOENT) {
		return nil // not mounted (any more)
	}
	return err
}
