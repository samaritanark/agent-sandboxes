//go:build darwin || linux

package tty

import (
	"os"
	"syscall"
	"unsafe"
)

// Is reports whether f is a terminal: it answers the terminal-attributes request. Being a
// character device is not enough (/dev/null is one).
func Is(f *os.File) bool {
	var t syscall.Termios
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), ioctlGetTermios, uintptr(unsafe.Pointer(&t)))
	return e == 0
}
