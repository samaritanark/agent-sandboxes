//go:build windows

package tty

import (
	"os"
	"syscall"
)

// Is reports whether f is a console (NUL and pipes are not).
func Is(f *os.File) bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(f.Fd()), &mode) == nil
}
