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

// MakeRaw is not needed on Windows: the host binary hands the console to ssh.
func MakeRaw(*os.File) (func(), error) { return nil, syscall.EWINDOWS }

// Size is not available on Windows here.
func Size(*os.File) (cols, rows uint16, err error) { return 0, 0, syscall.EWINDOWS }
