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

func ioctl(f *os.File, req uintptr, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), req, uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

// MakeRaw puts the terminal f into raw mode (as cfmakeraw does) and returns the function that
// restores it.
func MakeRaw(f *os.File) (func(), error) {
	var old syscall.Termios
	if err := ioctl(f, ioctlGetTermios, unsafe.Pointer(&old)); err != nil {
		return nil, err
	}
	t := old
	t.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	t.Oflag &^= syscall.OPOST
	t.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	t.Cflag &^= syscall.CSIZE | syscall.PARENB
	t.Cflag |= syscall.CS8
	t.Cc[syscall.VMIN], t.Cc[syscall.VTIME] = 1, 0
	if err := ioctl(f, ioctlSetTermios, unsafe.Pointer(&t)); err != nil {
		return nil, err
	}
	return func() { ioctl(f, ioctlSetTermios, unsafe.Pointer(&old)) }, nil
}

// Size is the terminal f's window size in columns and rows.
func Size(f *os.File) (cols, rows uint16, err error) {
	var ws struct{ Row, Col, X, Y uint16 }
	if err := ioctl(f, syscall.TIOCGWINSZ, unsafe.Pointer(&ws)); err != nil {
		return 0, 0, err
	}
	return ws.Col, ws.Row, nil
}
