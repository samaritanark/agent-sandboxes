package main

import (
	"os"
	"syscall"
	"unsafe"
)

// waitHangup returns when f's other end is gone: for stdout, nobody reads it any more (a pipe's
// reader closed, a terminal hung up). That is how an attach notices its SSH connection died
// without a terminal, where sshd sends no SIGHUP.
func waitHangup(f *os.File) {
	pfd := struct {
		fd      int32
		events  int16
		revents int16
	}{fd: int32(f.Fd())} // no events asked for: POLLERR and POLLHUP are always reported
	for {
		_, _, e := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(&pfd)), 1, 0, 0, 0, 0)
		if e == syscall.EINTR {
			continue
		}
		if e != 0 || pfd.revents&(0x8|0x10|0x20) != 0 { // POLLERR, POLLHUP, POLLNVAL
			return
		}
	}
}
