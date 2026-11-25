//go:build linux

package tty

import "syscall"

const ioctlGetTermios = syscall.TCGETS
