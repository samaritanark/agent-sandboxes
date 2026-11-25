//go:build darwin || freebsd || netbsd || openbsd

package syncproto

import "syscall"

func ctimeNs(s *syscall.Stat_t) int64 { return s.Ctimespec.Sec*1e9 + s.Ctimespec.Nsec }
