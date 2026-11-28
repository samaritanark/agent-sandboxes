package main

import "syscall"

func uname() (release, version string) {
	var u syscall.Utsname
	if syscall.Uname(&u) != nil {
		return "", ""
	}
	str := func(a [65]int8) string {
		b := make([]byte, 0, len(a))
		for _, c := range a {
			if c == 0 {
				break
			}
			b = append(b, byte(c))
		}
		return string(b)
	}
	return str(u.Release), str(u.Version)
}
