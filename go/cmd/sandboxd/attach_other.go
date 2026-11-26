//go:build !linux && !darwin

package main

import (
	"fmt"
	"os"
)

func ctlAttach(string, []string) int {
	fmt.Fprintln(os.Stderr, "sandboxd: attach needs a Unix terminal")
	return 1
}
