//go:build !linux

// Command sandbox-gateway runs only in the appliance VM (Linux).
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "sandbox-gateway runs only in the appliance VM (Linux)")
	os.Exit(1)
}
