// Command sandbox-canary is the capability probe's canary (design 5.2.3 check 3): sandboxd runs it
// as the only program of a sandbox under each runtime, with a read-only root file system of its
// own (/usr/lib/sandbox/canary/rootfs in the appliance image). It reports the kernel it sees and
// what it read through a mount, by writing /canary/out/result.json, and exits 0.
package main

import (
	"encoding/json"
	"os"
	"strings"
)

// Result is what the canary reports.
type Result struct {
	Release string `json:"release"` // uname -r
	Version string `json:"version"` // uname -v
	Probe   string `json:"probe"`   // the content of /canary/in/probe
	UID     int    `json:"uid"`
}

func main() {
	r := Result{UID: os.Getuid()}
	r.Release, r.Version = uname()
	if b, err := os.ReadFile("/canary/in/probe"); err == nil {
		r.Probe = strings.TrimSpace(string(b))
	}
	b, _ := json.Marshal(r)
	if err := os.WriteFile("/canary/out/result.json", b, 0o644); err != nil {
		os.Exit(2)
	}
}
