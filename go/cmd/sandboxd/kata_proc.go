package main

import (
	"bytes"
	"path/filepath"
)

// microVMProcess is whether a command line (NUL-separated) is container id's Kata shim
// ("containerd-shim-kata-v2 ... -id <id>") or hypervisor (an argument under /run/vc/vm/<id>/).
func microVMProcess(cmdline []byte, id string) bool {
	args := bytes.Split(bytes.TrimRight(cmdline, "\x00"), []byte{0})
	if len(args) == 0 || id == "" {
		return false
	}
	switch filepath.Base(string(args[0])) {
	case "containerd-shim-kata-v2":
		for i := 1; i+1 < len(args); i++ {
			if string(args[i]) == "-id" && string(args[i+1]) == id {
				return true
			}
		}
	case "cloud-hypervisor":
		for _, a := range args[1:] {
			if bytes.HasPrefix(a, []byte("/run/vc/vm/"+id+"/")) {
				return true
			}
		}
	}
	return false
}
