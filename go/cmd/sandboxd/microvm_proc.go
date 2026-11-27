package main

import (
	"bytes"
	"path/filepath"

	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/runtime"
)

// microVMProcess is whether a command line (NUL-separated) is one of container id's runtime
// processes: under Kata its shim ("containerd-shim-kata-v2 ... -id <id>") or hypervisor (an
// argument under /run/vc/vm/<id>/); under gVisor its shim ("containerd-shim-runsc-v1 ... -id
// <id>"), sandbox, or gofer (runsc-sandbox and runsc-gofer, whose bundle is the task directory
// containerd keeps for id in sandboxd's namespace). gVisor's sentry processes have no command line;
// microVMCgroup finds them.
func microVMProcess(cmdline []byte, id string) bool {
	args := bytes.Split(bytes.TrimRight(cmdline, "\x00"), []byte{0})
	if len(args) == 0 || id == "" {
		return false
	}
	switch filepath.Base(string(args[0])) {
	case "containerd-shim-kata-v2", "containerd-shim-runsc-v1":
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
	case "runsc-sandbox", "runsc-gofer":
		bundle := []byte("/io.containerd.runtime.v2.task/" + runtime.Namespace + "/" + id)
		for _, a := range args[1:] {
			a = bytes.TrimPrefix(a, []byte("--bundle="))
			if bytes.HasPrefix(a, []byte("/")) && bytes.HasSuffix(a, bundle) {
				return true
			}
		}
	}
	return false
}

// microVMCgroup is the cgroup (v2) runsc puts container id's sandbox in: containerd's default
// cgroups path, /<namespace>/<id>.
func microVMCgroup(id string) string {
	return "/sys/fs/cgroup/" + runtime.Namespace + "/" + id
}
