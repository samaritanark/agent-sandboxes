package main

import (
	"strings"
	"testing"
)

func TestMicroVMProcess(t *testing.T) {
	id := "ses-20261126-225837-da93"
	nul := func(s string) []byte { return []byte(strings.ReplaceAll(s, " ", "\x00") + "\x00") }
	for cmd, want := range map[string]bool{
		"/opt/kata/bin/containerd-shim-kata-v2 -namespace sandbox -id " + id + " start":   true,
		"/opt/kata/bin/cloud-hypervisor --api-socket /run/vc/vm/" + id + "/clh-api.sock":  true,
		"/opt/kata/bin/containerd-shim-kata-v2 -id ses-20261126-225837-0000":              false,
		"/opt/kata/bin/cloud-hypervisor --api-socket /run/vc/vm/" + id + "x/clh-api.sock": false,
		"/bin/sh -c kill -id " + id: false,
		"/opt/kata/bin/containerd-shim-kata-v2 -namespace " + id + " -id other":                                                        false,
		"/opt/kata/libexec/virtiofsd --shared-dir=/run/vc/vm/" + id + "/":                                                              false,
		"/usr/local/bin/containerd-shim-runsc-v1 -namespace sandbox -address /run/containerd/containerd.sock -id " + id:                true,
		"runsc-sandbox --root=/run/containerd/runsc/sandbox boot --bundle=/run/containerd/io.containerd.runtime.v2.task/sandbox/" + id: true,
		"runsc-gofer --root=/run/containerd/runsc/sandbox gofer --bundle /run/containerd/io.containerd.runtime.v2.task/sandbox/" + id:  true,
		"runsc-sandbox boot --bundle=/run/containerd/io.containerd.runtime.v2.task/sandbox/" + id + "--db":                             false,
		"runsc-sandbox boot --bundle=/run/containerd/io.containerd.runtime.v2.task/default/" + id:                                      false,
		"runsc-gofer gofer --bundle /run/containerd/io.containerd.runtime.v2.task/sandbox/" + id + "/x":                                false,
		"/usr/bin/runsc --root=/run/containerd/runsc/sandbox wait " + id:                                                               false,
	} {
		if got := microVMProcess(nul(cmd), id); got != want {
			t.Errorf("%q: %v", cmd, got)
		}
	}
	if microVMProcess(nul("/opt/kata/bin/containerd-shim-kata-v2 -id"), "") {
		t.Error("an empty id matched")
	}
	if microVMCgroup(id) != "/sys/fs/cgroup/sandbox/"+id {
		t.Error(microVMCgroup(id))
	}
}
