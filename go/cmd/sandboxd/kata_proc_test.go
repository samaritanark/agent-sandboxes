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
		"/opt/kata/bin/containerd-shim-kata-v2 -namespace " + id + " -id other": false,
		"/opt/kata/libexec/virtiofsd --shared-dir=/run/vc/vm/" + id + "/":       false,
	} {
		if got := microVMProcess(nul(cmd), id); got != want {
			t.Errorf("%q: %v", cmd, got)
		}
	}
	if microVMProcess(nul("/opt/kata/bin/containerd-shim-kata-v2 -id"), "") {
		t.Error("an empty id matched")
	}
}
