//go:build linux

package runtime

import (
	"context"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func vm() MicroVM {
	return MicroVM{ID: "s-one", Image: "docker.io/library/alpine@sha256:00", Args: []string{"sh"},
		Env: []string{"TERM=xterm"}, UID: 1000, GID: 1000, NetNS: "/var/run/netns/sbx-s-one-agent",
		CPUs: 1.5, MemoryMiB: 2048, Hostname: "sandbox",
		Mounts: []Mount{{Source: "/var/lib/sandbox/workspaces/0123456789abcdef", Target: "/home/agent/workspace"},
			{Source: "/var/lib/sandbox/workspaces/0123456789abcdef/.git/config", Target: "/home/agent/workspace/.git/config", ReadOnly: true}}}
}

func spec(t *testing.T, m MicroVM, extra ...oci.SpecOpts) *oci.Spec {
	t.Helper()
	// an image config (here: options that ask for root and a capability) cannot widen it
	opts := SpecOpts(m, extra...)
	s, err := oci.GenerateSpecWithPlatform(ctxNS(context.Background()), nil, "linux/arm64", &containers.Container{ID: m.ID}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHardening(t *testing.T) {
	s := spec(t, vm(), oci.WithUIDGID(0, 0), oci.WithCapabilities([]string{"CAP_SYS_ADMIN"}))
	p := s.Process
	if p.User.UID != 1000 || p.User.GID != 1000 || !p.NoNewPrivileges {
		t.Errorf("user %+v nnp %v", p.User, p.NoNewPrivileges)
	}
	c := p.Capabilities
	if len(c.Bounding)+len(c.Effective)+len(c.Permitted)+len(c.Inheritable)+len(c.Ambient) != 0 {
		t.Errorf("capabilities %+v", c)
	}
	if s.Linux.Seccomp == nil || s.Linux.Seccomp.DefaultAction == specs.ActAllow || len(s.Linux.Seccomp.Syscalls) == 0 {
		t.Error("no default seccomp profile")
	}
	var netns string
	for _, ns := range s.Linux.Namespaces {
		if ns.Type == specs.NetworkNamespace {
			netns = ns.Path
		}
	}
	if netns != "/var/run/netns/sbx-s-one-agent" {
		t.Errorf("network namespace %q", netns)
	}
	if *s.Linux.Resources.Memory.Limit != 2048<<20 || *s.Linux.Resources.CPU.Quota != 150000 || *s.Linux.Resources.CPU.Period != 100000 {
		t.Errorf("resources %+v %+v", s.Linux.Resources.Memory, s.Linux.Resources.CPU)
	}
	opts := map[string]string{}
	for _, m := range s.Mounts {
		if m.Type == "bind" {
			opts[m.Destination] = strings.Join(m.Options, ",")
		}
	}
	if opts["/home/agent/workspace"] != "rbind,rw" || opts["/home/agent/workspace/.git/config"] != "rbind,ro" {
		t.Errorf("bind mounts %v", opts)
	}
	if s.Hostname != "sandbox" || s.Process.Args[0] != "sh" {
		t.Error("mounts, hostname, or args lost")
	}
}

func TestCheck(t *testing.T) {
	if err := vm().Check(); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func(*MicroVM){
		"root":       func(m *MicroVM) { m.UID = 0 },
		"root group": func(m *MicroVM) { m.GID = 0 },
		"no netns":   func(m *MicroVM) { m.NetNS = "" },
		"no memory":  func(m *MicroVM) { m.MemoryMiB = 0 },
		"no image":   func(m *MicroVM) { m.Image = "" },
		"relative":   func(m *MicroVM) { m.Mounts = append(m.Mounts, Mount{Source: "x", Target: "/x"}) },
		"over root":  func(m *MicroVM) { m.Mounts = append(m.Mounts, Mount{Source: "/x", Target: "/"}) },
	} {
		m := vm()
		f(&m)
		if m.Check() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
