//go:build linux

package runtime

import (
	"context"
	"strings"
	"testing"

	runtimeoptions "github.com/containerd/containerd/api/types/runtimeoptions/v1"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/typeurl/v2"
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
	for _, rt := range []string{"", Kata, GVisor} {
		m := vm()
		m.Runtime = rt
		if err := m.Check(); err != nil {
			t.Fatal(err)
		}
	}
	for name, f := range map[string]func(*MicroVM){
		"root":       func(m *MicroVM) { m.UID = 0 },
		"root group": func(m *MicroVM) { m.GID = 0 },
		"no netns":   func(m *MicroVM) { m.NetNS = "" },
		"no memory":  func(m *MicroVM) { m.MemoryMiB = 0 },
		"no image":   func(m *MicroVM) { m.Image = "" },
		"relative":   func(m *MicroVM) { m.Mounts = append(m.Mounts, Mount{Source: "x", Target: "/x"}) },
		"over root":  func(m *MicroVM) { m.Mounts = append(m.Mounts, Mount{Source: "/x", Target: "/"}) },
		"runtime":    func(m *MicroVM) { m.Runtime = "runc" },
	} {
		m := vm()
		f(&m)
		if m.Check() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestWithRuntime: a session runs under the shim and configuration of its runtime, Kata unless it
// asks for gVisor.
func TestWithRuntime(t *testing.T) {
	for kind, want := range map[string][2]string{"": {KataRuntime, KataConfig}, Kata: {KataRuntime, KataConfig},
		GVisor: {GVisorRuntime, GVisorConfig}} {
		var c containers.Container
		if err := withRuntime(kind)(context.Background(), nil, &c); err != nil {
			t.Fatal(err)
		}
		var o runtimeoptions.Options
		if err := typeurl.UnmarshalTo(c.Runtime.Options, &o); err != nil {
			t.Fatal(err)
		}
		if c.Runtime.Name != want[0] || o.ConfigPath != want[1] {
			t.Errorf("%q: %s %s", kind, c.Runtime.Name, o.ConfigPath)
		}
	}
}

// TestGVisorIsASandbox: a gVisor container is marked as a sandbox of its own (gVisor's shim gives
// `runsc create` the container's I/O only then); a Kata one is not marked.
func TestGVisorIsASandbox(t *testing.T) {
	for rt, want := range map[string]string{"": "", Kata: "", GVisor: "sandbox"} {
		m := vm()
		m.Runtime = rt
		if got := spec(t, m).Annotations[criContainerType]; got != want {
			t.Errorf("%q: %q", rt, got)
		}
	}
}
