package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

func installEnv(t *testing.T, d *driver.Mock, tr *fakeTransport) (Env, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	n := 0
	return Env{Driver: driver.Absent{}, Transport: tr, Stdout: &out, Stderr: &errb, StateDir: t.TempDir(),
		Install: InstallDeps{
			RecordDriver: func(kind, tool string) (driver.Driver, error) { return d, nil },
			GenerateKey: func(comment string) (string, string, error) {
				n++
				return "PRIVATE-" + comment, "ssh-ed25519 AAAA" + comment, nil
			},
			HostCPUs: 10, HostMemGiB: 32, ReadyTimeout: 50 * time.Millisecond, Poll: time.Millisecond,
		}}, &out, &errb
}

func image(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "image.raw")
	b := make([]byte, 1024)
	copy(b[512:], "EFI PART")
	os.WriteFile(p, b, 0o600)
	return p
}

func TestInstall(t *testing.T) {
	d := &driver.Mock{Caps: driver.Capabilities{NestedVirt: true}, EP: driver.SSHEndpoint{Host: "h", Port: 1, User: "root", HostKey: "k"}}
	tr := &fakeTransport{release: goodRelease}
	env, out, errb := installEnv(t, d, tr)
	os.MkdirAll(filepath.Join(env.StateDir, "extra-ca-certs"), 0o755)
	os.WriteFile(filepath.Join(env.StateDir, "extra-ca-certs", "proxy-ca.crt"), []byte("CA1"), 0o644)
	os.WriteFile(filepath.Join(env.StateDir, "extra-ca-certs", "notes.txt"), []byte("no"), 0o644)
	img := image(t)
	rc := Run(context.Background(), []string{"install", "--dev-image", img, "--vm-disk=40"}, env)
	if rc != 0 || d.State != driver.Running {
		t.Fatalf("rc=%d state=%v\n%s%s", rc, d.State, out, errb)
	}
	if !strings.Contains(out.String(), "(mock; 8 CPUs, 26 GiB memory, 40 GiB disk)") || !strings.Contains(out.String(), "image 3.0.0, control API 1") {
		t.Errorf("out %q", out)
	}
	if !strings.Contains(errb.String(), "development image; its signature is not checked") {
		t.Errorf("no unsigned-image warning: %q", errb)
	}
	s := d.Created
	if s.AuthorizedKey != "ssh-ed25519 AAAAsandbox-client" || s.HostKeyPrivate != "PRIVATE-sandbox-vm" || s.CABundle != "CA1\n" ||
		d.Resource != (driver.Resources{CPUs: 8, MemoryMiB: 26 * 1024, DiskGiB: 40}) {
		t.Errorf("seed %+v resources %+v", s, d.Resource)
	}
	if b, _ := os.ReadFile(filepath.Join(env.StateDir, "vm", "id_ed25519")); string(b) != "PRIVATE-sandbox-client" {
		t.Errorf("client key %q", b)
	}
	if st, _ := os.Stat(filepath.Join(env.StateDir, "vm", "id_ed25519")); st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("client key mode %v", st.Mode())
	}
	// a second install refuses
	if rc := Run(context.Background(), []string{"setup", "--dev-image", img}, env); rc != 1 || !strings.Contains(errb.String(), "already exists") {
		t.Errorf("reinstall: rc=%d %q", rc, errb)
	}

	// uninstall without a terminal removes the VM and its keys, nothing else
	os.WriteFile(filepath.Join(env.StateDir, "config.yaml"), []byte("x"), 0o600)
	env.Driver = d
	if rc := Run(context.Background(), []string{"uninstall"}, env); rc != 0 || d.State != driver.NotCreated {
		t.Fatalf("uninstall rc=%d state=%v", rc, d.State)
	}
	if !strings.Contains(out.String(), "Kept your settings and profiles in ~/.sandbox.") {
		t.Errorf("out %q", out)
	}
	if _, err := os.Stat(filepath.Join(env.StateDir, "vm")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("vm state left: %v", err)
	}
	if _, err := os.Stat(filepath.Join(env.StateDir, "config.yaml")); err != nil {
		t.Errorf("uninstall removed operator state: %v", err)
	}
}

func TestInstallRefusals(t *testing.T) {
	img := image(t)
	notImage := filepath.Join(t.TempDir(), "hosts")
	os.WriteFile(notImage, []byte("127.0.0.1 localhost\n"), 0o600)
	qcow := filepath.Join(t.TempDir(), "x.qcow2")
	os.WriteFile(qcow, []byte("QFI\xfb\x00\x00\x00\x03"), 0o600)
	if err := checkDiskImage(qcow); err != nil {
		t.Errorf("qcow2 refused: %v", err)
	}
	for _, c := range []struct {
		args []string
		caps driver.Capabilities
		want string
	}{
		{[]string{}, driver.Capabilities{NestedVirt: true}, "no image"},
		{[]string{"--dev-image", "/nonexistent"}, driver.Capabilities{NestedVirt: true}, "is not a file"},
		{[]string{"--dev-image", notImage}, driver.Capabilities{NestedVirt: true}, "neither a qcow2 image nor a raw disk"},
		{[]string{"--dev-image", img, "--vm-cpus", "0"}, driver.Capabilities{NestedVirt: true}, "--vm-cpus must be >= 1"},
		{[]string{"--dev-image", img, "--dns", "1.1.1.1"}, driver.Capabilities{NestedVirt: true}, "removed in v3: the VM uses the host's upstream DNS"},
		{[]string{"--dev-image", img, "--pod-cidr=10.0.0.0/8"}, driver.Capabilities{NestedVirt: true}, "no Kubernetes"},
		{[]string{"--dev-image", img, "--bogus"}, driver.Capabilities{NestedVirt: true}, "unknown option '--bogus'"},
		{[]string{"--dev-image", img}, driver.Capabilities{Problems: []string{"nested KVM is disabled"}}, "nested KVM is disabled"},
	} {
		d := &driver.Mock{Caps: c.caps}
		env, _, errb := installEnv(t, d, &fakeTransport{release: goodRelease})
		if rc := Run(context.Background(), append([]string{"install"}, c.args...), env); rc != 1 || !strings.Contains(errb.String(), c.want) {
			t.Errorf("%q: rc=%d %q", c.args, rc, errb)
		}
		if d.Created != nil {
			t.Errorf("%q: a VM was created", c.args)
		}
	}
	// the VM never answers: install fails after the timeout, saying where to look
	d := &driver.Mock{Caps: driver.Capabilities{NestedVirt: true}, EP: driver.SSHEndpoint{Host: "h", Port: 1, User: "root", HostKey: "k"}}
	env, _, errb := installEnv(t, d, &fakeTransport{release: "", relErr: errors.New("connection refused")})
	if rc := Run(context.Background(), []string{"install", "--dev-image", img}, env); rc != 1 || !strings.Contains(errb.String(), "not answering") {
		t.Errorf("unanswering VM: rc=%d %q", rc, errb)
	}
	if rc := Run(context.Background(), []string{"uninstall", "--keep-lima"}, env); rc != 1 || !strings.Contains(errb.String(), "use --keep-vm") {
		t.Errorf("--keep-lima: %q", errb)
	}
}

func TestUninstallState(t *testing.T) {
	setup := func() Env {
		env, _, _ := installEnv(t, &driver.Mock{}, &fakeTransport{})
		for _, p := range []string{"secrets/GH_TOKEN", "logs/ses-1/session.json", "profiles/p.yaml", "quarantine/r/x/meta.json", "cache/x"} {
			os.MkdirAll(filepath.Dir(filepath.Join(env.StateDir, p)), 0o700)
			os.WriteFile(filepath.Join(env.StateDir, p), []byte("x"), 0o600)
		}
		os.WriteFile(filepath.Join(env.StateDir, "config.yaml"), []byte("x"), 0o600)
		return env
	}
	exists := func(env Env, p string) bool { _, err := os.Lstat(filepath.Join(env.StateDir, p)); return err == nil }

	// on a terminal: asked per category, default no
	env := setup()
	env.StdinTTY = true
	env.Stdin = strings.NewReader("y\n\nyes\nn\n") // secrets yes, quarantine no, logs yes, settings no
	var out bytes.Buffer
	env.Stdout = &out
	if rc := Run(context.Background(), []string{"uninstall"}, env); rc != 0 {
		t.Fatal(out.String())
	}
	if exists(env, "secrets") || !exists(env, "quarantine") || exists(env, "logs") || !exists(env, "profiles") || !exists(env, "config.yaml") || !exists(env, "cache/x") {
		t.Errorf("after prompts: %s", out.String())
	}
	if !strings.Contains(out.String(), "Remove your secrets and agent tokens (~/.sandbox/secrets)? [y/N] ") {
		t.Errorf("prompt %q", out.String())
	}
	// --purge removes every category, and only those
	env = setup()
	if rc := Run(context.Background(), []string{"uninstall", "--purge"}, env); rc != 0 {
		t.Fatal()
	}
	for _, p := range []string{"secrets", "quarantine", "logs", "profiles", "config.yaml"} {
		if exists(env, p) {
			t.Errorf("--purge left %s", p)
		}
	}
	if !exists(env, "cache/x") {
		t.Error("--purge removed state outside its categories")
	}
	// --keep-vm keeps the VM; without a terminal nothing else goes
	env = setup()
	d := &driver.Mock{State: driver.Stopped}
	env.Driver = d
	if rc := Run(context.Background(), []string{"uninstall", "--keep-vm"}, env); rc != 0 || d.State != driver.Stopped || !exists(env, "secrets") {
		t.Errorf("--keep-vm: state %v", d.State)
	}
}

func TestInstallDriverChoice(t *testing.T) {
	cases := []struct {
		args       []string
		kind, tool string
		fail       string
	}{
		{nil, "", "", ""},
		{[]string{"--driver", "lima"}, "lima", "", ""},
		{[]string{"--driver=vfkit"}, "vfkit", "", ""},
		{[]string{"--vfkit", "/opt/vfkit"}, "vfkit", "/opt/vfkit", ""},
		{[]string{"--limactl", "/opt/limactl", "--driver", "lima"}, "lima", "/opt/limactl", ""},
		{[]string{"--qemu", "/usr/bin/qemu-system-x86_64"}, "qemu", "/usr/bin/qemu-system-x86_64", ""},
		{[]string{"--driver", "qemu"}, "qemu", "", ""},
		{[]string{"--vfkit", "/a", "--limactl", "/b"}, "", "", "choose different drivers"},
		{[]string{"--qemu", "/a", "--vfkit", "/b"}, "", "", "choose different drivers"},
		{[]string{"--driver", "lima", "--vfkit", "/a"}, "", "", "does not apply"},
		{[]string{"--driver", "vfkit", "--qemu", "/a"}, "", "", "does not apply"},
		{[]string{"--driver", "xen"}, "", "", "unknown driver"},
	}
	for _, c := range cases {
		d := &driver.Mock{Caps: driver.Capabilities{NestedVirt: true}, EP: driver.SSHEndpoint{Host: "h", Port: 1, User: "root", HostKey: "k"}}
		env, out, errb := installEnv(t, d, &fakeTransport{release: goodRelease})
		var kind, tool string
		called := false
		env.Install.RecordDriver = func(k, tl string) (driver.Driver, error) {
			kind, tool, called = k, tl, true
			return d, nil
		}
		rc := Run(context.Background(), append([]string{"install", "--dev-image", image(t)}, c.args...), env)
		if c.fail != "" {
			if rc == 0 || called || !strings.Contains(errb.String(), c.fail) {
				t.Errorf("%v: rc=%d called=%v %q", c.args, rc, called, errb)
			}
			continue
		}
		if rc != 0 || kind != c.kind || tool != c.tool {
			t.Errorf("%v: rc=%d kind=%q tool=%q\n%s%s", c.args, rc, kind, tool, out, errb)
		}
	}
}
