package lima

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

var seed = driver.SeedConfig{
	Hostname:       "sandbox",
	AuthorizedKey:  "ssh-ed25519 AAAAclient op@host",
	HostKeyPrivate: "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n",
	HostKeyPublic:  "ssh-ed25519 AAAAguest",
	CABundle:       "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
	DNS:            []string{"1.1.1.1", "9.9.9.9"},
}
var res = driver.Resources{CPUs: 4, MemoryMiB: 8192, DiskGiB: 40}
var img = driver.ImageRef{Path: "/state/image.raw", Format: "raw", Version: "3.0.0"}

func decode(t *testing.T, b []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestConfigHardening(t *testing.T) {
	b, err := Config("darwin", "arm64", img, res, seed)
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, b)
	want := map[string]interface{}{
		"vmType": "vz", "arch": "aarch64", "cpus": 4.0, "memory": "8192MiB", "disk": "40GiB",
		"mounts": []interface{}{}, "plain": true, "propagateProxyEnv": false, "upgradePackages": false,
		"nestedVirtualization": true,
		"networkOpts":          map[string]interface{}{"hostLoopback": false},
		"containerd":           map[string]interface{}{"system": false, "user": false},
		"ssh": map[string]interface{}{"localPort": 0.0, "loadDotSSHPubKeys": false, "forwardAgent": false,
			"forwardX11": false, "forwardX11Trusted": false},
		"portForwards": []interface{}{map[string]interface{}{"guestIP": "0.0.0.0", "proto": "any", "ignore": true}},
		"vmOpts":       map[string]interface{}{"vz": map[string]interface{}{"rosetta": map[string]interface{}{"enabled": false, "binfmt": false}}},
		"images":       []interface{}{map[string]interface{}{"location": "/state/image.raw", "arch": "aarch64"}},
	}
	for k, v := range want {
		if !reflect.DeepEqual(m[k], v) {
			t.Errorf("%s = %#v, want %#v", k, m[k], v)
		}
	}
	if _, ok := m["env"]; ok {
		t.Error("the config must not use env: (Lima copies it into /etc/environment)")
	}
	prov := m["provision"].([]interface{})
	if len(prov) != 1 {
		t.Fatalf("provision %v", prov)
	}
	pr := prov[0].(map[string]interface{})
	if pr["mode"] != "data" || pr["path"] != SeedPath || pr["owner"] != "root:root" || pr["permissions"] != 600.0 {
		t.Errorf("seed provision %v", pr)
	}
	vals := map[string]string{}
	for _, l := range strings.Split(strings.TrimSuffix(pr["content"].(string), "\n"), "\n") {
		k, v, _ := strings.Cut(l, "=")
		vals[k] = v
		if strings.ContainsFunc(v, func(r rune) bool { return r < ' ' || r == 0x7f }) {
			t.Errorf("seed %s is not one printable line", k)
		}
	}
	if k, _ := base64.StdEncoding.DecodeString(vals[SeedHostKey]); string(k) != seed.HostKeyPrivate {
		t.Errorf("host key %q", vals[SeedHostKey])
	}
	if vals[SeedDNS] != "1.1.1.1 9.9.9.9" || vals[SeedHostKeyPub] != seed.HostKeyPublic || vals[SeedAuthorizedKey] != seed.AuthorizedKey || len(vals) != 7 {
		t.Errorf("seed %v", vals)
	}

	q := decode(t, must(Config("linux", "amd64", img, res, seed)))
	if q["vmType"] != "qemu" || q["arch"] != "x86_64" || q["networkOpts"] != nil || q["vmOpts"] != nil || q["nestedVirtualization"] != nil || q["plain"] != true {
		t.Errorf("linux/amd64 config: %v", q)
	}
	if a := decode(t, must(Config("linux", "arm64", img, res, seed))); a["nestedVirtualization"] != true {
		t.Error("linux/arm64 should ask for nested virtualization")
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func TestConfigRefusals(t *testing.T) {
	bad := func(name string, goarch string, i driver.ImageRef, r driver.Resources, s driver.SeedConfig) {
		if _, err := Config("darwin", goarch, i, r, s); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	bad("arch", "386", img, res, seed)
	bad("relative image", "arm64", driver.ImageRef{Path: "image.raw"}, res, seed)
	bad("no cpus", "arm64", img, driver.Resources{MemoryMiB: 4096, DiskGiB: 10}, seed)
	s := seed
	s.Hostname = "a\nb"
	bad("newline in hostname", "arm64", img, res, s)
	s = seed
	s.DNS = []string{"1.1.1.1 2.2.2.2"}
	bad("space in DNS", "arm64", img, res, s)
	s = seed
	s.Proxy = "http://{{.Home}}/"
	bad("template marker", "arm64", img, res, s)
	s = seed
	s.HostKeyPrivate = ""
	bad("no host key", "arm64", img, res, s)
}

// TestConfigLimaValidates runs the real limactl, when installed, over the rendered config.
func TestConfigLimaValidates(t *testing.T) {
	lc, err := exec.LookPath("limactl")
	if err != nil {
		t.Skip("limactl not installed")
	}
	dir := t.TempDir()
	i := img
	i.Path = filepath.Join(dir, "image.raw")
	os.WriteFile(i.Path, []byte("x"), 0o600)
	for _, goarch := range []string{"arm64", "amd64"} {
		f := filepath.Join(dir, "sandbox-"+goarch+".yaml")
		os.WriteFile(f, must(Config("darwin", goarch, i, res, seed)), 0o600)
		if out, err := exec.Command(lc, "validate", f).CombinedOutput(); err != nil {
			t.Errorf("limactl validate (%s): %v\n%s", goarch, err, out)
		}
	}
}

type fakeLima struct {
	list  string
	calls [][]string
	cfg   []byte
	err   error
}

func (f *fakeLima) exec(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if len(args) > 2 && args[1] == "create" {
		f.cfg, _ = os.ReadFile(args[len(args)-1])
	}
	if len(args) > 1 && args[1] == "list" {
		return []byte(f.list), f.err
	}
	return nil, f.err
}

func newFake(t *testing.T, list string) (*Driver, *fakeLima) {
	f := &fakeLima{list: list}
	return &Driver{Limactl: "/opt/lima/limactl", Instance: Instance, StateDir: t.TempDir(), GOOS: "darwin", GOARCH: "arm64", Exec: f.exec}, f
}

func TestStatus(t *testing.T) {
	other := `{"name":"other","status":"Running","sshLocalPort":1}` + "\n"
	for list, want := range map[string]driver.State{
		"":    driver.NotCreated,
		other: driver.NotCreated,
		other + `{"name":"sandbox-v3","status":"Running","sshLocalPort":60022}` + "\n": driver.Running,
		`{"name":"sandbox-v3","status":"Stopped"}`:                                     driver.Stopped,
		`{"name":"sandbox-v3","status":"Broken"}`:                                      driver.Broken,
	} {
		d, _ := newFake(t, list)
		if got, err := d.Status(context.Background()); err != nil || got != want {
			t.Errorf("list %q: %v %v, want %v", list, got, err, want)
		}
	}
	d, _ := newFake(t, "not json\n")
	if _, err := d.Status(context.Background()); err == nil {
		t.Error("garbage list output: no error")
	}
}

func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	d, f := newFake(t, "")
	if err := d.Create(ctx, img, res, seed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(f.cfg), `"hostLoopback": false`) {
		t.Errorf("limactl create got %q", f.cfg)
	}
	create := f.calls[len(f.calls)-1]
	if create[0] != "/opt/lima/limactl" || create[1] != "--tty=false" || create[2] != "create" || create[3] != "--name=sandbox-v3" {
		t.Errorf("create argv %q", create)
	}
	if _, err := os.Stat(create[4]); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the staged config (with the private host key) was left behind: %v", err)
	}
	if b, _ := os.ReadFile(hostKeyRecord(d.StateDir)); string(b) != "ssh-ed25519 AAAAguest\n" {
		t.Errorf("pinned key %q", b)
	}
	f.list = `{"name":"sandbox-v3","status":"Stopped"}`
	if err := d.Create(ctx, img, res, seed); err == nil {
		t.Error("Create over an existing instance: no error")
	}
	if _, err := d.Endpoint(ctx); err == nil {
		t.Error("Endpoint of a stopped instance: no error")
	}
	f.list = `{"name":"sandbox-v3","status":"Running","sshLocalPort":60022}`
	ep, err := d.Endpoint(ctx)
	if err != nil || ep != (driver.SSHEndpoint{Host: "127.0.0.1", Port: 60022, User: "root", HostKey: "ssh-ed25519 AAAAguest"}) {
		t.Errorf("endpoint %+v %v", ep, err)
	}
	f.list = `{"name":"sandbox-v3","status":"Running","sshLocalPort":70000}`
	if _, err := d.Endpoint(ctx); err == nil {
		t.Error("out-of-range port: no error")
	}
	d.Start(ctx)
	d.Stop(ctx)
	if err := d.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	n := len(f.calls)
	for i, want := range [][]string{{"start", "sandbox-v3"}, {"stop", "sandbox-v3"}, {"delete", "--force", "sandbox-v3"}} {
		if got := f.calls[n-3+i][2:]; !reflect.DeepEqual(got, want) {
			t.Errorf("call %q, want %q", got, want)
		}
	}
	if _, err := os.Stat(hostKeyRecord(d.StateDir)); !errors.Is(err, os.ErrNotExist) {
		t.Error("Delete left the pinned key")
	}
}

func TestHostReach(t *testing.T) {
	d, _ := newFake(t, "")
	if hr, _ := d.HostReach(context.Background()); !hr.BlocksAll || d.Name() != "lima-vz" {
		t.Errorf("vz: %+v %s", hr, d.Name())
	}
	d.GOOS = "linux"
	if hr, _ := d.HostReach(context.Background()); hr.BlocksAll || hr.Scoped || d.Name() != "lima-qemu" {
		t.Errorf("qemu: %+v", hr)
	}
}

func TestStopFallsBackToForce(t *testing.T) {
	d, f := newFake(t, "")
	calls := 0
	d.Exec = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		f.calls = append(f.calls, args)
		calls++
		if calls == 1 {
			return nil, errors.New("did not receive an event with the exiting status")
		}
		return nil, nil
	}
	if err := d.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"--tty=false", "stop", "--force", "sandbox-v3"}; !reflect.DeepEqual(f.calls[1], want) {
		t.Errorf("second call %q", f.calls[1])
	}
}
