package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/brokerkey"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

// runState runs one command with a state directory holding a profile and a secret store.
func runState(t *testing.T, tr *fakeTransport, k brokerkey.Keeper, state string, args ...string) res {
	t.Helper()
	var out, errb bytes.Buffer
	rc := Run(context.Background(), args, Env{Driver: &driver.Mock{State: driver.Running}, Transport: tr,
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, StateDir: state,
		Now: func() time.Time { return time.Unix(1800000000, 0) }, BrokerKey: k})
	return res{rc, out.String(), errb.String()}
}

func secretState(t *testing.T) (string, brokerkey.Keeper) {
	state := t.TempDir()
	os.MkdirAll(filepath.Join(state, "profiles"), 0o700)
	os.MkdirAll(filepath.Join(state, "secrets"), 0o700)
	os.WriteFile(filepath.Join(state, "profiles", "p.yaml"), []byte("tier: 1\nsecrets:\n  - GH_TOKEN\n  - GONE\n"), 0o600)
	os.WriteFile(filepath.Join(state, "secrets", "GH_TOKEN"), []byte("ghp_value\n"), 0o600)
	os.WriteFile(filepath.Join(state, "secrets", "UNNAMED"), []byte("other"), 0o600)
	return state, brokerkey.File{Path: filepath.Join(state, "broker.key")}
}

// TestRunPushesBoundSecrets: the names the VM gives are shown, each present one is sealed under its
// reference (the bytes as stored), a missing one is removed from the VM's store, and the run
// follows.
func TestRunPushesBoundSecrets(t *testing.T) {
	state, k := secretState(t)
	tr := &fakeTransport{release: goodRelease, bindings: `{"secrets":["GH_TOKEN","GONE"],"repos":[]}`}
	r := runState(t, tr, k, state, "run", "--profile", "p")
	if r.rc != 0 || !strings.Contains(r.out, "==> Sealing this launch's secrets for the sandbox VM: GH_TOKEN GONE\n") {
		t.Fatalf("%+v", r)
	}
	if !reflect.DeepEqual(tr.bindingArgs, [][]string{{"--profile", "p"}}) {
		t.Errorf("pre-pass args %q", tr.bindingArgs)
	}
	want := [][]string{{"ctl", "broker-put", "secret.GH_TOKEN"}, {"ctl", "broker-delete", "secret.GONE"}}
	if !reflect.DeepEqual(tr.ctl, want) {
		t.Fatalf("ctl %q", tr.ctl)
	}
	key, _ := k.Load()
	if v, err := brokerseal.Open(key, "secret.GH_TOKEN", tr.ctlIn[0]); err != nil || string(v) != "ghp_value\n" {
		t.Errorf("%q %v", v, err)
	}
	if len(tr.runs) != 1 || tr.runs[0][1] != "run" {
		t.Errorf("runs %q", tr.runs)
	}
}

// TestRunRefusesUnnamedSecret: a name in the store that neither the command line nor a pushed
// profile mentions is refused, and nothing is pushed or run.
func TestRunRefusesUnnamedSecret(t *testing.T) {
	state, k := secretState(t)
	tr := &fakeTransport{release: goodRelease, bindings: `{"secrets":["GH_TOKEN","UNNAMED"],"repos":[]}`}
	r := runState(t, tr, k, state, "run", "--profile", "p")
	if r.rc != 1 || !strings.Contains(r.err, "asked for secret 'UNNAMED'") || len(tr.ctl) != 0 || len(tr.runs) != 0 {
		t.Fatalf("%+v ctl %q runs %q", r, tr.ctl, tr.runs)
	}
	// a part of a word is not a mention
	os.WriteFile(filepath.Join(state, "profiles", "q.yaml"), []byte("note: XUNNAMED UNNAMEDX\n"), 0o600)
	if r := runState(t, tr, k, state, "run"); r.rc != 1 {
		t.Errorf("a partial word counted: %+v", r)
	}
	// named on the command line, or in config.yaml, it passes
	tr = &fakeTransport{release: goodRelease, bindings: `{"secrets":["UNNAMED"],"repos":[]}`}
	if r := runState(t, tr, k, state, "run", "--name", "for-UNNAMED"); r.rc != 0 || len(tr.ctl) != 1 {
		t.Errorf("on the command line: %+v %q", r, tr.ctl)
	}
	os.WriteFile(filepath.Join(state, "config.yaml"), []byte("# UNNAMED\n"), 0o600)
	tr = &fakeTransport{release: goodRelease, bindings: `{"secrets":["UNNAMED"],"repos":[]}`}
	if r := runState(t, tr, k, state, "run"); r.rc != 0 || len(tr.ctl) != 1 {
		t.Errorf("in config.yaml: %+v %q", r, tr.ctl)
	}
	// a file outside the pushed set, or a pushed one that is not a profile, does not count
	os.Remove(filepath.Join(state, "config.yaml"))
	os.WriteFile(filepath.Join(state, "notes.txt"), []byte("UNNAMED\n"), 0o600)
	os.MkdirAll(filepath.Join(state, "extra-ca-certs"), 0o700)
	os.WriteFile(filepath.Join(state, "extra-ca-certs", "UNNAMED.pem"), []byte("UNNAMED\n"), 0o600)
	tr = &fakeTransport{release: goodRelease, bindings: `{"secrets":["UNNAMED"],"repos":[]}`}
	if r := runState(t, tr, k, state, "run"); r.rc != 1 {
		t.Errorf("an unpushed file counted: %+v", r)
	}
}

// TestRunBindingsOutputChecked: anything but the exact shape stops the launch before a push.
func TestRunBindingsOutputChecked(t *testing.T) {
	state, k := secretState(t)
	many := `{"secrets":["N0"`
	for i := 1; i <= maxBoundSecrets; i++ {
		many += `,"N` + strconv.Itoa(i) + `"`
	}
	for _, bad := range []string{`{"secrets":["gh_token"],"repos":[]}`, `{"secrets":["A","A"],"repos":[]}`, `{"secrets":["A"],"x":1}`, `{"secrets":[],"repos":[],"x":1}`,
		`{}`, `{"secrets":["A"]}{}`, `[]`, `{"secrets":["../x"],"repos":[]}`, many + "]}"} {
		tr := &fakeTransport{release: goodRelease, bindings: bad}
		if r := runState(t, tr, k, state, "run", "A", "gh_token"); r.rc != 1 || !strings.Contains(r.err, "invalid") || len(tr.runs) != 0 {
			t.Errorf("%s: %+v", bad, r)
		}
	}
	// the pre-pass failing pushes nothing; the run says why
	tr := &fakeTransport{release: goodRelease, bindingsErr: errors.New("exit status 1")}
	if r := runState(t, tr, k, state, "run", "--bogus"); r.rc != 0 || len(tr.ctl) != 0 || len(tr.runs) != 1 {
		t.Errorf("failed pre-pass: %+v", r)
	}
	// no secrets: nothing pushed, no key made
	tr = &fakeTransport{release: goodRelease, bindings: `{"secrets":[],"repos":[]}`}
	if r := runState(t, tr, k, state, "run"); r.rc != 0 || len(tr.ctl) != 0 || strings.Contains(r.out, "Sealing") {
		t.Errorf("none: %+v", r)
	}
	if _, err := k.Load(); err == nil {
		t.Error("a key made for a launch without secrets")
	}
	// other commands have no pre-pass
	tr = &fakeTransport{release: goodRelease, bindings: `{"secrets":["GH_TOKEN"],"repos":[]}`}
	runState(t, tr, k, state, "list")
	if len(tr.bindingArgs) != 0 {
		t.Error("pre-pass for list")
	}
}

// TestRunSecretTooLarge: a secret over the limit stops the launch.
func TestRunSecretTooLarge(t *testing.T) {
	state, k := secretState(t)
	os.WriteFile(filepath.Join(state, "secrets", "GH_TOKEN"), bytes.Repeat([]byte("x"), MaxSecretSize+1), 0o600)
	tr := &fakeTransport{release: goodRelease, bindings: `{"secrets":["GH_TOKEN"],"repos":[]}`}
	if r := runState(t, tr, k, state, "run", "--profile", "p"); r.rc != 1 || !strings.Contains(r.err, "larger than") || len(tr.ctl) != 0 {
		t.Errorf("%+v", r)
	}
}

// TestMirroredHome: with the operator's home known, the state push names it (the VM links its
// .sandbox to the pushed state) and every proxied command and the pre-pass run with it as HOME.
func TestMirroredHome(t *testing.T) {
	state, _ := secretState(t)
	tr := &fakeTransport{release: goodRelease}
	var out, errb bytes.Buffer
	rc := Run(context.Background(), []string{"run", "--repo", "~/x"}, Env{Driver: &driver.Mock{State: driver.Running}, Transport: tr,
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, StateDir: state, Home: "/Users/op",
		Now: func() time.Time { return time.Unix(1800000000, 0) }})
	if rc != 0 {
		t.Fatalf("%d %s", rc, errb.String())
	}
	if !reflect.DeepEqual(tr.pushArgs, [][]string{{"/Users/op"}}) {
		t.Errorf("push args %q", tr.pushArgs)
	}
	want := []string{"env", "HOME=/Users/op", "sandbox", "run", "--repo", "~/x"}
	if !reflect.DeepEqual(tr.runs[0], want) || !reflect.DeepEqual(tr.bindingArgv[0][:3], want[:3]) {
		t.Errorf("runs %q pre-pass %q", tr.runs, tr.bindingArgv)
	}
	// a home the VM cannot mirror (Windows) leaves HOME alone
	tr = &fakeTransport{release: goodRelease}
	Run(context.Background(), []string{"list"}, Env{Driver: &driver.Mock{State: driver.Running}, Transport: tr,
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, StateDir: state, Home: `C:\Users\op`})
	if tr.runs[0][0] != "sandbox" || len(tr.pushArgs[0]) != 0 {
		t.Errorf("windows home: %q %q", tr.runs, tr.pushArgs)
	}
}

// TestRepoNamed: a repository the VM asks to sync must be a --repo value (made absolute on the
// host, "~" as the home) or written in a pushed profile, as itself or in its "~/" form.
func TestRepoNamed(t *testing.T) {
	args := absRepos([]string{"--repo", "rel/app", "--repo=~/b", "--repo", "/abs/c", "--name", "/not/a/repo", "--repo=d"}, "/wd")
	if !reflect.DeepEqual(args, []string{"--repo", "/wd/rel/app", "--repo=~/b", "--repo", "/abs/c", "--name", "/not/a/repo", "--repo=/wd/d"}) {
		t.Fatalf("%q", args)
	}
	texts := [][]byte{[]byte("default_repo: ~/code/app\n"), []byte("default_repo: /srv/full\n")}
	for p, want := range map[string]bool{
		"/wd/rel/app": true, "/Users/op/b": true, "/abs/c": true, "/Users/op/code/app": true, "/srv/full": true,
		"/not/a/repo": false, "/Users/op/secret": false, "/abs": false,
	} {
		if got := repoNamed(p, args, texts, "/Users/op"); got != want {
			t.Errorf("%s: %v", p, got)
		}
	}
}

// TestRunRefusesUnnamedRepo: the pre-pass naming a repository nobody named stops the launch before
// anything is pushed or synced; so does a path that is not clean and absolute.
func TestRunRefusesUnnamedRepo(t *testing.T) {
	state, k := secretState(t)
	for bindings, want := range map[string]string{
		`{"secrets":["GH_TOKEN"],"repos":["/Users/op/.ssh"]}`: "asked to sync /Users/op/.ssh",
		`{"secrets":[],"repos":["rel"]}`:                      "invalid",
		`{"secrets":[],"repos":["/a/../b"]}`:                  "invalid",
		`{"secrets":[],"repos":["/a","/a"]}`:                  "invalid",
		`{"secrets":[]}`:                                      "invalid",
		`{"secrets":[],"repos":["/r0"` + strings.Repeat(`,"/r"`, 0) + manyRepos() + `]}`: "more than 16",
	} {
		tr := &fakeTransport{release: goodRelease, bindings: bindings}
		r := runState(t, tr, k, state, "run", "--profile", "p")
		if r.rc != 1 || !strings.Contains(r.err, want) || len(tr.ctl) != 0 || len(tr.runs) != 0 {
			t.Errorf("%s: %+v ctl %q runs %q", bindings, r, tr.ctl, tr.runs)
		}
	}
}

func manyRepos() string {
	var b strings.Builder
	for i := 1; i <= maxRepos; i++ {
		b.WriteString(`,"/r` + strconv.Itoa(i) + `"`)
	}
	return b.String()
}

// TestCopyEpoch: the epoch is read as the VM gives it, and anything but 32 hex digits is refused.
func TestCopyEpoch(t *testing.T) {
	for epoch, ok := range map[string]bool{"72b912d4a93adb6c0644659a26ecaf24\n": true, "": false, "72b912d4": false, "../x": false,
		"72b912d4a93adb6c0644659a26ecaf24x": false} {
		a := &app{env: Env{Transport: &fakeTransport{epoch: epoch}}, ctx: context.Background()}
		got, err := a.copyEpoch(driver.SSHEndpoint{}, "/var/lib/sandbox/workspaces/0123456789abcdef")
		if (err == nil) != ok || (ok && got != strings.TrimSpace(epoch)) {
			t.Errorf("%q: %q %v", epoch, got, err)
		}
	}
}
