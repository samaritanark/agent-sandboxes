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
	tr := &fakeTransport{release: goodRelease, bindings: `{"secrets":["GH_TOKEN","GONE"]}`}
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
	tr := &fakeTransport{release: goodRelease, bindings: `{"secrets":["GH_TOKEN","UNNAMED"]}`}
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
	tr = &fakeTransport{release: goodRelease, bindings: `{"secrets":["UNNAMED"]}`}
	if r := runState(t, tr, k, state, "run", "--name", "for-UNNAMED"); r.rc != 0 || len(tr.ctl) != 1 {
		t.Errorf("on the command line: %+v %q", r, tr.ctl)
	}
	os.WriteFile(filepath.Join(state, "config.yaml"), []byte("# UNNAMED\n"), 0o600)
	tr = &fakeTransport{release: goodRelease, bindings: `{"secrets":["UNNAMED"]}`}
	if r := runState(t, tr, k, state, "run"); r.rc != 0 || len(tr.ctl) != 1 {
		t.Errorf("in config.yaml: %+v %q", r, tr.ctl)
	}
	// a file outside the pushed set, or a pushed one that is not a profile, does not count
	os.Remove(filepath.Join(state, "config.yaml"))
	os.WriteFile(filepath.Join(state, "notes.txt"), []byte("UNNAMED\n"), 0o600)
	os.MkdirAll(filepath.Join(state, "extra-ca-certs"), 0o700)
	os.WriteFile(filepath.Join(state, "extra-ca-certs", "UNNAMED.pem"), []byte("UNNAMED\n"), 0o600)
	tr = &fakeTransport{release: goodRelease, bindings: `{"secrets":["UNNAMED"]}`}
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
	for _, bad := range []string{`{"secrets":["gh_token"]}`, `{"secrets":["A","A"]}`, `{"secrets":["A"],"x":1}`,
		`{}`, `{"secrets":["A"]}{}`, `[]`, `{"secrets":["../x"]}`, many + "]}"} {
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
	tr = &fakeTransport{release: goodRelease, bindings: `{"secrets":[]}`}
	if r := runState(t, tr, k, state, "run"); r.rc != 0 || len(tr.ctl) != 0 || strings.Contains(r.out, "Sealing") {
		t.Errorf("none: %+v", r)
	}
	if _, err := k.Load(); err == nil {
		t.Error("a key made for a launch without secrets")
	}
	// other commands have no pre-pass
	tr = &fakeTransport{release: goodRelease, bindings: `{"secrets":["GH_TOKEN"]}`}
	runState(t, tr, k, state, "list")
	if len(tr.bindingArgs) != 0 {
		t.Error("pre-pass for list")
	}
}

// TestRunSecretTooLarge: a secret over the limit stops the launch.
func TestRunSecretTooLarge(t *testing.T) {
	state, k := secretState(t)
	os.WriteFile(filepath.Join(state, "secrets", "GH_TOKEN"), bytes.Repeat([]byte("x"), MaxSecretSize+1), 0o600)
	tr := &fakeTransport{release: goodRelease, bindings: `{"secrets":["GH_TOKEN"]}`}
	if r := runState(t, tr, k, state, "run", "--profile", "p"); r.rc != 1 || !strings.Contains(r.err, "larger than") || len(tr.ctl) != 0 {
		t.Errorf("%+v", r)
	}
}
