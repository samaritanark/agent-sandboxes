package app

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/brokerkey"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

func runKey(t *testing.T, d driver.Driver, tr *fakeTransport, k brokerkey.Keeper, stdin string, args ...string) res {
	t.Helper()
	var out, errb bytes.Buffer
	rc := Run(context.Background(), args, Env{Driver: d, Transport: tr, Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb,
		StateDir: t.TempDir(), Now: func() time.Time { return time.Unix(1800000000, 0) }, BrokerKey: k,
		Install: InstallDeps{Poll: time.Millisecond}})
	return res{rc, out.String(), errb.String()}
}

func TestBrokerKeyPushedAtStart(t *testing.T) {
	k := brokerkey.File{Path: filepath.Join(t.TempDir(), "broker.key")}
	d := &driver.Mock{State: driver.Stopped}
	tr := &fakeTransport{release: goodRelease}
	r := runKey(t, d, tr, k, "", "vm", "start")
	if r.rc != 0 || !strings.Contains(r.out, "Made the credential broker's store key") {
		t.Fatalf("%+v", r)
	}
	key, _ := k.Load()
	if len(tr.ctl) != 1 || !reflect.DeepEqual(tr.ctl[0], []string{"ctl", "broker-key"}) || !bytes.Equal(tr.ctlIn[0], key) {
		t.Fatalf("pushed %q", tr.ctl)
	}
	for _, a := range tr.ctl[0] {
		if strings.Contains(a, string(key)) {
			t.Error("the key in an argument")
		}
	}
	// a running VM: pushed again (a restarted sandboxd gets it back), with the same key
	r = runKey(t, d, tr, k, "", "vm", "start")
	if r.rc != 0 || len(tr.ctl) != 2 || !bytes.Equal(tr.ctlIn[1], key) || strings.Contains(r.out, "Made") {
		t.Fatalf("again: %+v %q", r, tr.ctl)
	}
	// sandboxd refusing it is a warning: the VM is still usable
	tr.ctlRC = 1
	if r = runKey(t, d, tr, k, "", "vm", "start"); r.rc != 0 || !strings.Contains(r.err, "could not give the credential broker its key") {
		t.Fatalf("refused: %+v", r)
	}
}

func TestBrokerPut(t *testing.T) {
	k := brokerkey.File{Path: filepath.Join(t.TempDir(), "broker.key")}
	d := &driver.Mock{State: driver.Running}
	tr := &fakeTransport{release: goodRelease}
	if r := runKey(t, d, tr, k, "ghp_value\n", BrokerPut, "github"); r.rc != 0 {
		t.Fatalf("%+v", r)
	}
	key, _ := k.Load()
	if len(tr.ctl) != 1 || !reflect.DeepEqual(tr.ctl[0], []string{"ctl", "broker-put", "github"}) {
		t.Fatalf("%q", tr.ctl)
	}
	if bytes.Contains(tr.ctlIn[0], []byte("ghp_value")) {
		t.Fatal("the value reached the VM unsealed")
	}
	if v, err := brokerseal.Open(key, "github", tr.ctlIn[0]); err != nil || string(v) != "ghp_value" {
		t.Errorf("%q %v", v, err)
	}
	for _, bad := range [][]string{{BrokerPut}, {BrokerPut, "../x"}, {BrokerPut, "a", "b"}} {
		if r := runKey(t, d, tr, k, "v", bad...); r.rc != 1 {
			t.Errorf("%q: %+v", bad, r)
		}
	}
	if r := runKey(t, d, tr, k, "\n", BrokerPut, "empty"); r.rc != 1 || !strings.Contains(r.err, "no value") {
		t.Errorf("empty: %+v", r)
	}
}

func TestDoctorBrokerKey(t *testing.T) {
	k := brokerkey.File{Path: filepath.Join(t.TempDir(), "broker.key")}
	d := &driver.Mock{State: driver.Running}
	tr := &fakeTransport{release: goodRelease, reach: "blocked"}
	if r := runKey(t, d, tr, k, "", "doctor"); !strings.Contains(r.out, "ok    credential broker key in "+k.Path+": not made yet") {
		t.Errorf("absent: %s", r.out)
	}
	brokerkey.Get(k)
	if r := runKey(t, d, tr, k, "", "doctor"); r.rc != 0 || !strings.Contains(r.out, "warn  credential broker key in "+k.Path+": a plain file") {
		t.Errorf("file: %+v", r)
	}
}
