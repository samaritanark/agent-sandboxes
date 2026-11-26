package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

// TestFlows: the session's gateway records, one line each; a missing session is an error.
func TestFlows(t *testing.T) {
	state := t.TempDir()
	dir := filepath.Join(state, "logs", "ses-20261126-213445-5114")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "flows.jsonl"), []byte(
		`{"type":"request","decision":"allowed","authority":"api.anthropic.com","method":"POST","path":"/v1/messages","status":200,"rule":"default:forward","start":"2026-11-26T22:37:00Z"}`+"\n"+
			`{"type":"flow","decision":"denied","sni":"evil.example.com","port":443,"reason":"not on the allowlist","start":"2026-11-26T22:37:01Z"}`+"\n"+
			`{"type":"flow","decision":"dependency","dependency":"pg","port":5432,"start":"2026-11-26T22:37:02Z"}`+"\n"+
			"not json\n"), 0o600)
	run := func(args ...string) res {
		var out, errb bytes.Buffer
		rc := Run(context.Background(), append([]string{"flows"}, args...), Env{Driver: &driver.Mock{State: driver.Stopped},
			Transport: &fakeTransport{}, Stdout: &out, Stderr: &errb, StateDir: state, Now: func() time.Time { return time.Unix(1800000000, 0) }})
		return res{rc, out.String(), errb.String()}
	}
	r := run("ses-20261126-213445-5114")
	want := "=== Gateway flows for ses-20261126-213445-5114 ===\n" +
		"2026-11-26T22:37:00Z  allowed     api.anthropic.com  POST  /v1/messages  200  default:forward\n" +
		"2026-11-26T22:37:01Z  denied      evil.example.com  (not on the allowlist)\n" +
		"2026-11-26T22:37:02Z  dependency  pg:5432\n"
	if r.rc != 0 || r.out != want {
		t.Errorf("%d\n%s", r.rc, r.out)
	}
	if r := run("ses-missing"); r.rc != 1 || !strings.Contains(r.err, "Session not found") {
		t.Errorf("%+v", r)
	}
	os.MkdirAll(filepath.Join(state, "x"), 0o700)
	os.WriteFile(filepath.Join(state, "x", "flows.jsonl"), []byte(`{"decision":"allowed"}`+"\n"), 0o600)
	if r := run("../x"); r.rc != 1 || strings.Contains(r.out, "allowed") {
		t.Errorf("%+v", r)
	}
}
