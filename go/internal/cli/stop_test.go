package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

func sessionJSON(t *testing.T, e Env, id, body string) string {
	dir := e.LogsDir + "/" + id
	os.MkdirAll(dir, 0o755)
	os.WriteFile(dir+"/session.json", []byte(body), 0o644)
	return dir + "/session.json"
}

// TestStop: a live session is stopped through sandboxd and its record gets v2's end time; one
// sandboxd no longer holds is reported as already stopped; a failed teardown is recorded as
// incomplete; the infra reminders follow the record.
func TestStop(t *testing.T) {
	e, fs, _ := launchEnv(t)
	fs.started = []*sessionspec.Spec{{ID: "ses-a"}}
	sj := sessionJSON(t, e, "ses-a", `{"session_id":"ses-a","pod_name":"sandbox-x-a","tier":"1","infra_token":true}`)
	var out, errb bytes.Buffer
	if rc := Run([]string{"stop", "ses-a"}, e, &out, &errb); rc != 0 {
		t.Fatalf("%d %s", rc, errb.String())
	}
	if out.String() != "==> Stopping session: ses-a\n  Pod deleted.\n\nSession ses-a stopped.\nLogs: "+e.LogsDir+"/ses-a\n" ||
		!strings.Contains(errb.String(), "REMINDER: Revoke infra token used in this session.") {
		t.Errorf("out %q err %q", out.String(), errb.String())
	}
	if b, _ := os.ReadFile(sj); !strings.Contains(string(b), `"end_time"`) || strings.Contains(string(b), "end_reason") {
		t.Errorf("record %s", b)
	}
	// again: sandboxd no longer has it running
	out.Reset()
	errb.Reset()
	Run([]string{"stop", "ses-a"}, e, &out, &errb)
	if !strings.Contains(errb.String(), "Pod sandbox-x-a not found (already stopped).") || strings.Contains(out.String(), "Pod deleted") {
		t.Errorf("again: %q %q", out.String(), errb.String())
	}
	// a teardown that fails
	e, fs, _ = launchEnv(t)
	fs.started = []*sessionspec.Spec{{ID: "ses-b"}}
	fs.stopErr = errors.New("netns busy\ndetail")
	sj = sessionJSON(t, e, "ses-b", `{"session_id":"ses-b"}`)
	errb.Reset()
	Run([]string{"stop", "ses-b"}, e, &bytes.Buffer{}, &errb)
	if b, _ := os.ReadFile(sj); !strings.Contains(string(b), `"end_reason": "teardown-incomplete"`) || !strings.Contains(errb.String(), "INCOMPLETE") {
		t.Errorf("failed teardown: %s %q", b, errb.String())
	}
	// no session id
	if rc := Run([]string{"stop"}, e, &bytes.Buffer{}, &errb); rc != 1 {
		t.Errorf("no id: %d", rc)
	}
}

// TestListActive: list's active section is sandboxd's live sessions in kubectl's column layout,
// nothing when there are none, and v2's "(could not reach cluster)" when sandboxd cannot answer.
func TestListActive(t *testing.T) {
	e, fs, _ := launchEnv(t)
	fs.started = []*sessionspec.Spec{{ID: "ses-20261126-101500-ab12"}}
	sessionJSON(t, e, "ses-20261126-101500-ab12", `{"agent":"claude","tier":"2","name":"app/claude","start_time":"2026-11-26T10:15:00Z"}`)
	var out bytes.Buffer
	Run([]string{"list"}, e, &out, &bytes.Buffer{})
	want := "Active pods in namespace 'sandbox':\n\n" +
		"SESSION                    AGENT    TIER   NAME         STATUS    AGE\n" +
		"ses-20261126-101500-ab12   claude   2      app/claude   Running   2026-11-26T10:15:00Z\n\n"
	if !strings.HasPrefix(out.String(), want) {
		t.Errorf("got\n%s\nwant\n%s", out.String(), want)
	}
	fs.started = nil
	out.Reset()
	Run([]string{"list"}, e, &out, &bytes.Buffer{})
	if !strings.HasPrefix(out.String(), "Active pods in namespace 'sandbox':\n\n\nRecent sessions") {
		t.Errorf("none: %q", out.String())
	}
	fs.listErr = errors.New("down")
	out.Reset()
	Run([]string{"list"}, e, &out, &bytes.Buffer{})
	if !strings.Contains(out.String(), "\n(could not reach cluster)\n") {
		t.Errorf("down: %q", out.String())
	}
}

// TestResumeOnSandboxd: a live session is attached with the agent's resume command and kept or
// stopped after as v2 did; a stopped one prints the relaunch command.
func TestResumeOnSandboxd(t *testing.T) {
	e, fs, _ := launchEnv(t)
	e.SessionPhase, e.RecreateSession, e.Attach = nil, nil, nil
	fs.started = []*sessionspec.Spec{{ID: "ses-r"}}
	sessionJSON(t, e, "ses-r", `{"agent":"claude","tier":"1","agent_session_id":"u-1"}`)
	var out, errb bytes.Buffer
	if rc := Run([]string{"resume", "ses-r", "--keep-alive"}, e, &out, &errb); rc != 0 {
		t.Fatalf("%d %s", rc, errb.String())
	}
	if len(fs.attached) != 1 || strings.Join(fs.attached[0], " ") != "ses-r claude --resume u-1" || !strings.Contains(out.String(), "(pod kept alive).") || len(fs.stopped) != 0 {
		t.Errorf("keep-alive: %q %q %q", fs.attached, out.String(), fs.stopped)
	}
	out.Reset()
	Run([]string{"resume", "ses-r"}, e, &out, &errb)
	if strings.Join(fs.stopped, ",") != "ses-r operator stop" || !strings.Contains(out.String(), "Session ses-r stopped.") {
		t.Errorf("teardown: %q %q", fs.stopped, out.String())
	}
	errb.Reset()
	if rc := Run([]string{"resume", "ses-r"}, e, &bytes.Buffer{}, &errb); rc != 1 || !strings.Contains(errb.String(), "not yet available in v3") || !strings.Contains(errb.String(), "sandbox run --agent claude --tier 1") {
		t.Errorf("stopped: %d %q", rc, errb.String())
	}
}

// TestSessionRepos: the repositories a session's record names, for the host's resume sync.
func TestSessionRepos(t *testing.T) {
	logs := t.TempDir()
	id := "ses-20261126-213445-5114"
	os.MkdirAll(filepath.Join(logs, id), 0o755)
	os.WriteFile(filepath.Join(logs, id, "session.json"), []byte(`{"id":"`+id+`","repos":["/h/a","/h/b"]}`), 0o644)
	if r, ok := SessionRepos(id, Env{LogsDir: logs}); !ok || strings.Join(r, ",") != "/h/a,/h/b" {
		t.Errorf("%q %v", r, ok)
	}
	os.MkdirAll(filepath.Join(logs, "x"), 0o755)
	os.WriteFile(filepath.Join(logs, "x", "session.json"), []byte(`{"repos":["/h/a"]}`), 0o644)
	for _, bad := range []string{"ses-20261126-213445-0000", "../" + id, "", "x"} {
		if _, ok := SessionRepos(bad, Env{LogsDir: logs}); ok {
			t.Errorf("%q read", bad)
		}
	}
}
