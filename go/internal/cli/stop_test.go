package cli

import (
	"bytes"
	"errors"
	"os"
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
