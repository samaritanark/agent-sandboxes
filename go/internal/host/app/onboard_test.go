package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
)

// TestOnboardClaude: the setup-token token is sealed as agent.claude bound to api.anthropic.com and
// stored in the VM's broker; settings and global instructions are copied for re-staging, never the
// credentials file; an API key or a malformed token is refused before anything is stored.
func TestOnboardClaude(t *testing.T) {
	state, k := secretState(t)
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(`{"theme":"dark"}`), 0o600)
	os.WriteFile(filepath.Join(home, ".claude", ".credentials.json"), []byte(`{"claudeAiOauth":{}}`), 0o600)
	tok := "sk-ant-oat01-" + strings.Repeat("A", 40)
	run := func(stdin string, envs map[string]string, args ...string) (res, *fakeTransport) {
		tr := &fakeTransport{release: goodRelease}
		var out, errb bytes.Buffer
		rc := Run(context.Background(), append([]string{"onboard"}, args...), Env{Driver: &driver.Mock{State: driver.Running}, Transport: tr,
			Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb, StateDir: state, Home: home,
			Now: func() time.Time { return time.Unix(1800000000, 0) }, BrokerKey: k, Getenv: func(n string) string { return envs[n] }})
		return res{rc, out.String(), errb.String()}, tr
	}
	r, tr := run(tok+"\n", nil, "--agent", "claude")
	if r.rc != 0 || !reflect.DeepEqual(tr.ctl, [][]string{{"ctl", "broker-put", "agent.claude"}}) || strings.Contains(r.out, tok) {
		t.Fatalf("%+v %q", r, tr.ctl)
	}
	key, _ := k.Load()
	v, b, bound, err := brokerseal.OpenBound(key, "agent.claude", tr.ctlIn[0])
	if err != nil || string(v) != tok || !bound || strings.Join(b.Hosts, ",") != "api.anthropic.com" || b.Inject != "bearer" {
		t.Errorf("%q %+v %v", v, b, err)
	}
	if got, _ := os.ReadFile(filepath.Join(state, "agent-config", "claude", "settings.json")); string(got) != `{"theme":"dark"}` {
		t.Errorf("settings %q", got)
	}
	if _, err := os.Stat(filepath.Join(state, "agent-config", "claude", ".credentials.json")); err == nil {
		t.Error("the credentials file was copied")
	}
	// from the environment
	if r, tr := run("", map[string]string{"CLAUDE_CODE_OAUTH_TOKEN": tok}); r.rc != 0 || len(tr.ctl) != 1 {
		t.Errorf("env: %+v", r)
	}
	for _, bad := range []string{"sk-ant-api03-" + strings.Repeat("A", 40), "", "sk-ant-oat01-x y"} {
		if r, tr := run(bad+"\n", nil); r.rc != 1 || len(tr.ctl) != 0 {
			t.Errorf("%q: %+v", bad, r)
		}
	}
	if r, tr := run("", nil, "--agent", "codex"); r.rc != 1 || len(tr.ctl) != 0 {
		t.Errorf("codex: %+v", r)
	}
	if r, tr := run("", nil, "--dry-run"); r.rc != 0 || len(tr.ctl) != 0 {
		t.Errorf("dry run: %+v", r)
	}
}
