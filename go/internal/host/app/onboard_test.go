package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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
	// copilot and grok (OQ-01): nothing goes to the broker; grok's settings are staged unless they
	// pin a model key
	if r, tr := run("", nil, "--agent", "copilot"); r.rc != 0 || len(tr.ctl) != 0 || !strings.Contains(r.out, "Sign in in your first session") {
		t.Errorf("copilot: %+v", r)
	}
	gcfg := filepath.Join(state, "agent-config", "grok", "config.toml")
	os.MkdirAll(filepath.Join(home, ".grok"), 0o700)
	os.WriteFile(filepath.Join(home, ".grok", "config.toml"), []byte("[model.grok-4]\napi_key = \"xai-k\"\n"), 0o600)
	if r, tr := run("", nil, "--agent", "grok"); r.rc != 0 || len(tr.ctl) != 0 || !strings.Contains(r.out, "NOT copied") {
		t.Errorf("grok with a model key: %+v", r)
	}
	if _, err := os.Stat(gcfg); err == nil {
		t.Error("a config with a model key was staged")
	}
	os.WriteFile(filepath.Join(home, ".grok", "config.toml"), []byte("[ui]\n"), 0o600)
	if r, _ := run("", nil, "--agent", "grok"); r.rc != 0 || !strings.Contains(r.out, "Copied ~/.grok/config.toml") {
		t.Errorf("grok: %+v", r)
	}
	if b, _ := os.ReadFile(gcfg); string(b) != "[ui]\n" {
		t.Errorf("staged %q", b)
	}
	if r, tr := run("", nil, "--dry-run"); r.rc != 0 || len(tr.ctl) != 0 {
		t.Errorf("dry run: %+v", r)
	}
}

// TestOnboardCodex: an imported Codex login is sealed as agent.codex (bound to chatgpt.com) and
// agent.codex.refresh (withheld), its non-secret account written for the launches, its config
// staged, and nothing else kept; a file that is not a ChatGPT login stores nothing.
func TestOnboardCodex(t *testing.T) {
	state, k := secretState(t)
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".codex"), 0o700)
	os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte(`model = "gpt-6"`), 0o600)
	seg := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	access := "eyJhbGciOiJSUzI1NiJ9." + seg(map[string]any{"exp": 1_800_900_000}) + ".sig"
	idt := "eyJhbGciOiJSUzI1NiJ9." + seg(map[string]any{"email": "me@example.com",
		"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": "acct-1", "chatgpt_plan_type": "plus"}}) + ".sig"
	login := filepath.Join(t.TempDir(), "auth.json")
	os.WriteFile(login, []byte(`{"auth_mode":"chatgpt","tokens":{"id_token":"`+idt+`","access_token":"`+access+`","refresh_token":"rt-1","account_id":"acct-1"}}`), 0o600)
	run := func(args ...string) (res, *fakeTransport) {
		tr := &fakeTransport{release: goodRelease}
		var out, errb bytes.Buffer
		rc := Run(context.Background(), append([]string{"onboard", "--agent", "codex"}, args...), Env{Driver: &driver.Mock{State: driver.Running}, Transport: tr,
			Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, StateDir: state, Home: home,
			Now: func() time.Time { return time.Unix(1800000000, 0) }, BrokerKey: k})
		return res{rc, out.String(), errb.String()}, tr
	}
	r, tr := run("--from-auth-json", login)
	if r.rc != 0 || !reflect.DeepEqual(tr.ctl, [][]string{{"ctl", "broker-put", "agent.codex"}, {"ctl", "broker-put", "agent.codex.refresh"}}) || !strings.Contains(r.err, "WARNING") {
		t.Fatalf("%+v %q", r, tr.ctl)
	}
	key, _ := k.Load()
	if v, b, _, err := brokerseal.OpenBound(key, "agent.codex", tr.ctlIn[0]); err != nil || string(v) != access || strings.Join(b.Hosts, ",") != "chatgpt.com" {
		t.Errorf("access %v %+v", err, b)
	}
	if v, b, bound, err := brokerseal.OpenBound(key, "agent.codex.refresh", tr.ctlIn[1]); err != nil || string(v) != "rt-1" || !bound || len(b.Hosts) != 0 || b.Readable {
		t.Errorf("refresh %v %+v", err, b)
	}
	id, _ := os.ReadFile(filepath.Join(state, "agent-config", "codex", "identity.json"))
	if !strings.Contains(string(id), `"account_id": "acct-1"`) || !strings.Contains(string(id), `"email": "me@example.com"`) || strings.Contains(string(id), "rt-1") {
		t.Errorf("identity %s", id)
	}
	if b, _ := os.ReadFile(filepath.Join(state, "agent-config", "codex", "config.toml")); string(b) != `model = "gpt-6"` {
		t.Errorf("config %q", b)
	}
	// the device login (here a stand-in): the same, without the warning about a shared login
	saved, _ := os.ReadFile(login)
	tr2 := &fakeTransport{release: goodRelease}
	var out2, err2 bytes.Buffer
	if rc := Run(context.Background(), []string{"onboard", "--agent", "codex"}, Env{Driver: &driver.Mock{State: driver.Running}, Transport: tr2,
		Stdin: strings.NewReader(""), Stdout: &out2, Stderr: &err2, StateDir: state, Home: home, BrokerKey: k,
		Now: func() time.Time { return time.Unix(1800000000, 0) }, CodexLogin: func() ([]byte, error) { return saved, nil }}); rc != 0 || len(tr2.ctl) != 2 || err2.Len() != 0 {
		t.Errorf("device login: %d %q %q", rc, tr2.ctl, err2.String())
	}
	for name, body := range map[string]string{"an API key file": `{"OPENAI_API_KEY":"sk-x"}`,
		"no refresh token": `{"tokens":{"id_token":"` + idt + `","access_token":"` + access + `","refresh_token":"","account_id":"acct-1"}}`} {
		os.WriteFile(login, []byte(body), 0o600)
		if r, tr := run("--from-auth-json", login); r.rc != 1 || len(tr.ctl) != 0 {
			t.Errorf("%s: %+v", name, r)
		}
	}
}
