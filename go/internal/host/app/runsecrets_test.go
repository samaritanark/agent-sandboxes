package app

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
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
	// no binding kept: sealed as withheld
	if v, b, bound, err := brokerseal.OpenBound(key, "secret.GH_TOKEN", tr.ctlIn[0]); err != nil || string(v) != "ghp_value\n" || !bound || len(b.Hosts) != 0 || b.Readable {
		t.Errorf("%q %+v %v %v", v, b, bound, err)
	}
	// with a binding kept beside it: sealed with the value
	os.MkdirAll(filepath.Join(state, "secrets", ".bindings"), 0o700)
	os.WriteFile(filepath.Join(state, "secrets", ".bindings", "GH_TOKEN"), []byte(`{"hosts":["api.github.com"],"inject":"bearer"}`), 0o600)
	tr2 := &fakeTransport{release: goodRelease, bindings: `{"secrets":["GH_TOKEN"],"repos":[]}`}
	if r := runState(t, tr2, k, state, "run", "--profile", "p"); r.rc != 0 {
		t.Fatalf("%+v", r)
	}
	if _, b, bound, err := brokerseal.OpenBound(key, "secret.GH_TOKEN", tr2.ctlIn[0]); err != nil || !bound || strings.Join(b.Hosts, ",") != "api.github.com" || b.Inject != "bearer" {
		t.Errorf("bound: %+v %v %v", b, bound, err)
	}
	// an unreadable binding stops the run before anything is pushed
	os.WriteFile(filepath.Join(state, "secrets", ".bindings", "GH_TOKEN"), []byte(`{"hosts":["*.github.com"],"inject":"bearer"}`), 0o600)
	tr3 := &fakeTransport{release: goodRelease, bindings: `{"secrets":["GH_TOKEN"],"repos":[]}`}
	if r := runState(t, tr3, k, state, "run", "--profile", "p"); r.rc != 1 || !strings.Contains(r.err, "the binding of secret 'GH_TOKEN'") || len(tr3.ctl) != 0 || len(tr3.runs) != 0 {
		t.Errorf("bad binding: %+v %q", r, tr3.ctl)
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
		`{}`, `{"secrets":["A"]}{}`, `{"secrets":["A"],"repos":[]} {}`, `[]`, `{"secrets":["../x"],"repos":[]}`, many + "]}"} {
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
	if runtime.GOOS == "windows" {
		t.Skip("host paths are POSIX paths the VM mirrors; v3 does not run sessions from a Windows host yet")
	}
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
		`{"secrets":[],"repos":["/r0"` + strings.Repeat(`,"/r"`, 0) + manyRepos() + `]}`: fmt.Sprintf("more than %d", maxRepos),
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

// TestRunPushesInfraTokens: each infra token the VM names and the command line names is read from
// its file, sealed as a bearer token bound to the --infra-endpoint hosts, and pushed; a token or
// host the command line does not name stops the launch before anything is pushed.
func TestRunPushesInfraTokens(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("host paths are POSIX paths the VM mirrors; v3 does not run sessions from a Windows host yet")
	}
	state, k := secretState(t)
	tok := filepath.Join(t.TempDir(), "vault-token")
	os.WriteFile(tok, []byte("hvs.secret\n"), 0o600)
	args := []string{"run", "--tier", "3", "--infra-token", "vault=" + tok, "--infra-endpoint", "https://Vault.Corp.Example:8200/v1"}
	pp := `{"secrets":[],"repos":[],"infra_tokens":[{"env":"INFRA_TOKEN_vault","path":"` + tok + `"}],"infra_hosts":["vault.corp.example"]}`
	tr := &fakeTransport{release: goodRelease, bindings: pp}
	r := runState(t, tr, k, state, args...)
	if r.rc != 0 || !strings.Contains(r.out, "==> Sealing this launch's infra tokens for the sandbox VM: INFRA_TOKEN_vault\n") {
		t.Fatalf("%+v", r)
	}
	if !reflect.DeepEqual(tr.ctl, [][]string{{"ctl", "broker-put", "infra.INFRA_TOKEN_vault"}}) {
		t.Fatalf("ctl %q", tr.ctl)
	}
	key, _ := k.Load()
	v, b, bound, err := brokerseal.OpenBound(key, "infra.INFRA_TOKEN_vault", tr.ctlIn[0])
	if err != nil || string(v) != "hvs.secret" || !bound || strings.Join(b.Hosts, ",") != "vault.corp.example" || b.Inject != "bearer" {
		t.Errorf("%q %+v %v %v", v, b, bound, err)
	}
	for name, out := range map[string]string{
		"unnamed token": `{"secrets":[],"repos":[],"infra_tokens":[{"env":"INFRA_TOKEN_vault","path":"/etc/shadow"}],"infra_hosts":[]}`,
		"renamed token": `{"secrets":[],"repos":[],"infra_tokens":[{"env":"INFRA_TOKEN","path":"` + tok + `"}],"infra_hosts":[]}`,
		"unnamed host":  `{"secrets":[],"repos":[],"infra_tokens":[],"infra_hosts":["evil.example.com"]}`,
		"bad variable":  `{"secrets":[],"repos":[],"infra_tokens":[{"env":"PATH","path":"` + tok + `"}],"infra_hosts":[]}`,
		"bad host":      `{"secrets":[],"repos":[],"infra_tokens":[],"infra_hosts":["EVIL.example.com"]}`,
		"relative path": `{"secrets":[],"repos":[],"infra_tokens":[{"env":"INFRA_TOKEN","path":"x/../y"}],"infra_hosts":[]}`,
	} {
		tr := &fakeTransport{release: goodRelease, bindings: out}
		if r := runState(t, tr, k, state, args...); r.rc != 1 || len(tr.ctl) != 0 || len(tr.runs) != 0 {
			t.Errorf("%s: %+v ctl %q", name, r, tr.ctl)
		}
	}
	// a relative token path is made absolute on the host, after its NAME=
	if got := absRepos([]string{"--infra-token", "v=rel/tok", "--infra-token=~/t", "--infra-token=other"}, "/wd"); strings.Join(got, " ") != "--infra-token v=/wd/rel/tok --infra-token=~/t --infra-token=/wd/other" {
		t.Errorf("abs %q", got)
	}
}

// TestParsePrepassInfra: the parser's own checks on infra tokens and hosts.
func TestParsePrepassInfra(t *testing.T) {
	base := `{"secrets":[],"repos":[],`
	if p, err := parsePrepass([]byte(base + `"infra_tokens":[{"env":"INFRA_TOKEN_a","path":"/t"}],"infra_hosts":["a.example.com"]}`)); err != nil || len(p.InfraTokens) != 1 || len(p.InfraHosts) != 1 {
		t.Fatalf("%v", err)
	}
	for _, bad := range []string{
		`"infra_tokens":[{"env":"PATH","path":"/t"}]}`,
		`"infra_tokens":[{"env":"INFRA_TOKEN","path":"/t"},{"env":"INFRA_TOKEN","path":"/u"}]}`,
		`"infra_hosts":["A.example.com"]}`,
		`"infra_hosts":["a.example.com","a.example.com"]}`,
		`"infra_hosts":["localhost"]}`,
	} {
		if _, err := parsePrepass([]byte(base + bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// TestRunOpencode: for an opencode launch the host fetches the model list with OPENCODE_API_KEY,
// seals the key bound to the endpoint's host, forwards OPENCODE_BASE_URL, and gives the run the
// configuration; an endpoint the operator did not name, a missing key, or an empty list stops it.
func TestRunOpencode(t *testing.T) {
	state, k := secretState(t)
	envs := map[string]string{"OPENCODE_API_KEY": "sk-real", "OPENCODE_BASE_URL": "https://vllm.corp.example/v1"}
	pp := `{"secrets":[],"repos":[],"opencode_base_url":"https://vllm.corp.example/v1"}`
	run := func(tr *fakeTransport, envs map[string]string, models string, args ...string) (res, string) {
		var out, errb bytes.Buffer
		var asked string
		rc := Run(context.Background(), args, Env{Driver: &driver.Mock{State: driver.Running}, Transport: tr,
			Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, StateDir: state,
			Now: func() time.Time { return time.Unix(1800000000, 0) }, BrokerKey: k,
			Getenv: func(n string) string { return envs[n] },
			FetchModels: func(_ context.Context, base, key string) ([]byte, error) {
				asked = base + " " + key
				return []byte(models), nil
			}})
		return res{rc, out.String(), errb.String()}, asked
	}
	tr := &fakeTransport{release: goodRelease, bindings: pp}
	r, asked := run(tr, envs, `{"data":[{"id":"qwen"},{"id":"llama"}]}`, "run", "--agent", "opencode")
	if r.rc != 0 || asked != "https://vllm.corp.example/v1 sk-real" || !strings.Contains(r.out, "  Found 2 model(s) on endpoint.") {
		t.Fatalf("%+v %q", r, asked)
	}
	key, _ := k.Load()
	if v, b, _, err := brokerseal.OpenBound(key, OpencodeRef, tr.ctlIn[0]); err != nil || string(v) != "sk-real" || strings.Join(b.Hosts, ",") != "vllm.corp.example" {
		t.Errorf("%q %+v %v", v, b, err)
	}
	last := strings.Join(tr.runs[len(tr.runs)-1], " ")
	if !strings.Contains(last, "OPENCODE_BASE_URL=https://vllm.corp.example/v1") || !strings.Contains(last, OpencodeConfigEnv+`={"enabled_providers":["openai-compat"]`) ||
		!strings.Contains(last, `"qwen":{"limit":{"context":131072,"output":8192},"name":"qwen"}`) || strings.Contains(last, "sk-real") {
		t.Errorf("run %q", last)
	}
	for name, c := range map[string]struct {
		envs   map[string]string
		models string
		args   []string
	}{
		"unnamed endpoint": {map[string]string{"OPENCODE_API_KEY": "sk"}, `{"data":[{"id":"m"}]}`, nil},
		"other --base-url": {envs, `{"data":[{"id":"m"}]}`, []string{"--base-url", "https://elsewhere.example/v1"}},
		"no key":           {map[string]string{"OPENCODE_BASE_URL": "https://vllm.corp.example/v1"}, `{"data":[{"id":"m"}]}`, nil},
		"no models":        {envs, `{"data":[]}`, nil},
	} {
		tr := &fakeTransport{release: goodRelease, bindings: pp}
		if r, _ := run(tr, c.envs, c.models, append([]string{"run", "--agent", "opencode"}, c.args...)...); r.rc != 1 || len(tr.ctl) != 0 || len(tr.runs) != 0 {
			t.Errorf("%s: %+v ctl %q", name, r, tr.ctl)
		}
	}
	// the configuration v2 built
	cfg, n := opencodeConfig("https://h/v1", []byte(`{"data":[{"id":"a"},{"id":""}]}`))
	if n != 1 || cfg != `{"enabled_providers":["openai-compat"],"provider":{"openai-compat":{"models":{"a":{"limit":{"context":131072,"output":8192},"name":"a"}},"name":"OpenAI-compatible endpoint","npm":"@ai-sdk/openai-compatible","options":{"apiKey":"{env:OPENAI_API_KEY}","baseURL":"https://h/v1"}}}}` {
		t.Errorf("%d %s", n, cfg)
	}
}

// TestOverlayAndSettings: an overlay directory outside ~/.sandbox is pushed with the operator state
// and the proxied command pointed at its copy; one under ~/.sandbox (a linked overlay) is passed on
// as it is; the operator's settings variables are forwarded, and nothing else of the environment.
func TestOverlayAndSettings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("host paths are POSIX paths the VM mirrors; v3 does not run sessions from a Windows host yet")
	}
	home := t.TempDir()
	state := filepath.Join(home, ".sandbox")
	os.MkdirAll(state, 0o700)
	ov := filepath.Join(t.TempDir(), "org-overlay")
	os.MkdirAll(filepath.Join(ov, "catalogue"), 0o755)
	os.MkdirAll(filepath.Join(ov, ".git"), 0o755)
	os.WriteFile(filepath.Join(ov, "config.yaml"), []byte("blocked_domains: []\n"), 0o644)
	os.WriteFile(filepath.Join(ov, "catalogue", "pg.yaml"), []byte("name: pg\n"), 0o644)
	os.WriteFile(filepath.Join(ov, ".git", "config"), []byte("[core]\n"), 0o644)
	os.WriteFile(filepath.Join(state, "config.yaml"), []byte("overlay: \""+ov+"\"  # the org's\n"), 0o600)
	run := func(envs map[string]string) *fakeTransport {
		tr := &fakeTransport{release: goodRelease}
		Run(context.Background(), []string{"list"}, Env{Driver: &driver.Mock{State: driver.Running}, Transport: tr,
			Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard, StateDir: state, Home: home,
			Getenv: func(k string) string { return envs[k] }, Now: func() time.Time { return time.Unix(1800000000, 0) }})
		return tr
	}
	tr := run(map[string]string{"SANDBOX_EXTRA_ALLOWED_DOMAINS": "a.example.com", "AWS_SECRET_ACCESS_KEY": "nope", "USER": "op"})
	names := tarNames(t, tr.pushes[0])
	if !slices.Contains(names, "overlay-local/config.yaml") || !slices.Contains(names, "overlay-local/catalogue/pg.yaml") || slices.Contains(names, "overlay-local/.git/config") {
		t.Errorf("pushed %q", names)
	}
	argv := strings.Join(tr.runs[len(tr.runs)-1], " ")
	if !strings.Contains(argv, "SANDBOX_OVERLAY="+home+"/.sandbox/overlay-local") || !strings.Contains(argv, "SANDBOX_EXTRA_ALLOWED_DOMAINS=a.example.com") ||
		!strings.Contains(argv, "USER=op") || strings.Contains(argv, "AWS_SECRET") {
		t.Errorf("argv %q", argv)
	}
	// a linked overlay (under ~/.sandbox) is the VM's own: named, not pushed
	linked := filepath.Join(state, "overlays", "org")
	os.MkdirAll(linked, 0o700)
	tr = run(map[string]string{"SANDBOX_OVERLAY": linked})
	if slices.Contains(tarNames(t, tr.pushes[0]), "overlay-local/config.yaml") || !strings.Contains(strings.Join(tr.runs[len(tr.runs)-1], " "), "SANDBOX_OVERLAY="+linked) {
		t.Errorf("linked: %q", tr.runs[len(tr.runs)-1])
	}
	// none: nothing pushed or set
	os.Remove(filepath.Join(state, "config.yaml"))
	tr = run(nil)
	if strings.Contains(strings.Join(tr.runs[len(tr.runs)-1], " "), "SANDBOX_OVERLAY") {
		t.Error("an overlay set with none configured")
	}
}

func tarNames(t *testing.T, b []byte) []string {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(b))
	var out []string
	for {
		h, err := tr.Next()
		if err != nil {
			return out
		}
		out = append(out, h.Name)
	}
}
