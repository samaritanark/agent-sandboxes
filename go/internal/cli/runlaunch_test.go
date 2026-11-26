package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/brokerseal"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

type fakeSessions struct {
	started    []*sessionspec.Spec
	agentFiles []AgentFiles
	attached   [][]string
	stopped    []string
	startErr   error
	stopErr    error
	listErr    error
}

func (f *fakeSessions) Start(s *sessionspec.Spec) error {
	f.started = append(f.started, s)
	return f.startErr
}
func (f *fakeSessions) Attach(id string, cmd []string) (int, error) {
	f.attached = append(f.attached, append([]string{id}, cmd...))
	return 0, nil
}
func (f *fakeSessions) Stop(id, reason string) error {
	f.stopped = append(f.stopped, id+" "+reason)
	return f.stopErr
}
func (f *fakeSessions) List() ([]SessionState, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []SessionState
	for _, s := range f.started {
		if live, _ := f.Live(s.ID); live {
			out = append(out, SessionState{ID: s.ID, State: "RUNNING"})
		}
	}
	return out, nil
}

func (f *fakeSessions) Live(id string) (bool, error) {
	for _, s := range f.started {
		if s.ID == id {
			for _, st := range f.stopped {
				if strings.HasPrefix(st, id+" ") {
					return false, nil
				}
			}
			return true, nil
		}
	}
	return false, nil
}

func launchEnv(t *testing.T) (Env, *fakeSessions, string) {
	home := t.TempDir()
	e := fixtureEnv("full", home, "", nil)
	e.RunHandoff = nil
	e.OrgBlockList = filepath.Join(home, "org.yaml")
	os.WriteFile(e.OrgBlockList, []byte("blocked_domains:\n  - \"*.pastebin.com\"\n"), 0o644)
	fs := &fakeSessions{}
	e.Launch = LaunchEnv{Sessions: fs,
		AgentImage: func(tag string) (string, error) {
			if tag != "sandbox:claude" {
				return "", errors.New("not preloaded")
			}
			return "docker.io/library/sandbox" + testDigest, nil
		},
		WorkspaceCopy:   func(string) (string, error) { return "", errors.New("no repos in this test") },
		VMMemoryMiB:     func() (int, error) { return 7936, nil },
		WriteAgentFiles: func(id string, f AgentFiles) error { fs.agentFiles = append(fs.agentFiles, f); return nil }}
	e.CredentialPresent = func(ref string) bool { return ref == "agent.claude" }
	e.CredentialBinding = func(ref string) (brokerseal.Binding, bool) {
		return brokerseal.Binding{Hosts: []string{"api.anthropic.com"}, Inject: "bearer"}, ref == "agent.claude"
	}
	return e, fs, home
}

// TestLaunchMemoryError: run stops before starting anything when the VM's memory is unreadable.
func TestLaunchMemoryError(t *testing.T) {
	e, fs, _ := launchEnv(t)
	e.Launch.VMMemoryMiB = func() (int, error) { return 0, errors.New("no meminfo") }
	var errb bytes.Buffer
	if rc := Run([]string{"run"}, e, &bytes.Buffer{}, &errb); rc != 1 || !strings.Contains(errb.String(), "The VM's memory: no meminfo") || len(fs.started) != 0 {
		t.Errorf("%d %s", rc, errb.String())
	}
}

// TestLaunch: a tier 1 run starts the spec, shows v2's banner, attaches the agent with its pinned
// conversation id, and tears the session down when the attach ends.
func TestLaunch(t *testing.T) {
	e, fs, home := launchEnv(t)
	var out, errb bytes.Buffer
	if rc := Run([]string{"run", "--name", "demo"}, e, &out, &errb); rc != 0 {
		t.Fatalf("%d\n%s\n%s", rc, out.String(), errb.String())
	}
	if len(fs.started) != 1 || fs.started[0].Image != "docker.io/library/sandbox"+testDigest || len(fs.started[0].Mounts) != 2 {
		t.Fatalf("started %+v", fs.started)
	}
	// claude's credential, re-staged configuration, and (tier 1) session history
	sp, sess := fs.started[0], sessionspec.SessionStore+"/"+fs.started[0].ID
	if m := sp.Mounts; m[0] != (sessionspec.Mount{Kind: sessionspec.AgentConfig, Source: sess + "/agent-config", Target: "/home/agent/.claude"}) ||
		m[1] != (sessionspec.Mount{Kind: sessionspec.History, Source: sess + "/history", Target: "/home/agent/.claude/projects"}) {
		t.Errorf("mounts %+v", m)
	}
	if len(sp.Bindings) != 1 || sp.Bindings[0].Ref != "agent.claude" || sp.Bindings[0].EnvVar != "CLAUDE_CODE_OAUTH_TOKEN" {
		t.Errorf("bindings %+v", sp.Bindings)
	}
	if err := sp.Validate(sessionspec.Options{}); err != nil {
		t.Errorf("sandboxd refuses it: %v", err)
	}
	if len(fs.agentFiles) != 1 || string(fs.agentFiles[0].Config[".claude.json"]) != `{"hasCompletedOnboarding":true,"projects":{}}`+"\n" || fs.agentFiles[0].HistoryKey != "" {
		t.Errorf("files %+v", fs.agentFiles)
	}
	if m := fs.started[0].Resources.MemoryMiB; m != 5632 { // scaled to the VM's 7936 MiB
		t.Errorf("agent memory %d", m)
	}
	id := fs.started[0].ID
	if len(fs.attached) != 1 || fs.attached[0][0] != id || fs.attached[0][1] != "claude" || len(fs.attached[0]) != 4 || fs.attached[0][2] != "--session-id" {
		t.Errorf("attached %q", fs.attached)
	}
	if strings.Join(fs.stopped, ",") != id+" operator stop" {
		t.Errorf("stopped %q", fs.stopped)
	}
	o := out.String()
	for _, want := range []string{"==> Starting session...\n", "  SANDBOX SESSION\n", "  Session    " + id + "\n", "  Name       demo\n",
		"  Agent      claude (Anthropic OAuth)\n", "  Repo       emptyDir (ephemeral)\n", "  Runtime    kata\n",
		"  Log        ~/logs/" + id + "\n", "==> Attaching to session (Ctrl-D or 'exit' to end)...\n",
		"==> Disconnected — tearing down session to free cluster resources...\n",
		"    Conversation history went with the session (tier 1 keeps none).\n"} {
		if !strings.Contains(o, want) {
			t.Errorf("missing %q in\n%s", want, o)
		}
	}
	_ = home
}

// TestLaunchKeepAliveAndDryRun: keep-alive leaves the session running with v2's trailer; a dry run
// prints the spec and starts nothing.
func TestLaunchKeepAliveAndDryRun(t *testing.T) {
	e, fs, _ := launchEnv(t)
	var out bytes.Buffer
	if rc := Run([]string{"run", "--keep-alive"}, e, &out, &bytes.Buffer{}); rc != 0 || len(fs.stopped) != 0 ||
		!strings.Contains(out.String(), "(pod kept alive).\n    Resume:  sandbox resume ses-") {
		t.Errorf("keep-alive: %d %q\n%s", rc, fs.stopped, out.String())
	}
	e, fs, _ = launchEnv(t)
	out.Reset()
	if rc := Run([]string{"run", "--dry-run"}, e, &out, &bytes.Buffer{}); rc != 0 || len(fs.started) != 0 ||
		!strings.Contains(out.String(), "==> DRY RUN — Session spec:\n{") || !strings.Contains(out.String(), "Dry run complete. No resources applied.") {
		t.Errorf("dry run: %d\n%s", rc, out.String())
	}
}

// TestLaunchRefusals: a start failure stops run with sandboxd's reason and nothing attached; an
// image the VM lacks, opencode, and infra tokens stop it before anything starts.
func TestLaunchRefusals(t *testing.T) {
	e, fs, _ := launchEnv(t)
	fs.startErr = errors.New("not admitted: memory")
	var errb bytes.Buffer
	if rc := Run([]string{"run"}, e, &bytes.Buffer{}, &errb); rc != 1 || !strings.Contains(errb.String(), "failed to start: not admitted: memory") || len(fs.attached) != 0 {
		t.Errorf("start failure: %d %q", rc, errb.String())
	}
	e, fs, _ = launchEnv(t)
	errb.Reset()
	if rc := Run([]string{"run", "--agent", "codex"}, e, &bytes.Buffer{}, &errb); rc != 1 || !strings.Contains(errb.String(), "No runnable image for agent 'codex'") || len(fs.started) != 0 {
		t.Errorf("no image: %d %q", rc, errb.String())
	}
}

// TestLaunchMCP: an MCP dependency's server reaches the agent's MCP configuration at its v3
// address, the configuration is written for sandboxd and mounted read-only, and the agent is
// started with v2's MCP flags.
func TestLaunchMCP(t *testing.T) {
	e, fs, home := launchEnv(t)
	os.MkdirAll(filepath.Join(home, ".sandbox", "profiles"), 0o755)
	os.WriteFile(filepath.Join(home, ".sandbox", "profiles", "m.yaml"), []byte("tier: 1\nmcps:\n  - everything-mcp\n"), 0o644)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "config", "catalogue"), 0o755)
	cat, _ := os.ReadFile(filepath.Join("..", "..", "..", "config", "catalogue", "everything-mcp.yaml"))
	os.WriteFile(filepath.Join(root, "config", "catalogue", "everything-mcp.yaml"), cat, 0o644)
	e.SandboxRoot = root
	os.WriteFile(filepath.Join(root, "config", "catalogue", "pg.yaml"), []byte("name: pg\nkind: service\nimage: docker.io/library/postgres@sha256:"+strings.Repeat("b", 64)+"\nport: 5432\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".sandbox", "profiles", "m.yaml"), []byte("tier: 1\nmcps:\n  - everything-mcp\nservices:\n  - pg\n"), 0o644)
	var wrote string
	e.Launch.WriteMCPConfig = func(id string, b []byte) (string, error) { wrote = id + " " + string(b); return "", nil }
	var out, errb bytes.Buffer
	if rc := Run([]string{"run", "--profile", "m"}, e, &out, &errb); rc != 0 {
		t.Fatalf("%d\n%s\n%s", rc, out.String(), errb.String())
	}
	id := fs.started[0].ID
	if !strings.HasPrefix(wrote, id+" ") || !strings.Contains(wrote, `"everything-mcp"`) || !strings.Contains(wrote, `"http://everything-mcp.deps.sandbox.internal:3001/sse"`) || !strings.Contains(wrote, `"sse"`) {
		t.Errorf("config %q", wrote)
	}
	var mount *sessionspec.Mount
	for i, m := range fs.started[0].Mounts {
		if m.Kind == sessionspec.MCPConfig {
			mount = &fs.started[0].Mounts[i]
		}
	}
	if mount == nil || mount.Source != sessionspec.SessionStore+"/"+id+"/mcp" || mount.Target != "/home/agent/.sandbox-mcp" || !mount.ReadOnly {
		t.Errorf("mount %+v", mount)
	}
	if got := strings.Join(fs.attached[0], " "); !strings.HasSuffix(got, "--mcp-config /home/agent/.sandbox-mcp/config.json --strict-mcp-config") {
		t.Errorf("attach %q", got)
	}
	if strings.Contains(wrote, `"pg"`) {
		t.Errorf("a service registered as an MCP server: %q", wrote)
	}
	if len(fs.started[0].Dependencies) != 2 || fs.started[0].Dependencies[0].Name != "everything-mcp" ||
		strings.Join(fs.started[0].Dependencies[0].Args, " ") != "node dist/sse.js" || len(fs.started[0].Dependencies[0].Command) != 0 {
		t.Errorf("deps %+v", fs.started[0].Dependencies)
	}
}
