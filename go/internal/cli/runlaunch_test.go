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

type fakeSessions struct {
	started  []*sessionspec.Spec
	attached [][]string
	stopped  []string
	startErr error
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
	return nil
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
		WorkspaceCopy: func(string) (string, error) { return "", errors.New("no repos in this test") }}
	return e, fs, home
}

// TestLaunch: a tier 1 run starts the spec, shows v2's banner, attaches the agent with its pinned
// conversation id, and tears the session down when the attach ends.
func TestLaunch(t *testing.T) {
	e, fs, home := launchEnv(t)
	var out, errb bytes.Buffer
	if rc := Run([]string{"run", "--name", "demo"}, e, &out, &errb); rc != 0 {
		t.Fatalf("%d\n%s\n%s", rc, out.String(), errb.String())
	}
	if len(fs.started) != 1 || fs.started[0].Image != "docker.io/library/sandbox"+testDigest || len(fs.started[0].Mounts) != 0 {
		t.Fatalf("started %+v", fs.started)
	}
	id := fs.started[0].ID
	if len(fs.attached) != 1 || fs.attached[0][0] != id || fs.attached[0][1] != "claude" || len(fs.attached[0]) != 4 || fs.attached[0][2] != "--session-id" {
		t.Errorf("attached %q", fs.attached)
	}
	if strings.Join(fs.stopped, ",") != id+" detached" {
		t.Errorf("stopped %q", fs.stopped)
	}
	o := out.String()
	for _, want := range []string{"==> Starting session...\n", "  SANDBOX SESSION\n", "  Session    " + id + "\n", "  Name       demo\n",
		"  Agent      claude (Anthropic OAuth)\n", "  Repo       emptyDir (ephemeral)\n", "  Runtime    kata\n",
		"  Log        ~/logs/" + id + "\n", "==> Attaching to session (Ctrl-D or 'exit' to end)...\n",
		"==> Disconnected — tearing down session to free cluster resources...\n",
		"    Conversation history preserved in ~/.sandbox/agent-home/claude/\n"} {
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
