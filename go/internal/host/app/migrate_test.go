package app

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncgate"
)

// importTransport records the history imports the host sends.
type importTransport struct {
	fakeTransport
	imports map[string][]string // "claude tier key": the files in the tar
}

func (f *importTransport) Run(ctx context.Context, ep driver.SSHEndpoint, argv []string, stdin io.Reader, stdout, stderr io.Writer, tty bool) (int, error) {
	if len(argv) == 5 && argv[1] == ImportHistory {
		tr := tar.NewReader(stdin)
		k := strings.Join(argv[2:], " ")
		for {
			h, err := tr.Next()
			if err != nil {
				break
			}
			if h.Typeflag == tar.TypeReg {
				b, _ := io.ReadAll(tr)
				f.imports[k] = append(f.imports[k], h.Name+"="+string(b))
			}
		}
		return 0, nil
	}
	return f.fakeTransport.Run(ctx, ep, argv, stdin, stdout, stderr, tty)
}

// v2Fixture is a v2 ~/.sandbox: agent homes (claude and codex signed in), Claude transcripts, and
// session records for them.
func v2Fixture(t *testing.T) (state, repo, other string) {
	state = t.TempDir()
	repo, other = t.TempDir(), t.TempDir()
	home := filepath.Join(state, "agent-home")
	proj := filepath.Join(home, "claude", "projects", "-workspace")
	os.MkdirAll(filepath.Join(proj, "11111111-1111-4111-8111-111111111111", "subagents"), 0o700)
	os.MkdirAll(filepath.Join(home, "codex"), 0o700)
	os.WriteFile(filepath.Join(home, "claude", ".credentials.json"), []byte("{}"), 0o600)
	os.WriteFile(filepath.Join(home, "codex", "auth.json"), []byte("{}"), 0o600)
	for id, body := range map[string]string{
		"11111111-1111-4111-8111-111111111111": "tier2 one repo",
		"22222222-2222-4222-8222-222222222222": "tier3 two repos",
		"33333333-3333-4333-8333-333333333333": "tier1",
		"44444444-4444-4444-8444-444444444444": "repo gone",
		"55555555-5555-4555-8555-555555555555": "no record",
	} {
		os.WriteFile(filepath.Join(proj, id+".jsonl"), []byte(body), 0o600)
	}
	os.WriteFile(filepath.Join(proj, "11111111-1111-4111-8111-111111111111", "subagents", "a.jsonl"), []byte("sub"), 0o600)
	os.Symlink("/etc/passwd", filepath.Join(proj, "11111111-1111-4111-8111-111111111111", "link"))
	rec := func(n, body string) {
		os.MkdirAll(filepath.Join(state, "logs", n), 0o700)
		os.WriteFile(filepath.Join(state, "logs", n, "session.json"), []byte(body), 0o600)
	}
	rec("ses-1", `{"agent":"claude","tier":2,"repos":["`+repo+`"],"agent_session_id":"11111111-1111-4111-8111-111111111111"}`)
	rec("ses-2", `{"agent":"claude","tier":"3","repos":["`+repo+`","`+other+`"],"agent_session_id":"22222222-2222-4222-8222-222222222222"}`)
	rec("ses-3", `{"agent":"claude","tier":1,"repos":["`+repo+`"],"agent_session_id":"33333333-3333-4333-8333-333333333333"}`)
	rec("ses-4", `{"agent":"claude","tier":2,"repos":["/no/such/repo"],"agent_session_id":"44444444-4444-4444-8444-444444444444"}`)
	rec("ses-5", `{"agent":"codex","tier":2,"repos":["`+repo+`"],"agent_session_id":"55555555-5555-4555-8555-555555555555"}`)
	os.MkdirAll(filepath.Join(state, "secrets", ".bindings"), 0o700)
	os.WriteFile(filepath.Join(state, "secrets", "JIRA"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(state, "secrets", "GH"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(state, "secrets", ".bindings", "GH"), []byte(`{"hosts":["api.github.com"],"inject":"bearer"}`), 0o600)
	os.MkdirAll(filepath.Join(state, "profiles"), 0o700)
	os.WriteFile(filepath.Join(state, "profiles", "dev.yaml"), []byte("tier: 2\n"), 0o600)
	return state, repo, other
}

// TestMigrate: the report (what carries over, unbound secrets, agents to sign in again), and
// Claude's conversations imported into the tier and repository set their v2 records name; the rest
// left in place. Nothing of v2 is removed without --remove-v2.
func TestMigrate(t *testing.T) {
	state, repo, other := v2Fixture(t)
	var limactl []string
	deps := MigrationDeps{GOOS: "darwin", Limactl: func(_ context.Context, args ...string) ([]byte, error) {
		limactl = append(limactl, strings.Join(args, " "))
		return []byte("sandbox-vm\nsandbox-v3\n"), nil
	}}
	tr := &importTransport{fakeTransport: fakeTransport{release: goodRelease}, imports: map[string][]string{}}
	var out, errb bytes.Buffer
	rc := Run(context.Background(), []string{"migrate"}, Env{Driver: &driver.Mock{State: driver.Running}, Transport: tr,
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, StateDir: state, Migration: deps,
		Now: func() time.Time { return time.Unix(1800000000, 0) }})
	o := out.String()
	for _, want := range []string{"==> Found a v2 install (agent homes in ~/.sandbox/agent-home; the Lima VM sandbox-vm)",
		"Carried over as they are: 1 profile(s), 2 secret(s)", "these have none and are withheld:\n      JIRA\n",
		"claude: run 'claude setup-token', then: sandbox onboard --agent claude", "codex:  sandbox onboard --agent codex",
		"2 conversation(s) imported; 3 stay in ~/.sandbox/agent-home", "When you no longer need it: sandbox migrate --remove-v2"} {
		if !strings.Contains(o, want) {
			t.Errorf("missing %q in\n%s", want, o)
		}
	}
	if rc != 0 {
		t.Fatalf("%d %s", rc, errb.String())
	}
	id1, _ := syncgate.RepoID(repo)
	key2, _ := historyKey([]string{other, repo})
	got1 := strings.Join(tr.imports["claude 2 "+id1], ",")
	if got1 != "-workspace/11111111-1111-4111-8111-111111111111.jsonl=tier2 one repo,-workspace/11111111-1111-4111-8111-111111111111/subagents/a.jsonl=sub" {
		t.Errorf("tier 2: %q", got1)
	}
	if got := strings.Join(tr.imports["claude 3 "+key2], ","); got != "-workspace/22222222-2222-4222-8222-222222222222.jsonl=tier3 two repos" || len(key2) != 32 {
		t.Errorf("tier 3: %q (%d imports)", got, len(tr.imports))
	}
	if len(tr.imports) != 2 {
		t.Errorf("imports %v", tr.imports)
	}
	if strings.Contains(strings.Join(limactl, ";"), "delete") {
		t.Error("deleted v2's VM without --remove-v2")
	}
	if _, err := os.Stat(filepath.Join(state, "agent-home", "claude", ".credentials.json")); err != nil {
		t.Error("touched v2's agent home")
	}
	// the key is the CLI's: the copy IDs, sorted, hashed
	if k, _ := historyKey([]string{repo, other}); k != key2 {
		t.Error("the key depends on the order")
	}
}

// TestRemoveV2: with --remove-v2 and a confirmation, v2's Lima VM is deleted and its agent homes
// archived without their tokens; without a terminal, nothing is removed unless --yes.
func TestRemoveV2(t *testing.T) {
	state, _, _ := v2Fixture(t)
	var limactl []string
	deps := MigrationDeps{GOOS: "darwin", Limactl: func(_ context.Context, args ...string) ([]byte, error) {
		limactl = append(limactl, strings.Join(args, " "))
		return []byte("sandbox-vm\n"), nil
	}}
	run := func(stdin string, tty bool, args ...string) res {
		var out, errb bytes.Buffer
		rc := Run(context.Background(), append([]string{"migrate", "--remove-v2"}, args...), Env{Driver: &driver.Mock{State: driver.Stopped},
			Transport: &fakeTransport{release: goodRelease}, Stdin: strings.NewReader(stdin), StdinTTY: tty, Stdout: &out, Stderr: &errb,
			StateDir: state, Migration: deps, Now: func() time.Time { return time.Unix(1800000000, 0) }})
		return res{rc, out.String(), errb.String()}
	}
	if r := run("", false); r.rc != 1 || strings.Contains(strings.Join(limactl, ";"), "delete") {
		t.Fatalf("no terminal: %+v %q", r, limactl)
	}
	if r := run("n\n", true); r.rc != 0 || !strings.Contains(r.out, "v2 kept.") || strings.Contains(strings.Join(limactl, ";"), "delete") {
		t.Fatalf("declined: %+v", r)
	}
	r := run("y\n", true)
	if r.rc != 0 || !strings.Contains(strings.Join(limactl, ";"), "delete --force sandbox-vm") {
		t.Fatalf("confirmed: %+v %q", r, limactl)
	}
	arch := filepath.Join(state, "v2-archive", "agent-home")
	if _, err := os.Stat(filepath.Join(state, "agent-home")); err == nil {
		t.Error("agent home not moved")
	}
	if _, err := os.Stat(filepath.Join(arch, "claude", ".credentials.json")); err == nil {
		t.Error("a login token was archived")
	}
	if _, err := os.Stat(filepath.Join(arch, "codex", "auth.json")); err == nil {
		t.Error("codex's login was archived")
	}
	if b, _ := os.ReadFile(filepath.Join(arch, "claude", "projects", "-workspace", "33333333-3333-4333-8333-333333333333.jsonl")); string(b) != "tier1" {
		t.Error("history not archived")
	}
	// the VM refusing to go stops the removal before the agent homes move
	state2, _, _ := v2Fixture(t)
	var out, errb bytes.Buffer
	rc := Run(context.Background(), []string{"migrate", "--remove-v2", "--yes"}, Env{Driver: &driver.Mock{State: driver.Stopped},
		Transport: &fakeTransport{release: goodRelease}, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb, StateDir: state2,
		Migration: MigrationDeps{GOOS: "darwin", Limactl: func(_ context.Context, args ...string) ([]byte, error) {
			if args[0] == "delete" {
				return nil, errors.New("busy")
			}
			return []byte("sandbox-vm\n"), nil
		}}, Now: func() time.Time { return time.Unix(1800000000, 0) }})
	if _, err := os.Stat(filepath.Join(state2, "agent-home")); rc != 1 || err != nil {
		t.Errorf("a failed VM delete: %d, agent home kept: %v", rc, err == nil)
	}
	// none found
	var o3 bytes.Buffer
	if Run(context.Background(), []string{"migrate"}, Env{Driver: &driver.Mock{}, Transport: &fakeTransport{}, Stdout: &o3, Stderr: io.Discard,
		StateDir: t.TempDir(), Migration: MigrationDeps{GOOS: "test"}}); !strings.Contains(o3.String(), "No v2 install found") {
		t.Errorf("%q", o3.String())
	}
	_ = exec.ErrNotFound
}
