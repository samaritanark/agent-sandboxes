package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/driver"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncgate"
)

// vetTransport is the VM for `vet`: the sync agent in-process, and the two vetting halves answered
// with plan (and recording the signed tag finish is given).
type vetTransport struct {
	agentTransport
	plan     func() vetPlan
	prepares [][]string
	finished []string
	proxied  [][]string
}

func (f *vetTransport) Run(ctx context.Context, ep driver.SSHEndpoint, argv []string, stdin io.Reader, stdout, stderr io.Writer, tty bool) (int, error) {
	switch {
	case indexOf(argv, VetPrepareCmd) >= 0:
		f.prepares = append(f.prepares, argv[indexOf(argv, VetPrepareCmd)+1:])
		b, _ := json.Marshal(f.plan())
		stdout.Write(append(b, '\n'))
		return 0, nil
	case indexOf(argv, VetFinishCmd) >= 0:
		var in map[string]string
		json.NewDecoder(stdin).Decode(&in)
		f.finished = append(f.finished, in["tag"])
		io.WriteString(stdout, `{"warnings":["a warning from the VM"]}`+"\n")
		return 0, nil
	case len(argv) >= 2 && argv[1] == ReceiveOperatorState:
		io.Copy(io.Discard, stdin)
		return 0, nil
	case len(argv) >= 2 && argv[1] == MirrorPath:
		return 0, nil
	case indexOf(argv, "vet") >= 0:
		f.proxied = append(f.proxied, argv)
		return 0, nil
	}
	return f.agentTransport.Run(ctx, ep, argv, stdin, stdout, stderr, tty)
}

func (f *vetTransport) Output(ctx context.Context, ep driver.SSHEndpoint, argv []string, max int) ([]byte, error) {
	if len(argv) == 2 && argv[0] == "cat" && argv[1] == ReleasePath {
		return []byte(goodRelease), nil
	}
	return f.agentTransport.Output(ctx, ep, argv, max)
}

// TestVet (D-20): the host checks HEAD itself against the VM's plan, signs the payload with the
// operator's key (ssh-keygen), hands the signed tag to the VM, and writes the tag into its own
// repository, where git verifies it; a plan for another commit or identity is refused; exceptions
// and commits a session made need an acknowledgement; --status runs in the VM.
func TestVet(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("host paths are POSIX paths the VM mirrors; v3 does not run sessions from a Windows host yet")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("no ssh-keygen")
	}
	os.Unsetenv("SSH_AUTH_SOCK")
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	repo, state, vmdir := filepath.Join(tmp, "repo"), filepath.Join(tmp, "state"), filepath.Join(tmp, "vm")
	os.MkdirAll(repo, 0o755)
	os.MkdirAll(vmdir, 0o755)
	git := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@e", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644)
	git("add", "a.txt")
	git("commit", "-q", "-m", "a")
	head := git("rev-parse", "HEAD")
	key := filepath.Join(tmp, "id")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "op@example.com", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	now := time.Unix(1800000000, 0).UTC()
	tagger := "Op <op@example.com> 1800000000 +0000"
	good := func() vetPlan {
		tag := "agent-vetted/" + head
		return vetPlan{Head: head, Tag: tag, Format: "ssh", SigningKey: key,
			Payload: "object " + head + "\ntype commit\ntag " + tag + "\ntagger " + tagger + "\n\nvetted for agent use\n"}
	}
	tr := &vetTransport{agentTransport: agentTransport{vmdir: vmdir}, plan: good}
	var out, errb bytes.Buffer
	env := Env{Driver: &driver.Mock{State: driver.Running}, Transport: tr, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb,
		StateDir: state, Now: func() time.Time { return now },
		GitConfig: func(k string) string { return map[string]string{"user.name": "Op", "user.email": "op@example.com"}[k] }}
	if rc := Run(context.Background(), []string{"vet", "--repo", repo}, env); rc != 0 {
		t.Fatalf("%d\n%s\n%s", rc, out.String(), errb.String())
	}
	if len(tr.prepares) != 1 || strings.Join(tr.prepares[0], "|") != repo+"|"+tagger {
		t.Errorf("prepare %q", tr.prepares)
	}
	if len(tr.finished) != 1 || !strings.HasPrefix(tr.finished[0], good().Payload+"-----BEGIN SSH SIGNATURE-----") {
		t.Fatalf("finish %q", tr.finished)
	}
	// the tag is in the host repository, and git verifies it with the operator's key
	pub, _ := os.ReadFile(key + ".pub")
	signers := filepath.Join(tmp, "allowed_signers")
	os.WriteFile(signers, []byte("op@example.com "+strings.TrimSpace(string(pub))+"\n"), 0o644)
	git("-c", "gpg.ssh.allowedSignersFile="+signers, "verify-tag", "agent-vetted/"+head) // fails the test if it does not verify
	if got := git("cat-file", "tag", "agent-vetted/"+head); got+"\n" != strings.TrimRight(tr.finished[0], "\n")+"\n" {
		t.Errorf("tag written:\n%s\nsigned:\n%s", got, tr.finished[0])
	}
	for _, want := range []string{"==> Attesting " + repo, "created signed attestation tag agent-vetted/" + head, "git -C " + repo + " push origin agent-vetted/" + head} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
	if !strings.Contains(errb.String(), "WARN: a warning from the VM") {
		t.Errorf("%s", errb.String())
	}

	// the VM's copy at another commit, or a payload for another identity: nothing signed
	git("tag", "-d", "agent-vetted/"+head)
	for name, p := range map[string]func() vetPlan{
		"another head":     func() vetPlan { p := good(); p.Head = strings.Repeat("1", 40); return p },
		"another identity": func() vetPlan { p := good(); p.Payload = strings.Replace(p.Payload, "Op <", "Mallory <", 1); return p },
		"another tag": func() vetPlan {
			p := good()
			p.Tag, p.Payload = "release/"+head, strings.Replace(p.Payload, "tag agent-vetted/", "tag release/", 1)
			return p
		},
	} {
		tr.plan, tr.finished = p, nil
		errb.Reset()
		if rc := Run(context.Background(), []string{"vet", "--repo", repo}, env); rc != 1 || len(tr.finished) != 0 {
			t.Errorf("%s: %d %s", name, rc, errb.String())
		}
	}
	// attested already
	tr.plan = func() vetPlan { p := good(); p.Already = true; return p }
	out.Reset()
	if rc := Run(context.Background(), []string{"vet", "--repo", repo}, env); rc != 0 || !strings.Contains(out.String(), "already attested") {
		t.Errorf("already: %d %s", rc, out.String())
	}
	// exceptions, and commits a session made at or below HEAD, need an acknowledgement
	id, _ := syncgate.RepoID(repo)
	os.MkdirAll(filepath.Join(state, "sync", id), 0o700)
	os.WriteFile(filepath.Join(state, "sync", id, LedgerFile), []byte("2027-01-15T08:00:00Z refs/heads/main 0000000000000000000000000000000000000000 -> "+head+" (fast-forward)\n"), 0o600)
	tr.plan, tr.finished = good, nil
	errb.Reset()
	if rc := Run(context.Background(), []string{"vet", "--repo", repo}, env); rc != 1 || len(tr.finished) != 0 ||
		!strings.Contains(errb.String(), "made in a sandbox session") || !strings.Contains(errb.String(), "Re-run with --yes") {
		t.Errorf("session commits: %d %s", rc, errb.String())
	}
	tr.plan = func() vetPlan { p := good(); p.Exceptions = []string{"config.py:3:generic-api-key"}; return p }
	env.StdinTTY, env.Stdin = true, strings.NewReader("n\n")
	errb.Reset()
	if rc := Run(context.Background(), []string{"vet", "--repo", repo}, env); rc != 1 || len(tr.finished) != 0 || !strings.Contains(errb.String(), "config.py:3:generic-api-key") {
		t.Errorf("declined: %d %s", rc, errb.String())
	}
	env.StdinTTY = false
	if rc := Run(context.Background(), []string{"vet", "--repo", repo, "--yes"}, env); rc != 0 || len(tr.finished) != 1 {
		t.Errorf("--yes: %d %s", rc, errb.String())
	}
	// --status (and anything else) runs in the VM
	if Run(context.Background(), []string{"vet", "--repo", repo, "--status"}, env); len(tr.proxied) != 1 {
		t.Errorf("status: %q", tr.proxied)
	}
}

// TestLedgerRecorded: a commit made in the VM's copy that the sync takes is recorded in the
// repository's ledger, which vet reads.
func TestLedgerRecorded(t *testing.T) {
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	repo, state, vmdir := filepath.Join(tmp, "repo"), filepath.Join(tmp, "state"), filepath.Join(tmp, "vm")
	os.MkdirAll(repo, 0o755)
	os.MkdirAll(vmdir, 0o755)
	git := func(dir string, args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@e", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git(repo, "init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644)
	git(repo, "add", "a.txt")
	git(repo, "commit", "-q", "-m", "a")
	a := &app{env: Env{Transport: &agentTransport{vmdir: vmdir}, StateDir: state, Stdout: io.Discard, Stderr: io.Discard,
		Now: func() time.Time { return time.Unix(1800000000, 0) }}, ctx: context.Background()}
	if _, _, err := a.syncRepo(driver.SSHEndpoint{}, repo); err != nil {
		t.Fatal(err)
	}
	git(vmdir, "checkout", "-q", "-b", "agent-work") // main is protected: the sync holds it for review
	os.WriteFile(filepath.Join(vmdir, "b.txt"), []byte("b\n"), 0o644)
	git(vmdir, "add", "b.txt")
	git(vmdir, "commit", "-q", "-m", "from a session")
	made := git(vmdir, "rev-parse", "HEAD")
	if _, rep, err := a.syncRepo(driver.SSHEndpoint{}, repo); err != nil || len(rep.Ledger) == 0 {
		t.Fatalf("%v %+v", err, rep)
	}
	id, _ := syncgate.RepoID(repo)
	b, _ := os.ReadFile(filepath.Join(state, "sync", id, LedgerFile))
	if !strings.Contains(string(b), "2027-01-15T08:00:00Z ") || !strings.Contains(string(b), "-> "+made) {
		t.Errorf("ledger:\n%s", b)
	}
}
