package vetting

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSignSplit (D-20): the VM's Prepare builds the payload `git tag -s` signs for HEAD; signed
// elsewhere (here with ssh-keygen and a throwaway key, as the host does), Finish accepts it only
// for HEAD, with a signature, and only when it verifies against a trust root; with no trust root
// it is accepted with a warning. A HEAD attested already is reported, not signed again.
func TestSignSplit(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("no ssh-keygen")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	os.Unsetenv("SSH_AUTH_SOCK")
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	repo, home := filepath.Join(tmp, "repo"), filepath.Join(tmp, "home")
	os.MkdirAll(filepath.Join(home, ".sandbox", "vetting"), 0o700)
	git := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@e", "-c", "commit.gpgsign=false"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	os.MkdirAll(repo, 0o755)
	git("init", "-q")
	os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a\n"), 0o644)
	git("add", "a.txt")
	git("commit", "-q", "-m", "a")
	head := git("rev-parse", "HEAD")
	key := filepath.Join(tmp, "id")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "op@example.com", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	pub, _ := os.ReadFile(key + ".pub")
	roots := filepath.Join(home, ".sandbox", "vetting", "allowed_signers")
	os.WriteFile(roots, []byte("op@example.com "+strings.TrimSpace(string(pub))+"\n"), 0o644)
	uc := filepath.Join(home, "config.yaml")
	os.WriteFile(uc, []byte("vetting_signing_key: ~/.ssh/id.pub\n"), 0o644)
	a := Attester{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, Warn: func(string) {}, Scan: func(string, string) []string { return nil }}
	a.Home, a.UserConfig, a.TrustRootDefault, a.TagPrefix = home, uc, roots, "agent-vetted/"
	a.Now = func() int64 { return 0 }

	tagger := "Op <op@example.com> 1800000000 +0000"
	p, err := a.Prepare(repo, "reviewed", tagger)
	if err != nil || p.Head != head || p.Tag != "agent-vetted/"+head || p.Already || p.Format != "ssh" || p.SigningKey != "~/.ssh/id.pub" ||
		p.Payload != "object "+head+"\ntype commit\ntag agent-vetted/"+head+"\ntagger "+tagger+"\n\nreviewed\n" {
		t.Fatalf("%+v %v", p, err)
	}
	sign := func(k string, payload string) []byte {
		cmd := exec.Command("ssh-keygen", "-Y", "sign", "-n", "git", "-f", k)
		cmd.Stdin = strings.NewReader(payload)
		sig, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte(payload), sig...)
	}
	tag := sign(key, p.Payload)
	if w, err := a.Finish(repo, tag); err != nil || len(w) != 0 {
		t.Errorf("finish: %v %v", w, err)
	}
	// another key, another commit, or no signature: refused
	other := filepath.Join(tmp, "other")
	exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", other).Run()
	if _, err := a.Finish(repo, sign(other, p.Payload)); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("another key: %v", err)
	}
	wrong := strings.Replace(p.Payload, head, strings.Repeat("0", 40), 2)
	if _, err := a.Finish(repo, sign(key, wrong)); err == nil || !strings.Contains(err.Error(), "not for this repository's HEAD") {
		t.Errorf("another commit: %v", err)
	}
	if _, err := a.Finish(repo, []byte(p.Payload)); err == nil || !strings.Contains(err.Error(), "no signature") {
		t.Errorf("unsigned: %v", err)
	}
	if _, err := a.Finish(repo, append([]byte(strings.Replace(p.Payload, "tagger Op", "tagger", 1)), tag[len(p.Payload):]...)); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("a malformed tag passed git mktag: %v", err)
	}
	// no trust root: accepted, with a warning
	os.Remove(roots)
	if w, err := a.Finish(repo, tag); err != nil || len(w) != 1 || !strings.Contains(w[0], "no vetting trust root") {
		t.Errorf("no trust root: %v %v", w, err)
	}
	// the copy was not written to
	if out := git("tag", "-l"); out != "" {
		t.Errorf("Finish wrote a tag into the copy: %q", out)
	}
	// once the tag is there, HEAD is attested already
	os.WriteFile(roots, []byte("op@example.com "+strings.TrimSpace(string(pub))+"\n"), 0o644)
	cmd := exec.Command("git", "-C", repo, "mktag")
	cmd.Stdin = bytes.NewReader(tag)
	oid, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	git("update-ref", "refs/tags/agent-vetted/"+head, strings.TrimSpace(string(oid)))
	if p, err := a.Prepare(repo, "", tagger); err != nil || !p.Already || p.Payload != "" {
		t.Errorf("already: %+v %v", p, err)
	}
	for _, bad := range []string{"no address 1 +0000", "Op <op@example.com> 1 0000", "Op\n <x> 1 +0000"} {
		if _, err := a.Prepare(repo, "", bad); err == nil {
			t.Errorf("tagger %q accepted", bad)
		}
	}
}
