package vetting

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func capCtx(t *testing.T, user, overlay string) Ctx {
	t.Helper()
	d := t.TempDir()
	c := Ctx{Now: func() int64 { return 0 }}
	c.Home = d
	c.UserConfig = filepath.Join(d, "user.yaml")
	writeFile(t, c.UserConfig, user)
	if overlay != "" {
		c.SandboxOverlay = filepath.Join(d, "ov")
		writeFile(t, filepath.Join(d, "ov", "config.yaml"), overlay)
	}
	return c
}

func TestFixDecimalNumbers(t *testing.T) {
	// a zero-padded invalid-octal value first, then a tighter overlay cap
	c := capCtx(t, "vetting_max_commits_behind: 08\n", "vetting_max_commits_behind: 5\n")
	if got := c.MaxCommitsBehind(); got != "08" {
		t.Fatalf("legacy: got %q", got)
	}
	c2 := capCtx(t, "vetting_max_commits_behind: 010\n", "vetting_max_commits_behind: 9\n")
	if got := c2.MaxCommitsBehind(); got != "010" { // octal 8 < 9, kept as the string 010
		t.Fatalf("legacy: got %q", got)
	}
	huge := capCtx(t, "vetting_max_age_days: 99999999999999999999\n", "")
	if got := huge.MaxAgeDays(); got != "99999999999999999999" {
		t.Fatalf("legacy: got %q", got)
	}
	age := Ctx{Now: func() int64 { return 86400*10 + 90 }}
	if got := age.AgeDays("0100"); got != "10" { // 0100 is octal 64
		t.Fatalf("legacy age: got %q", got)
	}

	defer deviation.Force(deviation.DecimalNumbers)()
	if got := c.MaxCommitsBehind(); got != "5" {
		t.Errorf("fixed: the tighter overlay cap must win, got %q", got)
	}
	if got := c2.MaxCommitsBehind(); got != "9" {
		t.Errorf("fixed: 010 is ten, so 9 is tighter; got %q", got)
	}
	if got := huge.MaxAgeDays(); got != "9223372036854775807" {
		t.Errorf("fixed: an oversized value clamps instead of wrapping; got %q", got)
	}
	if got := age.AgeDays("0100"); got != "9" { // 100 seconds before now
		t.Errorf("fixed age: got %q", got)
	}
	if !NumCmp("010", "9", "gt") || NumCmp("08", "9", "gt") {
		t.Error("fixed: comparisons are decimal")
	}
}

func gateDeps(out, errw *bytes.Buffer, status string, cfg GateConfig) GateDeps {
	return GateDeps{Out: out, Err: errw, Cfg: cfg,
		Status:         func(string) string { return status },
		RecordOverride: func(string, string, []string) {}}
}

func TestFixUnknownPostureFailsClosed(t *testing.T) {
	run := func() int {
		var o, e bytes.Buffer
		d := gateDeps(&o, &e, "vetted\tsha\ttag\talice\t0\t1", GateConfig{TrustRoot: "/trust/default", AgeDays: func(string) string { return "1" }})
		rc, _ := d.VettingGateRepos("x", "false", "false", []string{"/w/r"})
		return rc
	}
	if run() != 0 {
		t.Fatal("legacy: an unknown posture with no trust root passes")
	}
	defer deviation.Force(deviation.UnknownPostureFailsClosed)()
	if run() != 1 {
		t.Error("fixed: an unknown posture with no trust root must refuse")
	}
}

func TestFixUnknownAgeIsStale(t *testing.T) {
	run := func() int {
		var o, e bytes.Buffer
		d := gateDeps(&o, &e, "vetted\tsha\ttag\talice\t0\t", GateConfig{TrustRoots: []string{"/t"}, AgeCap: "30", AgeDays: func(string) string { return "" }})
		rc, _ := d.VettingGateRepos("required", "false", "false", []string{"/w/r"})
		return rc
	}
	if run() != 0 {
		t.Fatal("legacy: an unreadable tag date skips the recency cap")
	}
	defer deviation.Force(deviation.UnknownAgeIsStale)()
	if run() != 1 {
		t.Error("fixed: an attestation of unknown age must be treated as stale")
	}
}

func TestFixStrictKeyLiteral(t *testing.T) {
	c := capCtx(t, "", "")
	if !c.SSHKeyUsable("ssh-foo") {
		t.Fatal("legacy: any ssh- prefix counts")
	}
	defer deviation.Force(deviation.StrictKeyLiteral)()
	if c.SSHKeyUsable("ssh-foo") {
		t.Error("fixed: ssh-foo is not a public key")
	}
	for _, k := range []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA c", "key::ssh-rsa AAAAB3Nza", "ecdsa-sha2-nistp256 AAAAE2VjZHNh", "sk-ssh-ed25519@openssh.com AAAAGnNr"} {
		if !c.SSHKeyUsable(k) {
			t.Errorf("fixed: %q is a public key", k)
		}
	}
}

func excFixture(t *testing.T) string {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	fx := filepath.Join(t.TempDir(), "fx")
	if out, err := exec.Command(filepath.Join("testdata", "exc", "setup.sh"), fx).CombinedOutput(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	return fx
}

func TestFixBlobOnlyIgnoreFiles(t *testing.T) {
	fx := excFixture(t)
	repo := filepath.Join(fx, "ra-ign-dir") // .betterleaksignore is a directory
	if got := CommittedIgnoreFingerprints(repo, ""); len(got) == 0 {
		t.Fatal("legacy: the tree listing is read as entries")
	}
	defer deviation.Force(deviation.BlobOnlyIgnoreFiles)()
	if got := CommittedIgnoreFingerprints(repo, ""); len(got) != 0 {
		t.Errorf("fixed: a directory is not an ignore file, got %q", got)
	}
	if got := CommittedIgnoreFingerprints(filepath.Join(fx, "ra-vetted"), ""); len(got) == 0 {
		t.Error("fixed: a real ignore file is still read")
	}
}

// attestFixture builds the attestation fixture and a run directory with one repository copied in.
func attestFixture(t *testing.T, repo string) (Attester, string, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_SYSTEM", "/dev/null")
	t.Setenv("GIT_COMMITTER_DATE", "@1800000000 +0000")
	t.Setenv("SSH_AUTH_SOCK", "")
	os.Unsetenv("SSH_AUTH_SOCK")
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	fx := filepath.Join(tmp, "fx")
	if out, err := exec.Command(filepath.Join("testdata", "attest", "setup.sh"), fx).CombinedOutput(); err != nil {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	run := filepath.Join(fx, "run")
	os.MkdirAll(run, 0o755)
	copyDir(t, filepath.Join(fx, "tpl", repo), filepath.Join(run, repo))
	copyDir(t, filepath.Join(fx, "home-ed"), filepath.Join(run, "home"))
	writeFile(t, filepath.Join(run, "uc.yaml"), "vetting_signing_key: "+filepath.Join(fx, "keys", "a")+"\n")
	var o, e bytes.Buffer
	a := Attester{Out: &o, Err: &e, Warn: func(string) {}, Scan: func(string, string) []string { return nil }}
	a.Home = filepath.Join(run, "home")
	a.UserConfig = filepath.Join(run, "uc.yaml")
	a.TrustRootDefault = a.Home + "/.sandbox/vetting/allowed_signers"
	a.TagPrefix = "agent-vetted/"
	a.Now = func() int64 { return 0 }
	return a, filepath.Join(run, repo), &o, &e
}

func TestFixVerifyCreatedTag(t *testing.T) {
	a, repo, out, errb := attestFixture(t, "at-clean")
	// stand in for git 2.43: when asked to sign a tag, create an unsigned annotated one and exit 0
	realGit, _ := exec.LookPath("git")
	bin := t.TempDir()
	writeFile(t, filepath.Join(bin, "git"), "#!/bin/sh\nargs=\"\"\nsign=0\nfor a in \"$@\"; do case \"$a\" in tag) sign=1;; esac; done\nfor a in \"$@\"; do\n  if [ \"$a\" = -s ] && [ $sign = 1 ]; then a=-a; fi\n  args=\"$args '$(printf %s \"$a\" | sed \"s/'/'\\\\\\\\''/g\")'\"\ndone\neval exec "+realGit+" $args\n")
	os.Chmod(filepath.Join(bin, "git"), 0o755)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))

	if rc := a.AttestRepo(repo, "", "false"); rc != 0 || !strings.Contains(out.String(), "created signed attestation tag") {
		t.Fatalf("legacy: rc=%d out=%q err=%q", rc, out.String(), errb.String())
	}
	tags, _ := exec.Command(realGit, "-C", repo, "tag", "-l").Output()
	if strings.TrimSpace(string(tags)) == "" {
		t.Fatal("legacy: the unsigned tag is left in place")
	}
	exec.Command(realGit, "-C", repo, "tag", "-d", strings.TrimSpace(string(tags))).Run()
	out.Reset()
	errb.Reset()

	defer deviation.Force(deviation.VerifyCreatedTag)()
	if rc := a.AttestRepo(repo, "", "false"); rc == 0 {
		t.Fatalf("fixed: an unsigned tag must be a failure; out=%q", out.String())
	}
	if !strings.Contains(errb.String(), "no signature") {
		t.Errorf("fixed: expected the unsigned-tag message, got %q", errb.String())
	}
	tags, _ = exec.Command(realGit, "-C", repo, "tag", "-l").Output()
	if strings.TrimSpace(string(tags)) != "" {
		t.Errorf("fixed: the unsigned tag must be removed, got %q", tags)
	}
}

func TestFixVerifyExistingAttestation(t *testing.T) {
	a, repo, out, errb := attestFixture(t, "at-clean")
	head, _ := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	tag := "agent-vetted/" + strings.TrimSpace(string(head))
	if err := exec.Command("git", "-C", repo, "tag", tag).Run(); err != nil { // lightweight: cannot verify
		t.Fatal(err)
	}
	if rc := a.AttestRepo(repo, "", "false"); rc != 0 || !strings.Contains(out.String(), "already attested") {
		t.Fatalf("legacy: rc=%d out=%q", rc, out.String())
	}
	out.Reset()
	defer deviation.Force(deviation.VerifyExistingAttestation)()
	if rc := a.AttestRepo(repo, "", "false"); rc != 1 || !strings.Contains(errb.String(), "does not verify") {
		t.Errorf("fixed: rc=%d err=%q", rc, errb.String())
	}
}

// TestVerifyTagIgnoresWorkspaceConfig: the git that runs the verifier works in a scratch
// repository holding only the tag (TrustedGit), so a workspace's config does not reach it: a
// revocation file the workspace names (unpinned) is not read, though the same verification run in
// the workspace honours it.
func TestVerifyTagIgnoresWorkspaceConfig(t *testing.T) {
	a, repo, out, errb := attestFixture(t, "at-clean")
	if rc := a.AttestRepo(repo, "", "false"); rc != 0 {
		t.Fatalf("attest: rc=%d out=%q err=%q", rc, out.String(), errb.String())
	}
	head, _ := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	tag := "agent-vetted/" + strings.TrimSpace(string(head))
	root := a.TrustRoot()
	if signer, ok := VerifyTag(repo, tag, root, "ssh"); !ok || signer != "alice@example.com" {
		t.Fatalf("verify: %q %v", signer, ok)
	}
	pub, _ := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(repo)), "keys", "a.pub"))
	revoked := filepath.Join(t.TempDir(), "revoked")
	writeFile(t, revoked, string(pub))
	if err := exec.Command("git", "-C", repo, "config", "gpg.ssh.revocationFile", revoked).Run(); err != nil {
		t.Fatal(err)
	}
	// a logging TrustedGit: every call it gets must be in a scratch repository
	realGit, _ := exec.LookPath("git")
	log := filepath.Join(t.TempDir(), "calls")
	wrap := filepath.Join(t.TempDir(), "git")
	writeFile(t, wrap, "#!/bin/sh\necho \"$2\" >> "+log+"\nexec "+realGit+" \"$@\"\n")
	os.Chmod(wrap, 0o755)
	t.Setenv("SANDBOX_TRUSTED_GIT", wrap)
	if signer, ok := VerifyTag(repo, tag, root, "ssh"); !ok || signer != "alice@example.com" {
		t.Errorf("the workspace's revocation file reached the verifier: %q %v", signer, ok)
	}
	calls, _ := os.ReadFile(log)
	if n := strings.Count(string(calls), "sandbox-vet-tag-"); n != 4 || strings.Contains(string(calls), repo) {
		t.Errorf("trusted git calls (want 4, all in the scratch repository):\n%s", calls)
	}
	// control: the same pinned verification run in the workspace honours its revocation file
	ctl := exec.Command("git", "-C", repo, "-c", "gpg.format=ssh", "-c", "gpg.ssh.allowedSignersFile="+root, "tag", "-v", tag)
	if err := ctl.Run(); err == nil {
		t.Error("control: the revocation file is not honoured in the workspace; the test proves nothing")
	}
	if _, ok := VerifyTag(repo, "agent-vetted/missing", root, "ssh"); ok {
		t.Error("a missing tag verified")
	}
}
