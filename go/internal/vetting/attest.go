package vetting

import (
	"bufio"
	"fmt"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
)

// Attester carries the configuration and the terminal for the attestation functions.
type Attester struct {
	Ctx
	Out, Err io.Writer
	Stdin    *bufio.Reader
	TTYIn    bool // [[ -t 0 ]]
	TTYBoth  bool // [[ -t 0 && -t 1 ]]
	Warn     func(msg string)
	Scan     func(repo, acceptFile string) []string // scan_repo_secrets
}

func (a Attester) errln(lines ...string) {
	for _, l := range lines {
		fmt.Fprintln(a.Err, l)
	}
}

func (a Attester) reply() string {
	if a.Stdin == nil {
		return ""
	}
	line, _ := a.Stdin.ReadString('\n')
	return strings.Trim(strings.TrimSuffix(line, "\n"), " \t")
}

// AcknowledgeExceptions is _vetting_acknowledge_exceptions: before signing, show the signer which
// recorded secret exceptions the signature would let the agent read, and get an acknowledgment.
func (a Attester) AcknowledgeExceptions(realRepo, repo, assumeYes string) bool {
	if legacy := CommittedLegacyAcceptedSecrets(repo); len(legacy) > 0 {
		a.Warn(fmt.Sprintf("this repo still records %d secret exception(s) under accepted_secrets: in %s — that list is NO LONGER honored. Run 'sandbox exceptions migrate --repo %s' to move them to the repo-root %s, commit, and vet again.",
			len(legacy), repoConfigRel, repo, config.RepoIgnoreName))
	}
	entries := CommittedIgnoreFingerprints(repo, "")
	if len(entries) == 0 {
		return true
	}
	if commandV("betterleaks") == "" || commandV("jq") == "" {
		a.errln(fmt.Sprintf("ERROR: %s records secret exceptions (%s), but betterleaks/jq are not", repo, config.RepoIgnoreName),
			"       available to show what signing it would let the agent read. Install",
			"       them and re-run so the attestation is not a blind sign-off.")
		return false
	}
	af, _ := os.CreateTemp(os.TempDir(), "sandbox-vet-accept-")
	for _, e := range entries {
		af.WriteString(e + "\n")
	}
	af.Close()
	var accepted []string
	for _, line := range a.Scan(realRepo, af.Name()) {
		f := bashcompat.ReadTab(line, 5)
		if f[0] != "accepted" {
			continue
		}
		accepted = append(accepted, f[1]+":"+f[2]+":"+f[3])
	}
	os.Remove(af.Name())
	if len(accepted) == 0 {
		return true
	}
	a.errln("",
		fmt.Sprintf("  This repo records %d secret exception(s). Signing this attestation", len(accepted)),
		"  vouches that they are reviewed false positives — the agent WILL be able to",
		"  read these values once the repo is vetted:")
	for _, x := range accepted {
		a.errln("      " + x)
	}
	a.errln("")
	if assumeYes == "true" {
		a.errln("  Acknowledged via --yes.")
		return true
	}
	if !a.TTYIn {
		a.errln("ERROR: not an interactive terminal, so these cannot be acknowledged",
			"       interactively. Re-run with --yes to sign off on them explicitly.")
		return false
	}
	fmt.Fprint(a.Err, "  Acknowledge and sign? [y/N] ")
	if yes(a.reply()) {
		return true
	}
	a.errln("  Aborted; no attestation created.")
	return false
}

// AttestRepo is vetting_attest_repo: create a signed attestation tag at HEAD with the operator's
// own key, refusing a dirty tree when a clean one is required, after the exceptions
// acknowledgment. Returns the exit status (0 ok).
func (a Attester) AttestRepo(repo, msg, assumeYes string) int {
	if msg == "" {
		msg = "vetted for agent use"
	}
	if assumeYes == "" {
		assumeYes = "false"
	}
	real, err := physicalDir(repo)
	if err != nil {
		a.errln("ERROR: cannot access " + repo)
		return 1
	}
	if _, ok := vgit(real, "rev-parse", "--git-dir"); !ok {
		a.errln("ERROR: " + repo + " is not a git repository — nothing to attest.")
		return 1
	}
	if a.RequireCleanWorktree() == "true" {
		if st, _ := vgit(real, "status", "--porcelain"); trimNL(st) != "" {
			a.errln("ERROR: "+repo+" has a dirty working tree and vetting_require_clean_worktree",
				"       is set. Commit, stash (git stash -u), or remove the changes first —",
				"       the attestation must describe exactly the reviewed tree.")
			return 1
		}
	}
	headOut, _ := vgit(real, "rev-parse", "HEAD")
	head := trimNL(headOut)
	tag := a.TagPrefix + head
	if _, ok := vgit(real, "rev-parse", "-q", "--verify", "refs/tags/"+tag); ok {
		if deviation.Fixed(deviation.VerifyExistingAttestation) {
			if roots := a.TrustRoots(); len(roots) > 0 && !a.verifiesAgainstAny(real, tag, roots) {
				a.errln(fmt.Sprintf("ERROR: %s: a tag named %s already exists at HEAD but does not verify", repo, tag),
					"       against the trust root(s), so HEAD is not attested. The tag was not created by",
					"       this run and is left in place. Remove it (git tag -d "+tag+") and re-run, or ask a",
					"       reviewer whose key is enrolled to re-attest.")
				return 1
			}
		}
		fmt.Fprintf(a.Out, "  %s: already attested — tag %s exists.\n", repo, tag)
		return 0
	}
	if !a.AcknowledgeExceptions(real, repo, assumeYes) {
		return 1
	}

	fmtName := a.TrustFormat()
	falseBin := commandV("false")
	if falseBin == "" {
		falseBin = "/bin/false"
	}
	sshKeygen := commandV("ssh-keygen")
	if sshKeygen == "" {
		sshKeygen = falseBin
	}
	gpgBin := commandV("gpg", "gpg2")
	if gpgBin == "" {
		gpgBin = falseBin
	}
	opts := []string{"-c", "gpg.ssh.program=" + sshKeygen, "-c", "gpg.program=" + gpgBin,
		"-c", "gpg.x509.program=" + falseBin, "-c", "gpg.ssh.defaultKeyCommand="}
	if vsk := a.SigningKey(); vsk != "" {
		opts = append(opts, "-c", "gpg.format=ssh", "-c", "user.signingkey="+vsk)
	} else if fmtName == "ssh" {
		opts = append(opts, "-c", "gpg.format=ssh")
	}
	cmd := VettingGit(real, append(opts, "tag", "-s", tag, "-m", msg)...)
	cmd.Stdout, cmd.Stderr = a.Out, a.Err
	runErr := cmd.Run()
	if runErr == nil && deviation.Fixed(deviation.VerifyCreatedTag) && !tagIsSigned(real, tag) {
		// git exited 0 but the tag carries no signature (git 2.43 does this when the signer fails)
		vgit(real, "tag", "-d", tag)
		a.errln("ERROR: git reported success but the tag has no signature, so it was removed.")
		runErr = fmt.Errorf("unsigned tag")
	}
	if runErr == nil {
		fmt.Fprintf(a.Out, "  %s: created signed attestation tag %s\n", repo, tag)
		fmt.Fprintln(a.Out, "  Push it so other operators can verify:")
		fmt.Fprintf(a.Out, "        git -C %s push origin %s\n", repo, tag)
		return 0
	}
	a.errln("ERROR: failed to create the signed tag. Check that your signing key is",
		"       configured (git config user.signingkey; gpg.format matches your",
		"       key type) and that its public key is in the trust root.")
	state := a.SSHSigningKeyState(real)
	if state == "knob-bad" {
		a.errln("",
			"       Likely cause: vetting_signing_key: in your ~/.sandbox/config.yaml",
			fmt.Sprintf("       ('%s') is not an SSH key or an existing key", a.SigningKey()),
			"       file. Fix that config value; git config is not consulted while",
			"       it is set.")
	} else if fmtName == "ssh" && state == "mismatch" {
		bad, _ := vgit(real, "config", "user.signingkey")
		a.errln("",
			fmt.Sprintf("       Likely cause: user.signingkey ('%s') is not an SSH key or", trimNL(bad)),
			"       key file — it looks like a GPG key id from OpenPGP commit signing.",
			"       Attestations are SSH-signed here (ssh trust root). Keep your GPG",
			"       commit signing and set a key for attestations only:",
			"             # ~/.sandbox/config.yaml",
			"             vetting_signing_key: ~/.ssh/id_ed25519.pub",
			"       (or switch git to SSH signing globally), or run 'sandbox vet'",
			"       interactively and let it set this up for you.")
	}
	return 1
}

// InlineAttest is _vetting_inline_attest: the launch-time attest offer. After signing it
// re-verifies against the trust roots and removes a tag that does not verify.
func (a Attester) InlineAttest(repo, headSha string) bool {
	short := substr12(headSha)
	a.errln("",
		fmt.Sprintf("  %s is not vetted at HEAD %s.", repo, short),
		"  Your git signing key can attest it right now — the same signed sign-off",
		"  as 'sandbox vet', honored only if your key is in the trust root. Attest",
		"  only if you have reviewed what is at this HEAD.")
	fmt.Fprintf(a.Err, "  Attest HEAD %s... continue? [y/N] ", short)
	if !yes(a.reply()) {
		a.errln("  Not attested.")
		return false
	}
	if a.AttestRepo(repo, "vetted for agent use (attested at launch)", "false") != 0 {
		return false
	}
	f := bashcompat.ReadTab(a.StatusRepo(repo), 5)
	if f[0] == "vetted" {
		a.errln(fmt.Sprintf("  ✓ %s: attested and verified (signer %s)", repo, orUnknown(f[3])))
		return true
	}
	real, err := physicalDir(repo)
	if err != nil {
		return false
	}
	vgit(real, "tag", "-d", a.TagPrefix+headSha)
	a.errln("  ERROR: the attestation you just signed does not verify against the trust",
		"         root(s), so it was removed. Your signing key is likely not enrolled",
		"         as a reviewer — ask your overlay maintainer to add your public key,",
		"         or add it to "+a.TrustRoot()+".")
	return false
}

func gitGlobalConfig(args ...string) {
	exec.Command("git", append([]string{"config", "--global"}, args...)...).Run()
}

// SigningSetupAssist is vetting_signing_setup_assist: one-time signing setup for `sandbox vet`.
// It returns the exit status (0 when signing is now configured or left to the caller).
func (a Attester) SigningSetupAssist(repo string) int {
	real, err := physicalDir(repo)
	if err != nil {
		return 0
	}
	if a.TrustFormat() == "gpg" {
		return 0
	}
	state := a.SSHSigningKeyState(repo)
	if state == "ok" {
		return 0
	}
	if state == "knob-bad" {
		a.errln(fmt.Sprintf("  vetting_signing_key: in your ~/.sandbox/config.yaml ('%s')", a.SigningKey()),
			"  is not an SSH key or an existing key file. Fix that config value; git",
			"  config is not consulted while it is set.")
		return 1
	}
	if !a.TTYBoth {
		return 0
	}
	var candidates []string
	for _, k := range []string{a.Home + "/.ssh/id_ed25519.pub", a.Home + "/.ssh/id_ecdsa.pub", a.Home + "/.ssh/id_rsa.pub"} {
		if config.IsFile(k) {
			candidates = append(candidates, k)
		}
	}
	if len(candidates) == 0 {
		a.errln("  git signing is not usable for SSH attestations, and no SSH public key was",
			"  found under ~/.ssh. Create one (ssh-keygen -t ed25519), then re-run",
			"  'sandbox vet'.")
		return 1
	}
	pick := candidates[0]
	a.errln("")
	if state == "mismatch" {
		out, _ := vgit(real, "config", "user.signingkey")
		key := trimNL(out)
		a.errln(fmt.Sprintf("  Your git user.signingkey ('%s') is not an SSH key or key file — it", key),
			"  looks like a GPG key id from OpenPGP commit signing. Attestations here are",
			"  SSH-signed (the trust root is an allowed_signers file), and SSH signing",
			"  reads user.signingkey as a key file path, so signing would fail with",
			fmt.Sprintf("  \"Couldn't load public key %s\".", key),
			"",
			"  Your git config can stay exactly as it is: vetting_signing_key: in",
			"  ~/.sandbox/config.yaml signs attestations (and only attestations) with an",
			"  SSH key, while your commits keep their OpenPGP signature.")
		fmt.Fprintf(a.Err, "  Set vetting_signing_key: %s? [y/N] ", pick)
		if !yes(a.reply()) {
			a.errln("  Skipped. Either set it yourself:",
				"        # ~/.sandbox/config.yaml",
				"        vetting_signing_key: <path-to-your-key.pub>",
				"  or switch git to SSH signing (globally, or per-repo to leave your",
				"  global commit signing alone):",
				"        git config --global gpg.format ssh",
				"        git config --global user.signingkey <path-to-your-key.pub>")
			return 1
		}
		config.UpsertYAMLScalar(a.UserConfig, "vetting_signing_key", pick)
		a.errln(fmt.Sprintf("  Configured: vetting_signing_key: %s (in %s);", pick, a.UserConfig),
			"  your git signing config was not changed.")
	} else {
		a.errln("  git signing is not configured. Attestations are signed with your own SSH",
			"  key — nothing is shared or fetched; verification uses public keys only.")
		fmt.Fprintf(a.Err, "  Configure git (globally) to sign with %s? [y/N] ", pick)
		if !yes(a.reply()) {
			a.errln("  Skipped. Configure it manually to attest — globally:",
				"        git config --global gpg.format ssh",
				"        git config --global user.signingkey <path-to-your-key.pub>",
				"  or, to sign attestations only (leaving git config untouched):",
				"        # ~/.sandbox/config.yaml",
				"        vetting_signing_key: <path-to-your-key.pub>")
			return 1
		}
		gitGlobalConfig("gpg.format", "ssh")
		gitGlobalConfig("user.signingkey", pick)
		a.errln(fmt.Sprintf("  Configured: gpg.format=ssh, user.signingkey=%s", pick))
	}
	emailOut, _ := vgit(real, "config", "user.email")
	email := trimNL(emailOut)
	keyline := ""
	if b, err := os.ReadFile(pick); err == nil && len(b) > 0 {
		// awk '{print $1" "$2; exit}': the first record always prints, even when empty
		fs := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
		f1, f2 := "", ""
		if len(fs) > 0 {
			f1 = fs[0]
		}
		if len(fs) > 1 {
			f2 = fs[1]
		}
		keyline = f1 + " " + f2
	}
	if email != "" && keyline != "" {
		a.errln("",
			"  To be enrolled as a reviewer, your public key must be in the trust root.",
			"  Your allowed_signers line (send it to your overlay maintainer, or append",
			"  it to "+a.TrustRoot()+"):",
			"",
			"      "+email+" "+keyline,
			"")
	}
	return 0
}

var _ = config.Env{}

// tagIsSigned reports whether the tag object carries a signature block.
func tagIsSigned(real, tag string) bool {
	out, ok := vgit(real, "cat-file", "-p", "refs/tags/"+tag)
	return ok && (strings.Contains(out, "-----BEGIN SSH SIGNATURE-----") ||
		strings.Contains(out, "-----BEGIN PGP SIGNATURE-----") ||
		strings.Contains(out, "-----BEGIN SIGNED MESSAGE-----"))
}

// verifiesAgainstAny reports whether the tag verifies against at least one trust root.
func (a Attester) verifiesAgainstAny(real, tag string, roots []string) bool {
	for _, r := range roots {
		if _, ok := VerifyTag(real, tag, r, a.TrustFormat()); ok {
			return true
		}
	}
	return false
}
