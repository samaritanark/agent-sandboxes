package vetting

// Attestation signing split between the VM and the host (design 5.1.3, D-20). The operator's
// signing key never enters the VM, and the host never runs git against the repository, so:
// Prepare (in the VM, on the synced copy) makes v2's checks and builds the exact tag payload `git
// tag -s` would sign; the host checks HEAD itself, shows what it signs, and signs the payload; Finish
// (in the VM) assembles the tag with `git mktag` and verifies it against the trust roots; the host
// then writes the tag object and refs/tags/<tag> into its repository itself.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

// Plan is what Prepare gives the host: the commit and tag, whether HEAD is attested already, the
// exceptions the signature vouches for, how to sign, and the payload.
type Plan struct {
	Head       string   `json:"head"`
	Tag        string   `json:"tag"`
	Already    bool     `json:"already,omitempty"`
	Exceptions []string `json:"exceptions,omitempty"`  // file:line:rule of each accepted finding
	Format     string   `json:"format"`                // "ssh" or "gpg" (the trust root's)
	SigningKey string   `json:"signing_key,omitempty"` // vetting_signing_key as written; the host expands ~
	Payload    string   `json:"payload,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// taggerRE is git's tagger line after "tagger ": a name, an address, seconds, and a zone.
var taggerRE = regexp.MustCompile(`^[^<>\n\x00]+ <[^<>\n\x00]*> [0-9]{1,12} [+-][0-9]{4}$`)

// Payload is the tag object `git tag -s -m msg` signs.
func Payload(head, tag, tagger, msg string) string {
	return "object " + head + "\ntype commit\ntag " + tag + "\ntagger " + tagger + "\n\n" + strings.TrimRight(msg, "\n") + "\n"
}

// Prepare is the VM's half of vetting_attest_repo up to the signature.
func (a Attester) Prepare(repo, msg, tagger string) (Plan, error) {
	if msg == "" {
		msg = "vetted for agent use"
	}
	if !taggerRE.MatchString(tagger) {
		return Plan{}, fmt.Errorf("the host's tagger identity %q is not 'Name <email> seconds +zone'", tagger)
	}
	if strings.ContainsRune(msg, 0) || len(msg) > 4096 {
		return Plan{}, errors.New("the message has a NUL byte or is longer than 4096 bytes")
	}
	real, err := physicalDir(repo)
	if err != nil {
		return Plan{}, fmt.Errorf("cannot access %s", repo)
	}
	if _, ok := vgit(real, "rev-parse", "--git-dir"); !ok {
		return Plan{}, fmt.Errorf("%s is not a git repository — nothing to attest.", repo)
	}
	if a.RequireCleanWorktree() == "true" {
		if st, _ := vgit(real, "status", "--porcelain"); trimNL(st) != "" {
			return Plan{}, fmt.Errorf("%s has a dirty working tree and vetting_require_clean_worktree\n"+
				"       is set. Commit, stash (git stash -u), or remove the changes first —\n"+
				"       the attestation must describe exactly the reviewed tree.", repo)
		}
	}
	headOut, _ := vgit(real, "rev-parse", "HEAD")
	head := trimNL(headOut)
	p := Plan{Head: head, Tag: a.TagPrefix + head, Format: a.TrustFormat(), SigningKey: a.userGet("vetting_signing_key")}
	if _, ok := vgit(real, "rev-parse", "-q", "--verify", "refs/tags/"+p.Tag); ok {
		if deviation.Fixed(deviation.VerifyExistingAttestation) {
			if roots := a.TrustRoots(); len(roots) > 0 && !a.verifiesAgainstAny(real, p.Tag, roots) {
				return Plan{}, fmt.Errorf("%s: a tag named %s already exists at HEAD but does not verify\n"+
					"       against the trust root(s), so HEAD is not attested. The tag was not created by\n"+
					"       this run and is left in place. Remove it (git tag -d %s) and re-run, or ask a\n"+
					"       reviewer whose key is enrolled to re-attest.", repo, p.Tag, p.Tag)
			}
		}
		p.Already = true
		return p, nil
	}
	if legacy := CommittedLegacyAcceptedSecrets(repo); len(legacy) > 0 {
		p.Warnings = append(p.Warnings, fmt.Sprintf("this repo still records %d secret exception(s) under accepted_secrets: in %s — that list is NO LONGER honored. Run 'sandbox exceptions migrate --repo %s' to move them to the repo-root %s, commit, and vet again.",
			len(legacy), repoConfigRel, repo, config.RepoIgnoreName))
	}
	exc, err := a.acceptedExceptions(real, repo)
	if err != nil {
		return Plan{}, err
	}
	p.Exceptions = exc
	p.Payload = Payload(head, p.Tag, tagger, msg)
	return p, nil
}

// acceptedExceptions is the scan half of _vetting_acknowledge_exceptions: the findings the repo's
// recorded exceptions accept, which the signature would let the agent read.
func (a Attester) acceptedExceptions(realRepo, repo string) ([]string, error) {
	entries := CommittedIgnoreFingerprints(repo, "")
	if len(entries) == 0 {
		return nil, nil
	}
	if commandV("betterleaks") == "" || commandV("jq") == "" {
		return nil, fmt.Errorf("%s records secret exceptions (%s), but betterleaks/jq are not\n"+
			"       available to show what signing it would let the agent read.", repo, config.RepoIgnoreName)
	}
	af, err := os.CreateTemp(os.TempDir(), "sandbox-vet-accept-")
	if err != nil {
		return nil, err
	}
	defer os.Remove(af.Name())
	for _, e := range entries {
		af.WriteString(e + "\n")
	}
	af.Close()
	var accepted []string
	for _, line := range a.Scan(realRepo, af.Name()) {
		f := strings.SplitN(line, "\t", 5)
		if len(f) >= 4 && f[0] == "accepted" {
			accepted = append(accepted, f[1]+":"+f[2]+":"+f[3])
		}
	}
	return accepted, nil
}

// Finish is the VM's half after the signature: tag (the payload and its signature) must be for
// HEAD of the copy; `git mktag` checks it in a scratch repository that borrows the copy's objects,
// and it must verify against a trust root when any is set. It returns warnings.
func (a Attester) Finish(repo string, tag []byte) ([]string, error) {
	real, err := physicalDir(repo)
	if err != nil {
		return nil, fmt.Errorf("cannot access %s", repo)
	}
	headOut, _ := vgit(real, "rev-parse", "HEAD")
	head := trimNL(headOut)
	name := a.TagPrefix + head
	if head == "" || !bytes.HasPrefix(tag, []byte("object "+head+"\ntype commit\ntag "+name+"\ntagger ")) {
		return nil, errors.New("the signed tag is not for this repository's HEAD")
	}
	if !bytes.Contains(tag, []byte("\n-----BEGIN SSH SIGNATURE-----")) && !bytes.Contains(tag, []byte("\n-----BEGIN PGP SIGNATURE-----")) {
		return nil, errors.New("the tag carries no signature")
	}
	objects, ok := vgit(real, "rev-parse", "--path-format=absolute", "--git-common-dir")
	if !ok {
		return nil, errors.New("cannot find the repository's objects")
	}
	format := "sha1"
	if f, ok := vgit(real, "rev-parse", "--show-object-format"); ok && trimNL(f) != "" {
		format = trimNL(f)
	}
	dir, err := os.MkdirTemp(os.TempDir(), "sandbox-vet-sign-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	// VerifyTag reads the tag with the gates' git, which in the VM runs unprivileged
	// (sandbox-git): the scratch repository holds only the public tag and the copy's objects'
	// path, which that user can already read
	if err := os.Chmod(dir, 0o755); err != nil {
		return nil, err
	}
	git := func(stdin []byte, args ...string) (string, error) {
		cmd := exec.Command(TrustedGit(), append([]string{"-C", dir, "-c", "core.hooksPath=/dev/null"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		if stdin != nil {
			cmd.Stdin = bytes.NewReader(stdin)
		}
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("git %s: %v: %s", args[0], err, strings.TrimSpace(errb.String()))
		}
		return trimNL(out.String()), nil
	}
	if _, err := git(nil, "init", "-q", "--bare", "--object-format="+format); err != nil {
		return nil, err
	}
	alt := filepath.Join(trimNL(objects), "objects") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "objects", "info", "alternates"), []byte(alt), 0o644); err != nil {
		return nil, err
	}
	oid, err := git(tag, "mktag")
	if err != nil {
		return nil, fmt.Errorf("the signed tag is malformed: %v", err)
	}
	if _, err := git(nil, "update-ref", "refs/tags/"+name, oid); err != nil {
		return nil, err
	}
	roots := a.TrustRoots()
	if len(roots) == 0 {
		return []string{"no vetting trust root is configured, so the attestation was not verified; launches verify it against the trust root they use."}, nil
	}
	for _, r := range roots {
		if _, ok := VerifyTag(dir, name, r, a.TrustFormat()); ok {
			return nil, nil
		}
	}
	return nil, errors.New("the signature does not verify against the trust root(s): is your signing key's public key enrolled there?")
}
