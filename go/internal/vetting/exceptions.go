package vetting

import (
	"bytes"
	"os"
	"strings"

	"git.theark.cloud/acs/agent-sandboxes/go/internal/bashcompat"
	"git.theark.cloud/acs/agent-sandboxes/go/internal/config"
)

const (
	ignoreName     = ".betterleaksignore"
	ignoreFallback = ".gitleaksignore"
	repoConfigRel  = ".sandbox/config.yaml"
)

// gitShow is `_vetting_git repo show <rev>:<path>`; ok is false when git fails.
func gitShow(repo, rev, path string) ([]byte, bool) {
	cmd := VettingGit(repo, "show", rev+":"+path)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, false
	}
	return out.Bytes(), true
}

// CommittedIgnoreFingerprints is vetting_committed_ignore_fingerprints: the fingerprints in the
// repo-root ignore file as committed at rev (default HEAD), never the working tree.
func CommittedIgnoreFingerprints(repo, rev string) []string {
	if rev == "" {
		rev = "HEAD"
	}
	for _, name := range []string{ignoreName, ignoreFallback} {
		if b, ok := gitShow(repo, rev, name); ok {
			return config.StripIgnoreFileComments(b)
		}
	}
	return nil
}

// committedList reads a YAML list from HEAD's committed .sandbox/config.yaml.
func committedList(repo, key string) []string {
	f, err := os.CreateTemp(os.TempDir(), "sandbox-accept-src-")
	if err != nil {
		return nil
	}
	defer os.Remove(f.Name())
	if b, ok := gitShow(repo, "HEAD", repoConfigRel); ok {
		f.Write(b)
	}
	f.Close()
	return config.ExtractYAMLList(f.Name(), key)
}

// CommittedLegacyAcceptedSecrets is vetting_committed_legacy_accepted_secrets.
func CommittedLegacyAcceptedSecrets(repo string) []string {
	return committedList(repo, "accepted_secrets")
}

// CommittedAllowedDomains is vetting_committed_allowed_domains.
func CommittedAllowedDomains(repo string) []string {
	return committedList(repo, "extra_allowed_domains")
}

// statusFirst is `IFS=$'\t' read -r status _ <<<"$(vetting_status_repo repo)"`.
func (c Ctx) statusFields(repo string) []string { return bashcompat.ReadTab(c.StatusRepo(repo), 6) }

// VettedRepoAllowedDomains is vetted_repo_allowed_domains: the committed egress list, only for a
// repo that is currently vetted.
func (c Ctx) VettedRepoAllowedDomains(repo string) []string {
	if c.statusFields(repo)[0] != "vetted" {
		return nil
	}
	return CommittedAllowedDomains(repo)
}

// RepoGrantedAllowedDomains is repo_granted_allowed_domains: only when the overlay opted in
// (honorFlag exactly "true") and the repo is vetted.
func (c Ctx) RepoGrantedAllowedDomains(honorFlag, repo string) []string {
	if honorFlag != "true" {
		return nil
	}
	return c.VettedRepoAllowedDomains(repo)
}

// RepoIgnoreFile is repo_ignore_file in lib/config.sh.
func RepoIgnoreFile(repo string) string {
	for _, f := range []string{ignoreName, ignoreFallback} {
		if config.IsFile(repo + "/" + f) {
			return repo + "/" + f
		}
	}
	return repo + "/" + ignoreName
}

// LoadRepoIgnoreFingerprints is load_repo_ignore_fingerprints: the working-tree view.
func LoadRepoIgnoreFingerprints(repo string) []string {
	f := RepoIgnoreFile(repo)
	if !config.IsFile(f) {
		return nil
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return nil
	}
	return config.StripIgnoreFileComments(b)
}

// VettedAcceptedFingerprints is vetted_accepted_fingerprints in lib/filesystem.sh: the ignore-file
// fingerprints the secret gate may honor, or nothing unless the repo is vetted (or the operator
// accepted the unvetted repo outright).
func (c Ctx) VettedAcceptedFingerprints(repo, acceptUnvetted string) []string {
	f := c.statusFields(repo)
	status, tag, behind := f[0], f[2], f[4]
	if status != "vetted" || tag == "" {
		if acceptUnvetted == "true" {
			return LoadRepoIgnoreFingerprints(repo)
		}
		return nil
	}
	if c.ExceptionsRequireHead() == "true" {
		b := behind
		if b == "" {
			b = "1"
		}
		if !bashcompat.ArithCmp(b, "0", "eq") {
			return nil
		}
	}
	if c.ExceptionsFromCommit() == "true" {
		return CommittedIgnoreFingerprints(repo, tag)
	}
	return LoadRepoIgnoreFingerprints(repo)
}

// SSHKeyUsable is _vetting_ssh_key_usable: a literal SSH public key, or an existing key file.
func (c Ctx) SSHKeyUsable(key string) bool {
	for _, p := range []string{"ssh-", "sk-ssh-", "ecdsa-sha2-", "key::"} {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return config.IsFile(c.tilde(key))
}

// SSHSigningKeyState is _vetting_ssh_signingkey_state: ok, unconfigured, mismatch, or knob-bad.
func (c Ctx) SSHSigningKeyState(repo string) string {
	if vsk := c.SigningKey(); vsk != "" {
		if c.SSHKeyUsable(vsk) {
			return "ok"
		}
		return "knob-bad"
	}
	real, err := physicalDir(repo)
	if err != nil {
		return "unconfigured"
	}
	out, _ := vgit(real, "config", "user.signingkey")
	key := trimNL(out)
	if key == "" {
		return "unconfigured"
	}
	if c.SSHKeyUsable(key) {
		return "ok"
	}
	return "mismatch"
}

// SigningConfigured is _vetting_signing_configured.
func (c Ctx) SigningConfigured(repo string) bool {
	if c.TrustFormat() == "gpg" {
		return true
	}
	return c.SSHSigningKeyState(repo) == "ok"
}
