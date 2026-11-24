package config

import (
	"os"
	"sort"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

// The repo-root secret-exception store: SANDBOX_REPO_IGNORE_NAME and SANDBOX_REPO_IGNORE_FALLBACK.
const (
	RepoIgnoreName     = ".betterleaksignore"
	RepoIgnoreFallback = ".gitleaksignore"
)

// RepoIgnoreFile is repo_ignore_file: an existing .betterleaksignore, else an existing
// .gitleaksignore, else the .betterleaksignore path (for a writer to create).
func RepoIgnoreFile(repo string) string {
	for _, f := range []string{RepoIgnoreName, RepoIgnoreFallback} {
		if IsFile(repo + "/" + f) {
			return repo + "/" + f
		}
	}
	return repo + "/" + RepoIgnoreName
}

// LoadRepoIgnoreFingerprints is load_repo_ignore_fingerprints: the working-tree fingerprints.
func LoadRepoIgnoreFingerprints(repo string) []string {
	f := RepoIgnoreFile(repo)
	if !IsFile(f) {
		return nil
	}
	b, err := os.ReadFile(f)
	if err != nil {
		return nil
	}
	return StripIgnoreFileComments(b)
}

// LoadRepoMaskedPaths is load_repo_masked_paths: the repo's masked_paths: list.
func LoadRepoMaskedPaths(repo string) []string {
	return ExtractYAMLList(repo+"/"+RepoConfigName, "masked_paths")
}

// LoadRepoAcceptedSecrets is load_repo_accepted_secrets: the retired accepted_secrets: list.
func LoadRepoAcceptedSecrets(repo string) []string {
	return ExtractYAMLList(repo+"/"+RepoConfigName, "accepted_secrets")
}

// LoadExtraAllowedDomains is load_extra_allowed_domains_from_file.
func LoadExtraAllowedDomains(path string) []string {
	return ExtractYAMLList(path, "extra_allowed_domains")
}

// HonorRepoAllowedDomains is honor_repo_allowed_domains: true only when the team overlay's
// config.yaml sets honor_repo_allowed_domains: true. The key is read from the overlay alone.
func HonorRepoAllowedDomains(e Env) bool {
	ov := ResolveOverlayPath(e)
	if ov == "" || !IsFile(ov+"/config.yaml") {
		return false
	}
	return ExtractYAMLScalar(ov+"/config.yaml", "honor_repo_allowed_domains") == "true"
}

// UserExtraAllowedDomains is load_user_extra_allowed_domains: the user config's
// extra_allowed_domains: list, then the comma-separated SANDBOX_EXTRA_ALLOWED_DOMAINS.
//
// In legacy mode an env entry is glob-expanded against the current directory, an entry that is
// an echo option is dropped, and all whitespace is deleted; with LiteralEnvDomains an entry is
// taken as written, with surrounding whitespace trimmed.
func UserExtraAllowedDomains(e Env) []string {
	out := LoadExtraAllowedDomains(e.UserConfig)
	if e.ExtraAllowedDomains == "" {
		return out
	}
	if deviation.Fixed(deviation.LiteralEnvDomains) {
		for _, d := range strings.Split(e.ExtraAllowedDomains, ",") {
			if d = strings.Trim(d, " \t\n\v\f\r"); d != "" {
				out = append(out, d)
			}
		}
		return out
	}
	for _, w := range ifsSplit(e.ExtraAllowedDomains, ',') {
		for _, d := range bashGlob(w) {
			d = strings.Map(func(r rune) rune {
				if r < 0x80 && isSpace(byte(r)) {
					return -1
				}
				return r
			}, d) // echo "${domain}" | tr -d '[:space:]'
			// The final `echo "${domain}"` swallows an echo option (so does the first, but the
			// option survives tr unchanged, so one check covers both).
			if d != "" && !echoOption.MatchString(d) {
				out = append(out, d)
			}
		}
	}
	return out
}

// ifsSplit is bash word splitting of an unquoted expansion with IFS set to one non-whitespace
// character: every separator ends a field, so empty fields are kept, except that a trailing
// separator does not start a new field.
func ifsSplit(s string, sep byte) []string {
	if s == "" {
		return nil
	}
	f := strings.Split(s, string(sep))
	if strings.HasSuffix(s, string(sep)) {
		f = f[:len(f)-1]
	}
	return f
}

// bashGlob is bash pathname expansion of one word against the current directory, with the
// default options: no match leaves the word as is; a leading '.' must be matched literally; the
// matches come back sorted (byte order under LC_ALL=C). A word with '/' is left as is (the
// corpus has none; a domain cannot contain one).
func bashGlob(w string) []string {
	if !strings.ContainsAny(w, "*?[") || strings.Contains(w, "/") {
		return []string{w}
	}
	ents, err := os.ReadDir(".")
	if err != nil {
		return []string{w}
	}
	var m []string
	for _, de := range ents {
		n := de.Name()
		if n[0] == '.' && w[0] != '.' {
			continue
		}
		if bashcompat.Glob(w, n) {
			m = append(m, n)
		}
	}
	if len(m) == 0 {
		return []string{w}
	}
	sort.Strings(m)
	return m
}
