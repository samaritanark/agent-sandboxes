// Package vetting is the Go port of the repo-vetting gate in lib/vetting.sh (spike S8, D-34).
// Like package gate, it reproduces the bash exactly, quirks included, because the bash is the
// oracle until release.
package vetting

import (
	"io"
	"os"
	"regexp"
	"strings"

	"git.theark.cloud/acs/agent-sandboxes/go/internal/bashcompat"
	"git.theark.cloud/acs/agent-sandboxes/go/internal/config"
)

// Ctx carries what the bash reads from the environment and the clock.
type Ctx struct {
	config.Env                    // Home, UserConfig, SandboxOverlay
	TrustRootDefault string       // $SANDBOX_VETTING_TRUST_ROOT_DEFAULT
	TagPrefix        string       // $SANDBOX_VETTING_TAG_PREFIX
	Now              func() int64 // `date +%s`
	Stderr           io.Writer    // where the bash writes WARN lines
}

// NewCtx builds a Ctx from the process environment with the bash's defaults.
func NewCtx(now func() int64) Ctx {
	e := config.FromOS()
	c := Ctx{Env: e, Now: now, Stderr: os.Stderr}
	c.TrustRootDefault = os.Getenv("SANDBOX_VETTING_TRUST_ROOT_DEFAULT")
	if c.TrustRootDefault == "" {
		c.TrustRootDefault = e.Home + "/.sandbox/vetting/allowed_signers"
	}
	c.TagPrefix = os.Getenv("SANDBOX_VETTING_TAG_PREFIX")
	if c.TagPrefix == "" {
		c.TagPrefix = "agent-vetted/"
	}
	return c
}

// userGet reads a scalar from the user config; "" if the file or key is absent.
func (c Ctx) userGet(key string) string {
	if config.IsFile(c.UserConfig) {
		return config.ExtractYAMLScalar(c.UserConfig, key)
	}
	return ""
}

func (c Ctx) overlayDir() string {
	ov := config.ResolveOverlayPath(c.Env)
	if ov != "" && config.IsFile(ov+"/config.yaml") {
		return ov
	}
	return ""
}

func (c Ctx) overlayGet(key string) string {
	if ov := c.overlayDir(); ov != "" {
		return config.ExtractYAMLScalar(ov+"/config.yaml", key)
	}
	return ""
}

// configGet is _vetting_config_get: the user config's value, else the overlay's.
func (c Ctx) configGet(key string) string {
	if v := c.userGet(key); v != "" {
		return v
	}
	return c.overlayGet(key)
}

func rank(p string) int {
	switch p {
	case "off":
		return 0
	case "advisory":
		return 1
	case "required":
		return 2
	}
	return 1
}

// normalize is _vetting_normalize; an unknown non-empty value warns and becomes advisory.
func (c Ctx) normalize(v string) string {
	switch v {
	case "off", "advisory", "required":
		return v
	case "":
		return ""
	}
	if c.Stderr != nil {
		io.WriteString(c.Stderr, "WARN: unrecognized vetting posture '"+v+"' — treating as 'advisory'.\n")
	}
	return "advisory"
}

// ResolvePosture is resolve_vetting_posture: the user's choice (default advisory), which an
// overlay can only ratchet up.
func (c Ctx) ResolvePosture() string {
	userP := c.normalize(c.userGet("vetting"))
	eff := userP
	if eff == "" {
		eff = "advisory"
	}
	if ov := c.overlayDir(); ov != "" {
		overlayP := c.normalize(config.ExtractYAMLScalar(ov+"/config.yaml", "vetting"))
		if overlayP != "" && rank(overlayP) > rank(eff) {
			eff = overlayP
		}
	}
	return eff
}

var digits = regexp.MustCompile(`^[0-9]+$`)

// minCap is the shared loop of vetting_max_commits_behind and vetting_max_age_days: the smallest
// digits-only value of the user and overlay settings, found with the bash's comparison.
func (c Ctx) minCap(key string) string {
	eff := ""
	for _, v := range []string{c.userGet(key), c.overlayGet(key)} {
		if !digits.MatchString(v) {
			continue
		}
		if eff == "" || bashcompat.ArithLess(v, eff) {
			eff = v
		}
	}
	return eff
}

func (c Ctx) MaxCommitsBehind() string { return c.minCap("vetting_max_commits_behind") }
func (c Ctx) MaxAgeDays() string       { return c.minCap("vetting_max_age_days") }

// AgeDays is _vetting_age_days: whole days since a unix timestamp; "" when unknown.
func (c Ctx) AgeDays(epoch string) string {
	if !digits.MatchString(epoch) {
		return ""
	}
	e, ok := bashcompat.Arith(epoch)
	if !ok {
		return ""
	}
	now := c.Now()
	if e > now {
		return "0"
	}
	return itoa((now - e) / 86400)
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// strict is the shared shape of the tighten-only switches: "true" wins if either side sets it.
func (c Ctx) strict(key string) string {
	if c.userGet(key) == "true" || c.overlayGet(key) == "true" {
		return "true"
	}
	return "false"
}

func (c Ctx) ExceptionsRequireHead() string  { return c.strict("vetting_exceptions_require_head") }
func (c Ctx) RequireCleanWorktree() string   { return c.strict("vetting_require_clean_worktree") }
func (c Ctx) ExceptionsFromCommit() string   { return c.strict("vetting_exceptions_from_commit") }
func (c Ctx) ForbidUnvettedOverride() string { return c.strict("vetting_forbid_unvetted_override") }

func (c Ctx) tilde(v string) string {
	if strings.HasPrefix(v, "~") {
		return c.Home + v[1:]
	}
	return v
}

// TrustRoot is vetting_trust_root: the operator's own signer trust root.
func (c Ctx) TrustRoot() string {
	if v := c.userGet("vetting_trust_root"); v != "" {
		return c.tilde(v)
	}
	return c.TrustRootDefault
}

// TrustRoots is vetting_trust_roots: every existing trust root, operator-local first.
func (c Ctx) TrustRoots() []string {
	var out []string
	userRoot := c.TrustRoot()
	if config.Exists(userRoot) {
		out = append(out, userRoot)
	}
	if ov := c.overlayDir(); ov != "" {
		if v := config.ExtractYAMLScalar(ov+"/config.yaml", "vetting_trust_root"); v != "" {
			v = c.tilde(v)
			if !strings.HasPrefix(v, "/") {
				v = ov + "/" + v
			}
			if config.Exists(v) && v != userRoot {
				out = append(out, v)
			}
		}
	}
	return out
}

// TrustFormat is vetting_trust_format: "ssh" (default) or "gpg".
func (c Ctx) TrustFormat() string {
	switch v := c.configGet("vetting_trust_format"); v {
	case "gpg", "ssh":
		return v
	}
	return "ssh"
}

// SigningKey is vetting_signing_key (user config only).
func (c Ctx) SigningKey() string { return c.tilde(c.userGet("vetting_signing_key")) }

var (
	gpgSigner = regexp.MustCompile(`.*Good signature from "([^"]*)".*`)
	sshSigner = regexp.MustCompile(`.*Good "[^"]*" signature for ([^ ]*).*`)
)

// ExtractSigner is _vetting_extract_signer: the signer principal from `git tag -v` output.
func ExtractSigner(out, format string) string {
	re := sshSigner
	if format == "gpg" {
		re = gpgSigner
	}
	for _, line := range strings.Split(out, "\n") {
		if m := re.FindStringSubmatchIndex(line); m != nil && m[0] == 0 && m[1] == len(line) {
			return line[m[2]:m[3]]
		}
	}
	return ""
}
