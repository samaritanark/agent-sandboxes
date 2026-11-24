// Package catalogue is lib/catalogue.sh: resolving a vetted dependency entry by name (org install
// first, then the team overlay), reading its fields, and validating it before it is deployed.
package catalogue

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/checks"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

// Resource defaults for a dependency pod (CATALOGUE_DEFAULT_*).
const (
	DefaultCPURequest     = "250m"
	DefaultCPULimit       = "1"
	DefaultMemRequest     = "256Mi"
	DefaultMemLimit       = "512Mi"
	DefaultEphemeralLimit = "1Gi"
	DefaultRunAsUser      = "1000"
)

// Ctx is what the catalogue reads: the block lists (for egress), the install root
// ($SANDBOX_ROOT), and how to find and run cosign.
type Ctx struct {
	checks.Ctx
	SandboxRoot string
	HasCosign   func() bool              // command -v cosign
	RunCosign   func(args []string) bool // cosign args... >/dev/null 2>&1; true on exit 0
}

var nameChars = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// IsValidName is catalogue_is_valid_name: like is_valid_profile_name, but a numeric name is
// allowed.
func IsValidName(name string) bool {
	return name != "" && !strings.Contains(name, "/") && !strings.Contains(name, "..") &&
		!strings.HasPrefix(name, ".") && nameChars.MatchString(name)
}

// OrgDir is org_catalogue_dir.
func (c Ctx) OrgDir() string { return c.SandboxRoot + "/config/catalogue" }

// OverlayDir is overlay_catalogue_dir: the overlay's catalogue directory if it exists, else "".
func (c Ctx) OverlayDir() string {
	ov := config.ResolveOverlayPath(c.Env)
	if ov == "" {
		return ""
	}
	if st, err := os.Stat(ov + "/catalogue"); err == nil && st.IsDir() {
		return ov + "/catalogue"
	}
	return ""
}

// Resolve is catalogue_resolve: the org entry, else the overlay's; ok is false on a miss or an
// invalid name.
func (c Ctx) Resolve(name string) (string, bool) {
	if !IsValidName(name) {
		return "", false
	}
	if p := c.OrgDir() + "/" + name + ".yaml"; config.IsFile(p) {
		return p, true
	}
	if d := c.OverlayDir(); d != "" && config.IsFile(d+"/"+name+".yaml") {
		return d + "/" + name + ".yaml", true
	}
	return "", false
}

var echoOption = regexp.MustCompile(`^-[neE]+$`)

// Field is catalogue_field: a scalar field, or def when it is absent or empty. In legacy mode a
// value that is an echo option (-n, -e, -E, or a combination) comes back empty, because the bash
// prints it with echo; with EchoOptionItems it is kept.
func Field(path, key, def string) string {
	v := config.ExtractYAMLScalar(path, key)
	if v == "" {
		v = def
	}
	if !deviation.Fixed(deviation.EchoOptionItems) && echoOption.MatchString(v) {
		return ""
	}
	return v
}

// List is catalogue_list.
func List(path, key string) []string { return config.ExtractYAMLList(path, key) }

// HasKey is catalogue_has_key: a top-level "<key>:" line exists, whatever its value. key must not
// contain regex metacharacters.
func HasKey(path, key string) bool {
	if !config.IsFile(path) {
		return false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, l := range bashcompat.SplitRecords(b) {
		if strings.HasPrefix(l, key+":") {
			return true
		}
	}
	return false
}

// Error is a validation failure: the ERROR lines the bash prints to stderr.
type Error struct{ Lines []string }

func (e *Error) Error() string { return strings.Join(e.Lines, "\n") }

func fail(lines ...string) error { return &Error{Lines: lines} }

var (
	digestPinned = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	allDigits    = regexp.MustCompile(`^[0-9]+$`)
	secretName   = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	forbidden    = []string{"cap_add", "capabilities", "privileged", "host_network", "hostPID", "hostIPC"}
)

// intOf is a digit string as the bash's [[ -lt / -gt / -eq ]] reads it: octal with a leading 0 (8
// and 9 an error) and 64-bit wraparound in legacy mode, plain decimal with DecimalNumbers.
func intOf(s string) (int64, bool) {
	if deviation.Fixed(deviation.DecimalNumbers) {
		return bashcompat.Decimal(s)
	}
	return bashcompat.Arith(s)
}

// ValidateEntry is catalogue_validate_entry: nil when the entry at path is safe to deploy, else
// the first failure.
//
// In legacy mode each egress entry gets only the domain block check (check_domain_not_blocked);
// with CatalogueEgressFullCheck it gets the full egress check every other egress source gets
// (check_egress_target_not_blocked): host-name syntax, the over-broad wildcard refusal, and the
// blocked-CIDR check for an IP literal.
func (c Ctx) ValidateEntry(path, name string) error {
	pre := fmt.Sprintf("ERROR: catalogue entry '%s': ", name)
	kind, image, port := Field(path, "kind", ""), Field(path, "image", ""), Field(path, "port", "")
	if kind != "mcp" && kind != "service" {
		return fail(fmt.Sprintf("%skind must be 'mcp' or 'service' (got '%s').", pre, kind))
	}
	if image == "" {
		return fail(pre + "missing required 'image'.")
	}
	if !digestPinned.MatchString(image) {
		return fail(pre+"image must be digest-pinned",
			fmt.Sprintf("       (…@sha256:<64 hex>), not a mutable tag: '%s'.", image))
	}
	badPort := !allDigits.MatchString(port)
	if !badPort {
		if v, ok := intOf(port); ok && (v < 1 || v > 65535) {
			badPort = true
		}
	}
	if badPort {
		return fail(fmt.Sprintf("%s'port' must be 1-65535 (got '%s').", pre, port))
	}
	if uid := Field(path, "run_as_user", ""); uid != "" {
		bad := !allDigits.MatchString(uid)
		if !bad {
			if v, ok := intOf(uid); ok && v == 0 {
				bad = true
			}
		}
		if bad {
			return fail(fmt.Sprintf("%srun_as_user must be a non-zero UID (got '%s').", pre, uid))
		}
	}
	for _, d := range List(path, "egress") {
		if d == "" {
			continue
		}
		if d == "*" {
			return fail(pre + "egress '*' (allow-all) is forbidden.")
		}
		if deviation.Fixed(deviation.CatalogueEgressFullCheck) {
			if _, err := c.CheckEgressTargetNotBlocked(d); err != nil {
				reason := strings.TrimPrefix(strings.SplitN(err.Error(), "\n", 2)[0], "ERROR: ")
				return fail(fmt.Sprintf("%segress domain '%s' is refused:", pre, d), "       "+reason)
			}
			continue
		}
		if _, err := c.CheckDomainNotBlocked(d); err != nil {
			return fail(fmt.Sprintf("%segress domain '%s' is blocked by", pre, d),
				"       the org or overlay blocked-destinations list.")
		}
	}
	for _, s := range List(path, "secrets") {
		if s != "" && !secretName.MatchString(s) {
			return fail(fmt.Sprintf("%ssecret name '%s' must match", pre, s),
				"       [A-Z_][A-Z0-9_]* (it becomes an env var in the dep pod).")
		}
	}
	if kind == "mcp" {
		if t := Field(path, "mcp_transport", "http"); t != "http" && t != "sse" {
			return fail(fmt.Sprintf("%smcp_transport must be 'http' or 'sse' (got '%s').", pre, t))
		}
	}
	for _, f := range forbidden {
		if HasKey(path, f) {
			return fail(fmt.Sprintf("%sfield '%s' is forbidden.", pre, f),
				"       Dependencies run with ALL capabilities dropped and no host",
				"       namespaces; a browser uses --no-sandbox, never added caps (§1.8).")
		}
	}
	class, verify := Field(path, "class", ""), Field(path, "verify_signature", "")
	if class == "browser" && verify != "true" {
		return fail(pre+"class 'browser' requires",
			"       'verify_signature: true' — the largest, most third-party image",
			"       in the catalogue is the highest-value supply-chain target and",
			"       must be signature-verified, not digest-pinned alone (§2.7 #2).")
	}
	if verify == "true" {
		return c.VerifyImageSignature(path, name, image)
	}
	return nil
}

// VerifyImageSignature is verify_catalogue_image_signature: cosign with the entry's key, or its
// keyless identity (a regexp) and issuer; fails closed when cosign is missing.
func (c Ctx) VerifyImageSignature(path, name, image string) error {
	if !c.HasCosign() {
		return fail(fmt.Sprintf("ERROR: catalogue entry '%s' requires signature verification but", name),
			"       'cosign' is not installed. Install cosign or remove the entry.")
	}
	key, identity, issuer := Field(path, "cosign_key", ""), Field(path, "cosign_identity", ""), Field(path, "cosign_issuer", "")
	args := []string{"verify"}
	switch {
	case key != "":
		args = append(args, "--key", key)
	case identity != "" && issuer != "":
		args = append(args, "--certificate-identity-regexp", identity, "--certificate-oidc-issuer", issuer)
	default:
		return fail(fmt.Sprintf("ERROR: catalogue entry '%s': verify_signature is set but neither", name),
			"       cosign_key nor (cosign_identity + cosign_issuer) is declared.")
	}
	if !c.RunCosign(append(args, image)) {
		return fail(fmt.Sprintf("ERROR: catalogue entry '%s': cosign signature verification failed", name),
			fmt.Sprintf("       for image '%s'.", image))
	}
	return nil
}
