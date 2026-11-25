// Package deviation names the places where the Go port deliberately behaves differently from the
// v2 bash it replaces (spike S8, decision D-34). Each ID is a quirk of the bash that was found while
// porting and fixed here; the fix is on by default. The differential tests compare against the
// bash oracle, so they run in legacy mode (SetLegacy(true)), where every fix is off and the port
// reproduces the bash exactly; each fix has its own test that turns it on. When the bash is
// deleted at release, the legacy branches and this package go with it.
package deviation

import "sync"

// ID names one fix.
type ID string

// The fixes. The comment on each says what the bash did.
const (
	// EchoOptionItems: a masked_paths: entry that is -n, -e or -E (or a combination) was swallowed
	// because the bash passed it through the echo builtin.
	EchoOptionItems ID = "echo-option-items"
	// LiteralPathspec: _leakscan_finding_accepted passed the finding's path to git as a pathspec,
	// so a glob or magic prefix in an ignore-file entry matched other tracked files.
	LiteralPathspec ID = "literal-pathspec"
	// TabFieldsExact: tab-separated records were read with IFS=$'\t' read, which collapses empty
	// fields and shifts the rest left. Records are now split on every tab.
	TabFieldsExact ID = "tab-fields-exact"
	// RawPathNames: git ls-files printed non-ASCII directory names C-quoted, so they never matched
	// the dependency-directory list. Paths are now read NUL-delimited.
	RawPathNames ID = "raw-path-names"
	// StrictReportShape: a scanner report passed the fail-closed check if its LAST JSON value was an
	// array, whatever came before. It must now be exactly one array.
	StrictReportShape ID = "strict-report-shape"
	// QuoteRepoInMaskAdd: the sandbox mask add command printed the repo path unquoted.
	QuoteRepoInMaskAdd ID = "quote-repo-in-mask-add"
	// DecimalNumbers: numeric settings and comparisons were shell arithmetic, so a leading zero
	// meant octal (08 and 09 were errors that made a comparison false, defeating "most restrictive
	// cap wins") and an oversized value wrapped around to a negative number. They are now plain
	// decimal and clamp at the largest integer. version_ge (overlay min_sandbox_version) had the
	// same wraparound: a field of 2^64 read as 0, so any CLI satisfied it; fields now compare as
	// unbounded decimals.
	DecimalNumbers ID = "decimal-numbers"
	// UnknownPostureFailsClosed: a posture other than off, advisory or required enforced like
	// required, except that with no trust root it passed like advisory. It now always enforces.
	UnknownPostureFailsClosed ID = "unknown-posture-fails-closed"
	// UnknownAgeIsStale: when a recency cap is set and the attestation's tag date could not be
	// read, the cap was skipped. An attestation of unknown age is now treated as stale.
	UnknownAgeIsStale ID = "unknown-age-is-stale"
	// StrictKeyLiteral: any value starting ssh-, sk-ssh-, ecdsa-sha2- or key:: counted as an SSH
	// key. A literal must now look like a public key (type, then base64).
	StrictKeyLiteral ID = "strict-key-literal"
	// BlobOnlyIgnoreFiles: git show of a committed ignore file that is a directory printed the tree
	// listing, which was read as fingerprints. Only a file blob is read; a directory is skipped.
	BlobOnlyIgnoreFiles ID = "blob-only-ignore-files"
	// VerifyCreatedTag: git 2.43 creates an UNSIGNED tag and exits 0 when its SSH signer fails, and
	// the bash reported success. A tag with no signature is now removed and reported as a failure.
	VerifyCreatedTag ID = "verify-created-tag"
	// VerifyExistingAttestation: a tag of the right name already existing counted as "already
	// attested" without checking that it verifies. It must now verify against the trust root.
	VerifyExistingAttestation ID = "verify-existing-attestation"
	// ExactColumns: finding_is_encrypted assumed the scanner reported StartColumn one past the real
	// start. betterleaks reports exact 1-based byte columns, so the start is used as given.
	ExactColumns ID = "exact-columns"
	// LiteralMaskedPath: config_add_masked_path passed the new entry through awk -v, which expands
	// backslash escapes, so a path containing a literal \n wrote a real newline and could inject
	// top-level keys (extra_allowed_domains:) into the repo's config. The entry is now written as is.
	LiteralMaskedPath ID = "literal-masked-path"
	// WritesReadBack: config_add_masked_path and ignorefile_add_fingerprint wrote values their own
	// readers cannot read back unchanged (a masked path with a quote, " #", a leading '#', a line
	// break, or trailing whitespace; a fingerprint with a line break or surrounding whitespace).
	// render_profile_yaml had the same gap: a line break in --repo injected keys such as
	// extra_allowed_domains: into the saved profile, and "proj #2" read back as "proj". Such an entry did
	// something other than what was asked, and was added again on every call. It is now refused.
	WritesReadBack ID = "writes-read-back"
	// ListRemovalMatchesReader: remove_yaml_list_from_file stopped at the first unindented line, so
	// column-0 "- item" entries were left behind and became part of the previous key's list (an
	// exceptions migrate turned retired secret exceptions into masked paths); it also dropped blank
	// lines after the block. It now removes exactly the block extract_yaml_list_from_file reads,
	// keeping the blank and column-0 comment lines that end it.
	ListRemovalMatchesReader ID = "list-removal-matches-reader"
	// LiteralEnvDomains: SANDBOX_EXTRA_ALLOWED_DOMAINS was split unquoted, so an entry was
	// glob-expanded against the current directory (*.example.com became a file's name), an entry
	// of -n or -e vanished into echo, and inner whitespace was deleted (a b.com became ab.com).
	// Entries are now taken literally, with only surrounding whitespace trimmed.
	LiteralEnvDomains ID = "literal-env-domains"
	// ProfileLookupStaysInDir: find_profile_path joined the name as given, so a --profile name with
	// ".." components (or an absolute one) read a YAML file outside the user and overlay profile
	// directories. Such a name is now not found. Subdirectories inside them still resolve.
	ProfileLookupStaysInDir ID = "profile-lookup-stays-in-dir"
	// StrictEgressSyntax: check_egress_target_not_blocked accepted any string. The block check
	// compared it literally, but the policy rendered it into a YAML double-quoted scalar, which
	// interprets backslash escapes, so an escaped spelling of a blocked host passed the check and
	// reached the policy as that host. An egress target must now be a host name (labels of
	// letters, digits, '-' and '_', optionally after "*.", not ending in an all-digit label) or an
	// IP address; the IPv4 blocked-CIDR check runs on the normalized target.
	StrictEgressSyntax ID = "strict-egress-syntax"
	// StrictCIDRs: validate_cidr was a shape check that accepted 10.0.0.0/33, 999.1.1.1/8 and
	// :::/8, which the enforcement layer rejects (a block that does not block). A blocked CIDR
	// must now parse as an IPv4 or IPv6 prefix.
	StrictCIDRs ID = "strict-cidrs"
	// MissingOrgBlockListFailsClosed: with the org blocked-destinations.yaml missing,
	// check_domain_not_blocked warned and skipped the overlay and user lists too, while
	// domain_is_blocked still read them. A missing org list now refuses the domain (design
	// Appendix B, item 1).
	MissingOrgBlockListFailsClosed ID = "missing-org-block-list-fails-closed"
	// CatalogueEgressFullCheck: catalogue_validate_entry checked a dependency's egress entries with
	// check_domain_not_blocked only, although its comment says "exactly like --allow-domain", so a
	// catalogue entry could grant *.com, an IP inside a blocked CIDR, or an escaped spelling of a
	// blocked host. Each entry now gets check_egress_target_not_blocked.
	CatalogueEgressFullCheck ID = "catalogue-egress-full-check"
	// AuditDomainsAsData: audit_write_session_json pasted each allowed domain between quotes into
	// JSON text, so a quote in a domain added entries to the session record and an escape was
	// recorded as the character it names (the record could show a different domain from the one
	// checked); a domain that did not make valid JSON left session.json empty. Domains are now
	// recorded as given.
	AuditDomainsAsData ID = "audit-domains-as-data"
	// DefaultRepoSensitiveTightened: a linked overlay's profile default_repo (mounted when a run
	// passes no --repo) was refused only for the home directory itself, /, hidden paths, and
	// /etc, /root, /proc, /sys and /boot. An ancestor of the home directory (/home, /Users, which
	// hold every ~/.ssh), /run, /var/run (the container socket), /dev, macOS's /private (the real
	// /etc), a case variant on a case-insensitive volume (/ETC), and the home directory written
	// with a trailing slash in $HOME all passed. They are now refused.
	DefaultRepoSensitiveTightened ID = "default-repo-sensitive-tightened"
	// StrictSymlinkScan: link_validate_shape read `find -type l` output line by line, so a symlink
	// whose name contained a newline was looked up by its fragments and an escaping one was not
	// reported. Each symlink is now checked by its real name.
	StrictSymlinkScan ID = "strict-symlink-scan"
	// ZeroSignerCount: with a trust root of no signers, the link summary printed the count as
	// "0", a newline, and "0" (grep -c prints 0 and fails, and `|| echo 0` printed another).
	ZeroSignerCount ID = "zero-signer-count"
	// AgentHomeNoFollow: onboard copied and rewrote files in the agent home (which the sandboxed
	// agent can write) with cp, a shell redirect, and chmod, all of which follow symlinks, and read
	// the staged configs through them. Onboard now refuses a path there that is not a regular file
	// and writes through a fresh temp file renamed into place (design Appendix B).
	AgentHomeNoFollow ID = "agent-home-no-follow"
	// EnvCheckByName: check_host_env_not_leaked found prefix-matched variables by reading `env`
	// output line by line, so a value containing a newline and a blocked prefix reported a variable
	// that did not exist, and an empty prefix-matched variable counted while an empty exact-named
	// one did not. Names now come from the environment entries, and empty values never count.
	EnvCheckByName ID = "env-check-by-name"
	// FlagValueErrors: a flag given without a value (or with an empty one) failed through bash's
	// "${2:?...}" expansion, which prints the script's path and source line ("bin/sandbox: line
	// 4951: 2: --tier requires a value") rather than an ERROR line. It now prints
	// "ERROR: --tier requires a value".
	FlagValueErrors ID = "flag-value-errors"
	// RepoPathCaseInsensitive: validate_repo_path compared a workspace with the forbidden
	// credential directories, the home directory, and the sandbox's own state by exact string, but
	// macOS volumes ignore case and realpath keeps the case as typed, so --repo ~/.SSH passed and
	// mounted ~/.ssh. The comparisons now ignore case.
	RepoPathCaseInsensitive ID = "repo-path-case-insensitive"
	// CheckHelp: `sandbox check --help` took --help as the workspace path and failed ("Repo path
	// does not exist"). It now prints the usage line.
	CheckHelp ID = "check-help"
	// MaskPathComponents: `sandbox mask add` refused a RELPATH starting with '/' or "../" or
	// containing "/../", but not "", ".", "..", "a/..", or "./x": those stored masks such as "/"
	// or "../" (the whole workspace or its parent) or one that never matches ("./x"). A RELPATH
	// that is empty or has a "." or ".." component is now refused.
	MaskPathComponents ID = "mask-path-components"
	// MaskListStatus: `sandbox mask list` exited 1 whenever the repo had configured masked paths
	// (its last command was `[[ $any == false ]] && echo "(none)"`). It now exits 0.
	MaskListStatus ID = "mask-list-status"
)

var (
	mu     sync.RWMutex
	legacy bool
	forced = map[ID]bool{}
)

// Fixed reports whether the fix is on. It is on unless legacy mode is set (and the fix was not
// forced on for a test).
func Fixed(id ID) bool {
	mu.RLock()
	defer mu.RUnlock()
	return !legacy || forced[id]
}

// SetLegacy turns every fix off (true) or on (false). Differential tests call SetLegacy(true) in
// TestMain.
func SetLegacy(on bool) {
	mu.Lock()
	legacy = on
	mu.Unlock()
}

// Force turns one fix on while legacy mode is set, and returns a function that undoes it. Use it
// as `defer deviation.Force(deviation.X)()`.
func Force(id ID) (restore func()) {
	mu.Lock()
	prev := forced[id]
	forced[id] = true
	mu.Unlock()
	return func() {
		mu.Lock()
		forced[id] = prev
		mu.Unlock()
	}
}
