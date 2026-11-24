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
	// decimal and clamp at the largest integer.
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
	// break, or trailing whitespace; a fingerprint with a line break or surrounding whitespace). Such an entry did
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
