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
	// ExactColumns: finding_is_encrypted assumed the scanner reported StartColumn one past the real
	// start. betterleaks reports exact 1-based byte columns, so the start is used as given.
	ExactColumns ID = "exact-columns"
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
