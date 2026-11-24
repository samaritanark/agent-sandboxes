package gate

import (
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"os"
	"os/exec"
	"strings"
)

// LeakscanFindingAccepted is _leakscan_finding_accepted in lib/filesystem.sh: a finding is
// accepted when the ignore file lists its "relpath:rule:line" fingerprint on a line of its own
// AND the file is tracked by git in realRepo. Arguments containing a newline are not covered by
// the differential corpus.
func LeakscanFindingAccepted(acceptFile, realRepo, relpath, rule, line string) bool {
	if acceptFile == "" {
		return false
	}
	if st, err := os.Stat(acceptFile); err != nil || st.Size() == 0 { // [[ -s ]]
		return false
	}
	data, err := os.ReadFile(acceptFile) // grep fails on a directory or unreadable file
	if err != nil {
		return false
	}
	// grep -qxF: whole-line fixed-string match; a pattern containing newlines is several patterns.
	pats := strings.Split(relpath+":"+rule+":"+line, "\n")
	found := false
	for _, l := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		for _, p := range pats {
			if l == p {
				found = true
			}
		}
	}
	if !found {
		return false
	}
	// Tracked-file gate. fsmonitor and hooks are disabled so an untrusted repo config cannot exec
	// anything on this read. The bash passed relpath as a pathspec (so `d*` or `:(top)x` matched
	// other tracked files); the LiteralPathspec fix makes it a literal path.
	spec := relpath
	if deviation.Fixed(deviation.LiteralPathspec) {
		spec = ":(literal)" + relpath
	}
	cmd := exec.Command("git", "-C", realRepo, "-c", "core.fsmonitor=", "-c", "core.hooksPath=/dev/null",
		"ls-files", "--error-unmatch", "--", spec)
	return cmd.Run() == nil
}
