package gate

import (
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/tables"
)

// Rule tables shared with the mask builder and the host's sync gate (MASKED_* in
// lib/filesystem.sh); the data lives in internal/tables.
var (
	MaskedFilePaths = tables.MaskedFilePaths
	MaskedDirPath   = tables.MaskedDirPath
)

const maskedOpenrcSuffix = tables.MaskedOpenrcSuffix // MASKED_OPENRC_PATTERN='*-openrc.sh'

// MaskedOpenrcPattern is MASKED_OPENRC_PATTERN, as `sandbox mask list` prints it.
const MaskedOpenrcPattern = "*" + maskedOpenrcSuffix

var (
	listItemLead = regexp.MustCompile(`^[[:space:]]*-[[:space:]]*`)
	// echo "-n", "-e", "-E" and combinations are options to bash's builtin echo, not text.
	echoOption = regexp.MustCompile(`^-[neE]+$`)
)

// IsPathMasked is is_path_masked in lib/filesystem.sh: whether a workspace-relative path is hidden
// from the agent by the sandbox mask (built-in set plus the repo's masked_paths: list).
func IsPathMasked(repo, relpath string) bool {
	for _, p := range MaskedFilePaths {
		if relpath == p {
			return true
		}
	}
	if relpath == MaskedDirPath || strings.HasPrefix(relpath, MaskedDirPath+"/") {
		return true
	}
	if !strings.Contains(relpath, "/") && strings.HasSuffix(relpath, maskedOpenrcSuffix) {
		return true
	}
	for _, p := range config.LoadRepoMaskedPaths(repo) {
		if strings.HasSuffix(p, "/") {
			d := strings.TrimSuffix(p, "/")
			if relpath == d || strings.HasPrefix(relpath, d+"/") {
				return true
			}
		} else if relpath == p {
			return true
		}
	}
	return false
}
