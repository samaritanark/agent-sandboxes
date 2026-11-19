package gate

import (
	"regexp"
	"strings"

	"git.theark.cloud/acs/agent-sandboxes/go/internal/config"
)

// Rule tables shared with the mask builder (MASKED_* in lib/filesystem.sh).
var (
	maskedFilePaths = []string{".env", ".env.local", ".npmrc", "clouds.yaml", "kubeconfig"}
	maskedDirPath   = ".kube"
)

const maskedOpenrcSuffix = "-openrc.sh" // MASKED_OPENRC_PATTERN='*-openrc.sh'

const repoConfigName = ".sandbox/config.yaml" // SANDBOX_REPO_CONFIG_NAME

var (
	listItemLead = regexp.MustCompile(`^[[:space:]]*-[[:space:]]*`)
	// echo "-n", "-e", "-E" and combinations are options to bash's builtin echo, not text.
	echoOption = regexp.MustCompile(`^-[neE]+$`)
)

// IsPathMasked is is_path_masked in lib/filesystem.sh: whether a workspace-relative path is hidden
// from the agent by the sandbox mask (built-in set plus the repo's masked_paths: list).
func IsPathMasked(repo, relpath string) bool {
	for _, p := range maskedFilePaths {
		if relpath == p {
			return true
		}
	}
	if relpath == maskedDirPath || strings.HasPrefix(relpath, maskedDirPath+"/") {
		return true
	}
	if !strings.Contains(relpath, "/") && strings.HasSuffix(relpath, maskedOpenrcSuffix) {
		return true
	}
	for _, p := range config.ExtractYAMLList(repo+"/"+repoConfigName, "masked_paths") {
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
