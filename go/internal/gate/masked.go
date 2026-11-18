package gate

import (
	"os"
	"regexp"
	"strings"
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

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\v' || b == '\f' || b == '\r'
}

// ExtractYAMLList is extract_yaml_list_from_file in lib/config.sh: the items of a top-level
// "<key>:" block list in a flat YAML file, one per element. key must not contain regex
// metacharacters (the awk interpolates it into a regex; every caller passes a fixed word).
//
// Quirk kept from the original: a list line, or an item left after the leading "- " is removed,
// that is exactly -n, -e or -E (or a combination) is swallowed, because the bash passes it to the
// echo builtin, which reads it as an option. (A list entry named "-n" can therefore never be a mask.)
func ExtractYAMLList(path, key string) []string {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	flag := false
	for _, line := range splitRecords(data) {
		if strings.HasPrefix(line, key+":") {
			flag = true
			continue
		}
		if flag && line != "" {
			if c := line[0]; c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				flag = false
			}
		}
		if !flag {
			continue
		}
		t := strings.TrimLeft(line, " \t\n\v\f\r")
		if !strings.HasPrefix(t, "-") {
			continue
		}
		if echoOption.MatchString(line) {
			continue
		}
		item := listItemLead.ReplaceAllString(line, "")
		item = strings.NewReplacer(`"`, "", `'`, "").Replace(item)
		// ${item%%[[:space:]]#*}: cut at the first whitespace character that is followed by '#'.
		for i := 0; i+1 < len(item); i++ {
			if isSpace(item[i]) && item[i+1] == '#' {
				item = item[:i]
				break
			}
		}
		item = strings.TrimRight(item, " \t\n\v\f\r")
		if item == "" || item[0] == '#' {
			continue
		}
		if echoOption.MatchString(item) { // the final `echo "${item}"` swallows it the same way
			continue
		}
		out = append(out, item)
	}
	return out
}

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
	for _, p := range ExtractYAMLList(repo+"/"+repoConfigName, "masked_paths") {
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
