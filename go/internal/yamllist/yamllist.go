// Package yamllist reads a top-level block list ("key:" then "  - item" lines) from a flat YAML
// file, exactly as lib/config.sh's extract_yaml_list_from_file printed it. It has no dependencies,
// so both the in-VM policy layer (through config) and the host binary's sync gate use it: the host
// reads a repository's masked_paths: itself (the owner's decision, 2026-11-25), since the VM's
// report of the list cannot be trusted, and both sides must read it the same way.
package yamllist

import (
	"regexp"
	"strings"
)

var (
	itemLead   = regexp.MustCompile(`^[[:space:]]*-[[:space:]]*`)
	echoOption = regexp.MustCompile(`^-[neE]+$`) // what bash's echo swallows as an option
)

// RepoConfig is a repository's own sandbox config, relative to its root.
const RepoConfig = ".sandbox/config.yaml"

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\v' || b == '\f' || b == '\r'
}

// records splits data into lines as bash's `while read` saw them (a last line without a newline
// counts).
func records(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	s := string(data)
	parts := strings.Split(s, "\n")
	if strings.HasSuffix(s, "\n") {
		parts = parts[:len(parts)-1]
	}
	return parts
}

// Extract returns the items of the "key:" list in data. legacyEcho reproduces v2's quirk of
// dropping an item that is exactly -n, -e or -E (or a combination), which the bash passed to echo;
// the fixed behaviour (deviation EchoOptionItems) keeps it.
func Extract(data []byte, key string, legacyEcho bool) []string {
	var out []string
	flag := false
	for _, line := range records(data) {
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
		if !strings.HasPrefix(strings.TrimLeft(line, " \t\n\v\f\r"), "-") {
			continue
		}
		if item, ok := listItem(line, legacyEcho); ok {
			out = append(out, item)
		}
	}
	return out
}

// Item is what the list reader yields for one list line ("  - x"), and false when it yields
// nothing (writers use it to check that a value reads back unchanged).
func Item(line string, legacyEcho bool) (string, bool) { return listItem(line, legacyEcho) }

func listItem(line string, legacyEcho bool) (string, bool) {
	if legacyEcho && echoOption.MatchString(line) {
		return "", false
	}
	item := itemLead.ReplaceAllString(line, "")
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
		return "", false
	}
	if legacyEcho && echoOption.MatchString(item) {
		return "", false
	}
	return item, true
}

// IsEchoOption reports whether s is a string bash's echo takes as options.
func IsEchoOption(s string) bool { return echoOption.MatchString(s) }
