// Package config reads the flat YAML configuration files the sandbox uses (the user config, the
// team overlay, and a repo's .sandbox/config.yaml) exactly as lib/config.sh and lib/profile.sh do.
package config

import (
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/yamllist"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
)

// RepoConfigName is SANDBOX_REPO_CONFIG_NAME.
const RepoConfigName = ".sandbox/config.yaml"

var (
	reTrailComment = regexp.MustCompile(`[[:space:]]+#.*$`)
	reLeadSpace    = regexp.MustCompile(`^[[:space:]]+`)
	reTrailSpace   = regexp.MustCompile(`[[:space:]]+$`)
	// echo "-n", "-e", "-E" and combinations are options to bash's builtin echo, not text.
	echoOption = regexp.MustCompile(`^-[neE]+$`)
)

// Env carries what the bash reads from the process environment.
type Env struct {
	SandboxOverlay string // $SANDBOX_OVERLAY
	UserConfig     string // $USER_SANDBOX_CONFIG (default $HOME/.sandbox/config.yaml)
	Home           string // $HOME
	CacheDir       string // $LEAKSCAN_CACHE_DIR (default $HOME/.sandbox/cache/leakscan)
	TmpDir         string // $TMPDIR (default /tmp)

	ExtraAllowedDomains string // $SANDBOX_EXTRA_ALLOWED_DOMAINS
}

// ExtractYAMLScalar is extract_yaml_scalar_from_file: the value of the first top-level "<key>:"
// line, with an inline " # comment" and all quote characters removed. Empty if absent. key must
// not contain regex metacharacters.
func ExtractYAMLScalar(path, key string) string {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	pre := regexp.MustCompile(`^` + key + `:[[:space:]]*`)
	for _, line := range bashcompat.SplitRecords(data) {
		if !pre.MatchString(line) {
			continue
		}
		line = pre.ReplaceAllString(line, "")
		if loc := reTrailComment.FindStringIndex(line); loc != nil {
			line = line[:loc[0]]
		}
		line = strings.NewReplacer(`"`, "", `'`, "").Replace(line)
		line = reLeadSpace.ReplaceAllString(line, "")
		line = reTrailSpace.ReplaceAllString(line, "")
		return line
	}
	return ""
}

// ResolveOverlayPath is resolve_overlay_path in lib/profile.sh.
func ResolveOverlayPath(e Env) string {
	raw := ""
	if e.SandboxOverlay != "" {
		raw = e.SandboxOverlay
	} else if st, err := os.Stat(e.UserConfig); err == nil && st.Mode().IsRegular() {
		raw = ExtractYAMLScalar(e.UserConfig, "overlay")
	}
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "~") { // ${raw/#\~/${HOME}}
		raw = e.Home + raw[1:]
	}
	return raw
}

// StripIgnoreFileComments is strip_ignore_file_comments: trim each line, drop comments and blanks.
func StripIgnoreFileComments(data []byte) []string {
	var out []string
	for _, l := range bashcompat.SplitRecords(data) {
		l = strings.Trim(l, " \t\n\v\f\r")
		if l == "" || l[0] == '#' {
			continue
		}
		out = append(out, l)
	}
	return out
}

func IsFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// FromOS reads the same variables, with the same defaults, as the bash.
func FromOS() Env {
	e := Env{
		SandboxOverlay: os.Getenv("SANDBOX_OVERLAY"),
		UserConfig:     os.Getenv("USER_SANDBOX_CONFIG"),
		Home:           os.Getenv("HOME"),
		CacheDir:       os.Getenv("LEAKSCAN_CACHE_DIR"),
		TmpDir:         os.Getenv("TMPDIR"),

		ExtraAllowedDomains: os.Getenv("SANDBOX_EXTRA_ALLOWED_DOMAINS"),
	}
	if e.UserConfig == "" {
		e.UserConfig = e.Home + "/.sandbox/config.yaml"
	}
	if e.CacheDir == "" {
		e.CacheDir = e.Home + "/.sandbox/cache/leakscan"
	}
	if e.TmpDir == "" {
		e.TmpDir = "/tmp"
	}
	return e
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\v' || b == '\f' || b == '\r'
}

// ExtractYAMLList is extract_yaml_list_from_file in lib/config.sh: the items of a top-level
// "<key>:" block list in a flat YAML file, one per element. key must not contain regex
// metacharacters (the awk interpolates it into a regex; every caller passes a fixed word).
//
// In legacy mode (see package deviation) a list line, or an item left after the leading "- " is
// removed, that is exactly -n, -e or -E (or a combination) is swallowed, because the bash passes
// it to the echo builtin, which reads it as an option; with the EchoOptionItems fix such an entry
// is kept.
func ExtractYAMLList(path, key string) []string {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return yamllist.Extract(data, key, !deviation.Fixed(deviation.EchoOptionItems))
}

// listItem is what extract_yaml_list_from_file prints for one list line ("  - x"), and false
// when it prints nothing.
func listItem(line string) (string, bool) {
	return yamllist.Item(line, !deviation.Fixed(deviation.EchoOptionItems))
}

// UpsertYAMLScalar is upsert_yaml_scalar_in_file: replace the first "<key>:" line or append one;
// the file is rewritten with mode 0600.
func UpsertYAMLScalar(path, key, value string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		data = nil
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			return err
		}
	}
	var out []byte
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `:`)
	if re.Match(data) {
		done := false
		for _, line := range splitLines(data) {
			if !done && strings.HasPrefix(line, key+":") {
				out = append(out, []byte(key+": "+value+"\n")...)
				done = true
				continue
			}
			out = append(out, []byte(line+"\n")...)
		}
	} else {
		out = append(append(out, data...), []byte(key+": "+value+"\n")...)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func splitLines(data []byte) []string {
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

func Exists(p string) bool { _, err := os.Stat(p); return err == nil }
