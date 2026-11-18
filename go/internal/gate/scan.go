package gate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Port of scan_repo_secrets and the helpers it owns in lib/filesystem.sh, lib/config.sh and
// lib/profile.sh (resolve_overlay_path). The scanner (betterleaks) stays an external process,
// exactly as in the bash: the port runs the same command line and reads the same JSON report.

// Rule tables (LEAKSCAN_* in lib/filesystem.sh).
var (
	leakscanDepDirs = []string{
		"node_modules", "bower_components", ".pnp", ".yarn",
		"vendor", ".go",
		".venv", "venv", "virtualenv", ".virtualenvs", "site-packages", "*.egg-info", ".eggs", ".tox", ".nox",
		"__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
		".gradle", ".ansible",
	}
	leakscanSkipPaths = []string{".secrets.baseline"}
)

const (
	repoIgnoreName     = ".betterleaksignore"
	repoIgnoreFallback = ".gitleaksignore"
)

// ScanEnv carries what the bash reads from the process environment.
type ScanEnv struct {
	SandboxOverlay string // $SANDBOX_OVERLAY
	UserConfig     string // $USER_SANDBOX_CONFIG (default $HOME/.sandbox/config.yaml)
	Home           string // $HOME
	CacheDir       string // $LEAKSCAN_CACHE_DIR (default $HOME/.sandbox/cache/leakscan)
	TmpDir         string // $TMPDIR (default /tmp)
}

// ScanEnvFromOS reads the same variables, with the same defaults, as the bash.
func ScanEnvFromOS() ScanEnv {
	e := ScanEnv{
		SandboxOverlay: os.Getenv("SANDBOX_OVERLAY"),
		UserConfig:     os.Getenv("USER_SANDBOX_CONFIG"),
		Home:           os.Getenv("HOME"),
		CacheDir:       os.Getenv("LEAKSCAN_CACHE_DIR"),
		TmpDir:         os.Getenv("TMPDIR"),
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

var (
	reTrailComment = regexp.MustCompile(`[[:space:]]+#.*$`)
	reLeadSpace    = regexp.MustCompile(`^[[:space:]]+`)
	reTrailSpace   = regexp.MustCompile(`[[:space:]]+$`)
)

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
	for _, line := range splitRecords(data) {
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
func ResolveOverlayPath(e ScanEnv) string {
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
	for _, l := range splitRecords(data) {
		l = strings.Trim(l, " \t\n\v\f\r")
		if l == "" || l[0] == '#' {
			continue
		}
		out = append(out, l)
	}
	return out
}

// LeakscanRegexEscape is _leakscan_regex_escape.
func LeakscanRegexEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(`][\.^$*+?(){}|`, s[i]) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// bashGlob reports whether name matches a bash [[ == pattern ]] glob (*, ?, [set], backslash
// escape; no extglob, no [:class:]; bytes).
func bashGlob(pat, name string) bool {
	for len(pat) > 0 {
		switch pat[0] {
		case '*':
			for len(pat) > 0 && pat[0] == '*' {
				pat = pat[1:]
			}
			if pat == "" {
				return true
			}
			for i := 0; i <= len(name); i++ {
				if bashGlob(pat, name[i:]) {
					return true
				}
			}
			return false
		case '?':
			if name == "" {
				return false
			}
			pat, name = pat[1:], name[1:]
		case '[':
			if name == "" {
				return false
			}
			end, ok, matched := bracket(pat, name[0])
			if !ok { // no closing ]: '[' is literal
				if name[0] != '[' {
					return false
				}
				pat, name = pat[1:], name[1:]
				continue
			}
			if !matched {
				return false
			}
			pat, name = pat[end:], name[1:]
		case '\\':
			if len(pat) < 2 {
				return name == "\\" && len(pat) == 1 && len(name) == 1
			}
			if name == "" || name[0] != pat[1] {
				return false
			}
			pat, name = pat[2:], name[1:]
		default:
			if name == "" || name[0] != pat[0] {
				return false
			}
			pat, name = pat[1:], name[1:]
		}
	}
	return name == ""
}

// bracket parses a [...] expression at the start of pat and tests c. end is the index after the
// closing ']'; ok is false when there is no closing bracket.
func bracket(pat string, c byte) (end int, ok, matched bool) {
	i := 1
	neg := false
	if i < len(pat) && (pat[i] == '!' || pat[i] == '^') {
		neg = true
		i++
	}
	first := true
	for i < len(pat) {
		if pat[i] == ']' && !first {
			return i + 1, true, matched != neg
		}
		first = false
		lo := pat[i]
		if lo == '\\' && i+1 < len(pat) {
			i++
			lo = pat[i]
		}
		hi := lo
		if i+2 < len(pat) && pat[i+1] == '-' && pat[i+2] != ']' {
			hi = pat[i+2]
			i += 2
		}
		if c >= lo && c <= hi {
			matched = true
		}
		i++
	}
	return 0, false, false
}

func isDepDir(base string, globs []string) bool {
	for _, g := range globs {
		if bashGlob(g, base) {
			return true
		}
	}
	return false
}

func isOffValue(v string) bool {
	switch v {
	case "off", "false", "no", "0", "OFF", "False", "FALSE", "No", "NO":
		return true
	}
	return false
}

func exclusionsEnabled(e ScanEnv, repo string) bool {
	v := ExtractYAMLScalar(repo+"/"+repoConfigName, "leakscan_dep_exclusions")
	if v == "" {
		v = ExtractYAMLScalar(e.UserConfig, "leakscan_dep_exclusions")
	}
	return !isOffValue(v)
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

func inlineAllowEnabled(e ScanEnv) bool {
	ov := ResolveOverlayPath(e)
	if ov == "" || !isFile(ov+"/config.yaml") {
		return true
	}
	return !isOffValue(ExtractYAMLScalar(ov+"/config.yaml", "leakscan_inline_allow"))
}

func leakscanConfigURL(e ScanEnv) string {
	ov := ResolveOverlayPath(e)
	if ov == "" || !isFile(ov+"/config.yaml") {
		return ""
	}
	return ExtractYAMLScalar(ov+"/config.yaml", "leakscan_config_url")
}

func sha256File(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// operatorConfig is _leakscan_operator_config: a betterleaks config the operator supplies, to be
// used verbatim, or "" to generate one.
func operatorConfig(e ScanEnv) string {
	ov := ResolveOverlayPath(e)
	if ov == "" {
		return ""
	}
	if url := leakscanConfigURL(e); url != "" {
		cache := e.CacheDir + "/betterleaks.toml"
		pin := ExtractYAMLScalar(e.UserConfig, "leakscan_config_sha256")
		src := ExtractYAMLScalar(e.UserConfig, "leakscan_config_source")
		if isFile(cache) && pin != "" && src == url {
			if cur := sha256File(cache); cur != "" && cur == pin {
				return cache
			}
		}
		return ""
	}
	for _, f := range []string{"betterleaks.toml", ".betterleaks.toml"} {
		if isFile(ov + "/" + f) {
			return ov + "/" + f
		}
	}
	return ""
}

// ignorePath is _leakscan_ignore_path: an operator baseline in the overlay, or "".
func ignorePath(e ScanEnv) string {
	ov := ResolveOverlayPath(e)
	if ov == "" {
		return ""
	}
	for _, f := range []string{".betterleaksignore", ".gitleaksignore"} {
		if isFile(ov + "/" + f) {
			return ov + "/" + f
		}
	}
	return ""
}

// LeakscanConfig is the content _leakscan_write_config writes for repo.
func LeakscanConfig(e ScanEnv, repo string) string {
	var b strings.Builder
	b.WriteString("# generated by sandbox — betterleaks config for the secret gate\n[extend]\nuseDefault = true\n")
	if !exclusionsEnabled(e, repo) {
		return b.String()
	}
	var paths []string
	for _, sp := range leakscanSkipPaths {
		paths = append(paths, "(^|/)"+LeakscanRegexEscape(sp)+"$")
	}
	dep := append([]string{}, leakscanDepDirs...)
	if ov := ResolveOverlayPath(e); ov != "" && isFile(ov+"/config.yaml") {
		for _, x := range ExtractYAMLList(ov+"/config.yaml", "leakscan_extra_dep_dirs") {
			if x != "" {
				dep = append(dep, x)
			}
		}
	}
	out, _ := exec.Command("git", "-C", repo, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory").Output()
	for _, d := range strings.Split(string(out), "\n") {
		d = strings.TrimSuffix(d, "/")
		if d == "" {
			continue
		}
		base := d
		if i := strings.LastIndex(d, "/"); i >= 0 {
			base = d[i+1:]
		}
		if !isDepDir(base, dep) {
			continue
		}
		paths = append(paths, "(^|/)"+LeakscanRegexEscape(d)+"(/|$)")
	}
	if len(paths) == 0 {
		return b.String()
	}
	b.WriteString("[allowlist]\npaths = [\n")
	for _, p := range paths {
		fmt.Fprintf(&b, "  '''%s''',\n", p)
	}
	b.WriteString("]\n")
	return b.String()
}

// betterleaksRun is _betterleaks_run: reports whether the run can be trusted, and the exit code.
func betterleaksRun(e ScanEnv, target, report, config, ignore, honorInline string) (ok bool, rc int) {
	args := []string{"-n", "19"}
	if p, err := exec.LookPath("ionice"); err == nil && p != "" {
		args = append(args, "ionice", "-c3")
	}
	args = append(args, "betterleaks", "dir", target, "--no-banner", "-f", "json", "-r", report, "--validation=false", "--redact")
	if honorInline == "no" || !inlineAllowEnabled(e) {
		args = append(args, "--ignore-gitleaks-allow")
	}
	if config != "" {
		args = append(args, "-c", config)
	}
	if ignore != "" {
		args = append(args, "-i", ignore)
	}
	if err := exec.Command("nice", args...).Run(); err != nil {
		if ee, isExit := err.(*exec.ExitError); isExit {
			rc = ee.ExitCode()
			if rc < 0 { // killed by a signal: bash reports 128+n
				rc = 128 + 1
			}
		} else {
			rc = 127
		}
	}
	if rc == 0 {
		return true, rc
	}
	if rc == 1 {
		b, _ := os.ReadFile(report)
		if reportIsArray(b) {
			return true, rc
		}
	}
	return false, rc
}

// reportIsArray is `jq -e 'type == "array"'`: every value parses, and the last one is an array.
func reportIsArray(b []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var last any
	n := 0
	for {
		var v any
		err := dec.Decode(&v)
		if err == io.EOF {
			break
		}
		if err != nil {
			return false
		}
		last = v
		n++
	}
	if n == 0 {
		return false
	}
	_, isArr := last.([]any)
	return isArr
}

var tsvEscaper = strings.NewReplacer("\\", "\\\\", "\t", "\\t", "\n", "\\n", "\r", "\\r")

// tsvField renders a JSON value as jq @tsv does; ok is false for values @tsv rejects.
func tsvField(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", true
	case string:
		return tsvEscaper.Replace(x), true
	case json.Number:
		return x.String(), true
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	}
	return "", false
}

// tostringField renders a JSON value as jq tostring (scalars only; nested values are not covered).
func tostringField(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		if x {
			return "true"
		}
		return "false"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// reportRows is the jq filter over a report: one []string of the named fields per finding.
// stringify marks the fields passed through tostring. It mirrors jq: each input value is
// processed independently, an error abandons the rest of that value.
func reportRows(report []byte, fields []string, stringify map[string]bool) [][]string {
	var rows [][]string
	dec := json.NewDecoder(bytes.NewReader(report))
	dec.UseNumber()
	for {
		var v any
		if err := dec.Decode(&v); err != nil {
			break
		}
		var elems []any
		switch x := v.(type) {
		case []any:
			elems = x
		case map[string]any:
			for _, k := range sortedKeys(x) { // jq iterates object values in key order
				elems = append(elems, x[k])
			}
		default:
			continue
		}
	elem:
		for _, el := range elems {
			var obj map[string]any
			switch o := el.(type) {
			case nil:
			case map[string]any:
				obj = o
			default:
				break elem
			}
			row := make([]string, len(fields))
			for i, f := range fields {
				fv := obj[f]
				if stringify[f] {
					fv = tostringField(fv)
				}
				s, ok := tsvField(fv)
				if !ok {
					break elem
				}
				row[i] = s
			}
			rows = append(rows, row)
		}
	}
	return rows
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	for i := 1; i < len(ks); i++ {
		for j := i; j > 0 && ks[j] < ks[j-1]; j-- {
			ks[j], ks[j-1] = ks[j-1], ks[j]
		}
	}
	return ks
}

// readTab emulates `IFS=$'\t' read -r a b c ...` with n variables: tab is IFS whitespace, so
// leading tabs are dropped and runs of tabs separate fields; the last variable takes the rest.
func readTab(line string, n int) []string {
	out := make([]string, n)
	s := strings.TrimLeft(line, "\t")
	for i := 0; i < n-1; i++ {
		if s == "" {
			return out
		}
		j := strings.IndexByte(s, '\t')
		if j < 0 {
			out[i] = s
			return out
		}
		out[i] = s[:j]
		s = strings.TrimLeft(s[j:], "\t")
	}
	out[n-1] = strings.TrimRight(s, "\t")
	return out
}

// ScanRepoSecrets is scan_repo_secrets. It returns the lines the bash prints to stdout
// (without newlines). warn receives the one warning the bash prints on stderr.
func ScanRepoSecrets(e ScanEnv, repo, acceptFile string, warn io.Writer) []string {
	realRepo, err := filepath.EvalSymlinks(repo)
	if err == nil {
		realRepo, err = filepath.Abs(realRepo)
	}
	if err != nil {
		return nil
	}

	// A root ignore file with a non-relative fingerprint would blind the scanner: fail closed.
	for _, ignf := range []string{repoIgnoreName, repoIgnoreFallback} {
		p := realRepo + "/" + ignf
		if !isFile(p) {
			continue
		}
		data, _ := os.ReadFile(p)
		for _, entry := range StripIgnoreFileComments(data) {
			if strings.HasPrefix(entry, "/") || strings.HasPrefix(entry, "../") || strings.Contains(entry, "/../") {
				return []string{fmt.Sprintf("error\t%s carries a non-relative fingerprint (%s) that could silently suppress scan findings; remove it — entries must be repo-relative (relpath:rule:line)", ignf, entry)}
			}
		}
	}

	report, _ := os.CreateTemp(e.TmpDir, "sandbox-leakscan-")
	reportPath := report.Name()
	report.Close()
	defer os.Remove(reportPath)

	config := operatorConfig(e)
	if config == "" {
		f, _ := os.CreateTemp(e.TmpDir, "sandbox-leakcfg-")
		config = f.Name()
		f.WriteString(LeakscanConfig(e, repo))
		f.Close()
		defer os.Remove(config)
		if leakscanConfigURL(e) != "" && warn != nil {
			fmt.Fprintln(warn, "leakscan_config_url is set but no validated cached secret-gate config is available; scanning with the generated fallback. Launch once while online (or run 'sandbox link sync') to fetch it.")
		}
	}

	ignore := ignorePath(e)
	if ignore == "" {
		d, _ := os.MkdirTemp(e.TmpDir, "sandbox-leakignore-")
		ignore = d
		defer os.Remove(d)
	}

	var out []string
	ok, rc := betterleaksRun(e, realRepo, reportPath, config, ignore, "")
	if !ok {
		return append(out, fmt.Sprintf("error\tbetterleaks scan failed (exit %d)", rc))
	}
	data, _ := os.ReadFile(reportPath)
	for _, r := range reportRows(data, []string{"File", "RuleID", "StartLine", "StartColumn", "EndColumn", "Match"},
		map[string]bool{"StartLine": true, "StartColumn": true, "EndColumn": true}) {
		f := readTab(strings.Join(r, "\t"), 6)
		file, ruleid, line, startcol, endcol, match := f[0], f[1], f[2], f[3], f[4], f[5]
		if file == "" {
			continue
		}
		relpath := strings.TrimPrefix(file, realRepo+"/")
		if strings.HasPrefix(relpath, ".git/") {
			continue
		}
		class := "no"
		switch {
		case FindingIsEncrypted(file, line, startcol, endcol):
			class = "sealed"
		case IsPathMasked(repo, relpath):
			class = "yes"
		case LeakscanFindingAccepted(acceptFile, realRepo, relpath, ruleid, line):
			class = "accepted"
		}
		out = append(out, strings.Join([]string{class, relpath, ruleid, line, match}, "\t"))
	}

	// .git/config: readable in the pod and unmaskable; inline allow comments never honored.
	gitcfg := realRepo + "/.git/config"
	if isFile(gitcfg) {
		os.Truncate(reportPath, 0)
		ok, rc := betterleaksRun(e, gitcfg, reportPath, config, ignore, "no")
		if !ok {
			return append(out, fmt.Sprintf("error\tbetterleaks scan of .git/config failed (exit %d)", rc))
		}
		data, _ := os.ReadFile(reportPath)
		for _, r := range reportRows(data, []string{"File", "RuleID", "StartLine", "Match"}, map[string]bool{"StartLine": true}) {
			f := readTab(strings.Join(r, "\t"), 4)
			if f[0] == "" {
				continue
			}
			out = append(out, strings.Join([]string{"gitconfig", ".git/config", f[1], f[2], f[3]}, "\t"))
		}
	}
	return out
}
