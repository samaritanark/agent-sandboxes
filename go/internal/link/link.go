// Package link is lib/link.sh: git-backed team overlays. A link clones an overlay repo into a
// managed directory, pins it to a ref, validates the tree's shape on every change, and records
// the pointer and provenance in the user config. This file is the part without git (names, the
// recorded state, path normalization, and the shape gate); sync.go is the run-path sync.
package link

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

var nameChars = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// IsValidName is link_is_valid_name.
func IsValidName(name string) bool {
	return name != "" && !strings.Contains(name, "/") && !strings.Contains(name, "..") &&
		!strings.HasPrefix(name, ".") && nameChars.MatchString(name)
}

// NameFromURL is link_name_from_url: the repo basename of a git URL, or "" if it is not a valid
// name.
func NameFromURL(url string) string {
	b := strings.TrimSuffix(url, "/")
	if i := strings.LastIndex(b, "/"); i >= 0 {
		b = b[i+1:]
	}
	if i := strings.LastIndex(b, ":"); i >= 0 {
		b = b[i+1:]
	}
	b = strings.TrimSuffix(b, ".git")
	if IsValidName(b) {
		return b
	}
	return ""
}

// Ctx is what a link reads: the environment and where managed clones live ($LINK_OVERLAYS_DIR).
type Ctx struct {
	config.Env
	OverlaysDir string
}

// ManagedDir is link_managed_dir.
func (c Ctx) ManagedDir(name string) string { return c.OverlaysDir + "/" + name }

// URL, Ref and Commit are link_url_config, link_ref_config and link_commit_config.
func (c Ctx) URL() string    { return config.ExtractYAMLScalar(c.UserConfig, "link_url") }
func (c Ctx) Ref() string    { return config.ExtractYAMLScalar(c.UserConfig, "link_ref") }
func (c Ctx) Commit() string { return config.ExtractYAMLScalar(c.UserConfig, "link_commit") }

// IsActive is link_is_active.
func (c Ctx) IsActive() bool { return c.URL() != "" }

// ActiveDir is link_active_dir: the tilde-expanded overlay pointer, if a link is active and the
// pointer is a git working tree with a .git directory.
func (c Ctx) ActiveDir() string {
	if !c.IsActive() {
		return ""
	}
	d := config.ExtractYAMLScalar(c.UserConfig, "overlay")
	if d == "" {
		return ""
	}
	if strings.HasPrefix(d, "~") {
		d = c.Home + d[1:]
	}
	if st, err := os.Stat(d + "/.git"); err == nil && st.IsDir() {
		return d
	}
	return ""
}

// NormalizePath is _link_normalize_path: a leading ~ expanded, runs of '/' collapsed, "."
// components and a trailing '/' dropped; ".." is kept.
func NormalizePath(home, p string) string {
	if strings.HasPrefix(p, "~") {
		p = home + p[1:]
	}
	abs := strings.HasPrefix(p, "/")
	var out string
	for _, comp := range strings.Split(p, "/") {
		if comp != "" && comp != "." {
			out += "/" + comp
		}
	}
	if abs {
		if out == "" {
			return "/"
		}
		return out
	}
	if out = strings.TrimPrefix(out, "/"); out == "" {
		return "."
	}
	return out
}

// DefaultRepoIsSensitive is _link_default_repo_is_sensitive: a profile default_repo that would
// mount the home directory, the filesystem root, a hidden path, or host system state.
//
// With DefaultRepoSensitiveTightened it also refuses an ancestor of the home directory (/home
// holds every user's ~/.ssh), compares against the normalized home (a HOME with a trailing slash
// no longer slips past), adds /run, /var/run, /dev and macOS's /private (where /etc and /var
// really live), and compares case-insensitively (macOS volumes ignore case, so /ETC is /etc).
func DefaultRepoIsSensitive(home, value string) bool {
	v := NormalizePath(home, value)
	tight := deviation.Fixed(deviation.DefaultRepoSensitiveTightened)
	h := home
	if tight {
		h = NormalizePath("", home)
		v, h = strings.ToLower(v), strings.ToLower(h)
	}
	if v == "/" || v == h {
		return true
	}
	if tight && strings.HasPrefix(h, v+"/") {
		return true
	}
	if strings.HasPrefix(v, ".") && len(v) > 1 || hiddenComp(v) { // .?*|*/.?*
		return true
	}
	dirs := []string{"/etc", "/root", "/proc", "/sys", "/boot"}
	if tight {
		dirs = append(dirs, "/run", "/var/run", "/dev", "/private")
	}
	for _, d := range dirs {
		if v == d || strings.HasPrefix(v, d+"/") {
			return true
		}
	}
	return false
}

// hiddenComp is `*/.?*`: a '/' followed by a '.' and at least one more character.
func hiddenComp(v string) bool {
	for i := 0; i+2 < len(v); i++ {
		if v[i] == '/' && v[i+1] == '.' {
			return true
		}
	}
	return false
}

// Validation is what link_validate_shape reports: OK, and its stderr lines in order.
type Validation struct {
	OK     bool
	Stderr []string
}

func (r *Validation) warn(s string) { r.Stderr = append(r.Stderr, "WARN: "+s) }
func (r *Validation) line(s string) { r.Stderr = append(r.Stderr, s) }

var allDigits = regexp.MustCompile(`^[0-9]+$`)

// symlinkProblems is the bash's symlink scan: every symlink under dir whose target is absolute
// or contains "..". In legacy mode the names come from `find | sed` read line by line, so a name
// with a newline is split and its fragments looked up instead (an escaping symlink so named is
// missed); with StrictSymlinkScan each symlink is checked by its real name.
func symlinkProblems(dir string) []string {
	var links []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type()&fs.ModeSymlink != 0 {
			rel, _ := filepath.Rel(dir, p)
			links = append(links, rel)
		}
		return nil
	})
	var out []string
	check := func(rel string) {
		t, err := os.Readlink(filepath.Join(dir, rel))
		if err == nil && (strings.HasPrefix(t, "/") || strings.Contains(t, "..")) {
			out = append(out, "symlink escapes overlay: "+rel)
		}
	}
	for _, rel := range links {
		if deviation.Fixed(deviation.StrictSymlinkScan) {
			check(rel)
			continue
		}
		for _, frag := range strings.Split(rel, "\n") {
			if frag != "" {
				check(frag)
			}
		}
	}
	return out
}

// globYAML is "${dir}"/*.yaml: names not starting with '.', sorted, existing (a dangling symlink
// is skipped by the `[[ -e ]]` test).
func globYAML(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".yaml") {
			continue
		}
		if config.Exists(filepath.Join(dir, n)) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func isDir(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

var knownTop = map[string]bool{
	"profiles": true, "catalogue": true, "extra-ca-certs": true, "blocked-destinations.yaml": true,
	"config.yaml": true, "README.md": true, "GOVERNANCE.md": true, "README": true, "LICENSE": true,
	"NOTICE": true, "docs": true, "allowed_signers": true, "signers.txt": true,
	"gen-allowed-signers.sh": true, ".betterleaksignore": true, ".gitleaksignore": true,
}

// ValidateShape is link_validate_shape: the safety gate run on clone and on every sync.
func (c Ctx) ValidateShape(dir string) Validation {
	var r Validation
	problems := symlinkProblems(dir)
	var extra []string
	nProfiles, nCatalogue := 0, 0
	if isDir(dir + "/profiles") {
		for _, f := range globYAML(dir + "/profiles") {
			nProfiles++
			name := strings.TrimSuffix(f, ".yaml")
			if !IsValidName(name) {
				problems = append(problems, "invalid profile name: profiles/"+name+".yaml")
				continue
			}
			p := dir + "/profiles/" + f
			switch t := config.ExtractYAMLScalar(p, "tier"); t {
			case "1", "2", "3":
			default:
				if t == "" {
					t = "<none>"
				}
				problems = append(problems, fmt.Sprintf("profile '%s' has invalid/missing tier: '%s'", name, t))
			}
			if repo := config.ExtractYAMLScalar(p, "default_repo"); repo != "" && DefaultRepoIsSensitive(c.Home, repo) {
				problems = append(problems, fmt.Sprintf("profile '%s' default_repo points at a sensitive path: '%s'", name, repo))
			}
			for _, d := range config.LoadExtraAllowedDomains(p) {
				if d != "" {
					extra = append(extra, name+": "+d)
				}
			}
		}
	}
	if isDir(dir + "/catalogue") {
		for _, f := range globYAML(dir + "/catalogue") {
			nCatalogue++
			if name := strings.TrimSuffix(f, ".yaml"); !IsValidName(name) {
				problems = append(problems, "invalid catalogue name: catalogue/"+name+".yaml")
			}
		}
	}
	cfg := dir + "/config.yaml"
	hasCfg := config.IsFile(cfg)
	scalar := func(k string) string {
		if !hasCfg {
			return ""
		}
		return config.ExtractYAMLScalar(cfg, k)
	}
	vetting := scalar("vetting")
	switch vetting {
	case "off", "advisory", "required", "":
	default:
		r.warn(fmt.Sprintf("overlay config.yaml sets an unrecognized vetting posture '%s' — it will be treated as 'advisory' at run time.", vetting))
	}
	if ents, err := os.ReadDir(dir); err == nil {
		var names []string
		for _, e := range ents {
			if n := e.Name(); !strings.HasPrefix(n, ".") && config.Exists(filepath.Join(dir, n)) {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			if !knownTop[n] {
				r.warn(fmt.Sprintf("overlay ships an unrecognized top-level entry: %s (ignored by the CLI)", n))
			}
		}
	}
	if len(problems) > 0 {
		r.warn("overlay failed validation:")
		for _, p := range problems {
			r.line("         - " + p)
		}
		return r
	}
	if len(extra) > 0 {
		r.warn(fmt.Sprintf("overlay profiles request %d extra allowed egress domain(s) — review before use:", len(extra)))
		for _, d := range extra {
			r.line("         - " + d)
		}
	}
	var notes strings.Builder
	if troot := scalar("vetting_trust_root"); troot != "" {
		tp := troot
		if strings.HasPrefix(tp, "~") {
			tp = c.Home + tp[1:]
		}
		if !strings.HasPrefix(tp, "/") {
			tp = dir + "/" + tp
		}
		if config.IsFile(tp) {
			fmt.Fprintf(&notes, ", trust root: %s (%s signer(s))", troot, signerCount(tp))
		} else {
			fmt.Fprintf(&notes, ", trust root: %s (MISSING)", troot)
			r.warn(fmt.Sprintf("overlay config.yaml names vetting_trust_root: %s, but no such file ships in the overlay.", troot))
		}
	}
	if m := config.OverlayMinSandboxVersion(dir); m != "" {
		fmt.Fprintf(&notes, ", min CLI: %s", m)
	}
	if v := scalar("vetting_max_commits_behind"); allDigits.MatchString(v) {
		fmt.Fprintf(&notes, ", max commits behind HEAD: %s", v)
	} else if v != "" {
		r.warn(fmt.Sprintf("overlay config.yaml sets a non-integer vetting_max_commits_behind: '%s' — it will be ignored (no cap) at run time.", v))
	}
	if v := scalar("vetting_max_age_days"); allDigits.MatchString(v) {
		fmt.Fprintf(&notes, ", max attestation age: %s day(s)", v)
	} else if v != "" {
		r.warn(fmt.Sprintf("overlay config.yaml sets a non-integer vetting_max_age_days: '%s' — it will be ignored (no expiry) at run time.", v))
	}
	if v := scalar("vetting_exceptions_require_head"); v == "true" {
		notes.WriteString(", exceptions require attestation at HEAD")
	} else if v != "" && v != "false" {
		r.warn(fmt.Sprintf("overlay config.yaml sets vetting_exceptions_require_head: '%s' — only 'true' tightens; any other value leaves the permissive default.", v))
	}
	if v := scalar("vetting_exceptions_from_commit"); v == "true" {
		notes.WriteString(", exceptions read from attested commit")
	} else if v != "" && v != "false" {
		r.warn(fmt.Sprintf("overlay config.yaml sets vetting_exceptions_from_commit: '%s' — only 'true' tightens; any other value leaves the working-copy default.", v))
	}
	entries := "ies"
	if nCatalogue == 1 {
		entries = "y"
	}
	summary := fmt.Sprintf("  overlay contents: %d profile(s), %d catalogue entr%s", nProfiles, nCatalogue, entries)
	if config.IsFile(dir + "/blocked-destinations.yaml") {
		summary += ", blocked-destinations.yaml"
	}
	if vetting != "" {
		summary += ", vetting: " + vetting
	}
	r.line(summary + notes.String())
	r.OK = true
	return r
}

// signerCount is `grep -Ecv '^[[:space:]]*($|#)' file || echo 0`: the lines that are neither
// blank nor comments. With none, grep prints 0 and fails, so the bash prints "0", a newline, and
// "0" again; with ZeroSignerCount it prints one 0.
func signerCount(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "0"
	}
	n := 0
	for _, l := range bashcompat.SplitRecords(b) {
		t := strings.TrimLeft(l, " \t\n\v\f\r")
		if t != "" && t[0] != '#' {
			n++
		}
	}
	if n == 0 && !deviation.Fixed(deviation.ZeroSignerCount) {
		return "0\n0"
	}
	return fmt.Sprint(n)
}

// WriteConfig is link_write_config: the overlay pointer and provenance, in that order.
func (c Ctx) WriteConfig(dir, url, ref, commit string) error {
	for _, kv := range [][2]string{{"overlay", dir}, {"link_url", url}, {"link_ref", ref}, {"link_commit", commit}} {
		if err := config.UpsertYAMLScalar(c.UserConfig, kv[0], kv[1]); err != nil {
			return err
		}
	}
	return nil
}

// ClearConfig is link_clear_config: the provenance always, the overlay pointer only while it
// still points at the managed clone.
func (c Ctx) ClearConfig(managedDir string) error {
	cur := config.ExtractYAMLScalar(c.UserConfig, "overlay")
	if strings.HasPrefix(cur, "~") {
		cur = c.Home + cur[1:]
	}
	keys := []string{"link_url", "link_ref", "link_commit"}
	if cur == managedDir {
		keys = append([]string{"overlay"}, keys...)
	}
	for _, k := range keys {
		if err := config.RemoveYAMLScalar(c.UserConfig, k); err != nil {
			return err
		}
	}
	return nil
}
