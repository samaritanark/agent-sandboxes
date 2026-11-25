// Package syncgate is the host-side gate for VM-origin workspace changes (design 5.6.2, D-24):
// the VM may be controlled by an attacker, so every change it reports is checked here, on the
// host, before anything reaches the operator's checkout. This file classifies paths.
package syncgate

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/samaritanark/agent-sandboxes/go/internal/tables"
)

// Class is what the gate does with a VM-origin change to a path.
type Class int

const (
	Apply      Class = iota // an ordinary file: applied (after the type and link checks)
	Local                   // lock files and in-progress operation state: each side keeps its own (5.6.4 item 1)
	Quarantine              // masked, host-exec, never-VM-to-host, or unknown git state: held for `sandbox sync review`
	Ref                     // refs/heads/*: applied by the ref rules (rule 6)
	PackedRefs              // packed-refs: parsed into ref updates, never copied (rule 6)
	Head                    // HEAD: the HEAD rule (rule 6)
	Index                   // the index: merged by entry (rule 7)
	Object                  // a loose object or pack: hash-verified first (rule 6)
	Attributes              // .gitattributes: checked for driver changes (rule 8)
)

var classNames = map[Class]string{Apply: "apply", Local: "local", Quarantine: "quarantine", Ref: "ref",
	PackedRefs: "packed-refs", Head: "HEAD", Index: "index", Object: "object", Attributes: "attributes"}

func (c Class) String() string { return classNames[c] }

// Host describes the host file system's name matching, which decides what aliases what.
type Host struct {
	CaseInsensitive bool // APFS and NTFS defaults
	NormInsensitive bool // APFS
	Windows         bool // NTFS rules: trailing dots and spaces, 8.3 short names, streams
}

// Repo is the per-repo input the gate needs beyond the built-in tables.
type Repo struct {
	MaskedPaths []string // the repo's masked_paths: entries (a trailing / is a directory)
	HooksPath   string   // the host repo's effective core.hooksPath, relative to the repo, if inside it
}

// Limits on a VM-origin path.
const (
	MaxPathBytes      = 4096
	MaxComponentBytes = 255
)

// CleanPath validates a VM-origin path: relative, slash-separated, UTF-8, no empty, ".", or ".."
// component, no NUL or other control character, and within the length limits. It returns the
// components. On a Windows host, names NTFS cannot hold or would alias are refused too.
func CleanPath(p string, h Host) ([]string, error) {
	if p == "" || len(p) > MaxPathBytes || !utf8.ValidString(p) {
		return nil, errors.New("invalid path")
	}
	if strings.HasPrefix(p, "/") || strings.ContainsRune(p, '\\') {
		return nil, fmt.Errorf("%q is not a relative slash-separated path", p)
	}
	parts := strings.Split(p, "/")
	for _, c := range parts {
		if c == "" || c == "." || c == ".." || len(c) > MaxComponentBytes {
			return nil, fmt.Errorf("%q has an empty, dot, or oversized component", p)
		}
		for _, r := range c {
			if r < 0x20 || r == 0x7f {
				return nil, fmt.Errorf("%q holds a control character", p)
			}
		}
		if h.Windows {
			if strings.ContainsAny(c, `<>:"|?*`) || strings.HasSuffix(c, ".") || strings.HasSuffix(c, " ") {
				return nil, fmt.Errorf("%q cannot be written safely on NTFS", p)
			}
		}
	}
	return parts, nil
}

// asciiSingletons are the characters whose canonical decomposition is a single ASCII character:
// on a normalization-insensitive file system they alias it (KELVIN SIGN is K, so ".git/hooKs"
// spelled with it is ".git/hooks").
var asciiSingletons = map[rune]rune{0x212A: 'K', 0x037E: ';', 0x1FEF: '`'}

// foldRune is the smallest rune in r's simple case-folding orbit.
func foldRune(r rune) rune {
	m := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < m {
			m = f
		}
	}
	return m
}

// key is the comparison key of one component on this host, used only to decide that a path is
// protected (masked, an exec vector, git state), so it may over-match but must never under-match.
//
// On a case-insensitive host each rune is case-folded: full folding first (sharp s to ss, the fi
// ligature to fi; APFS folds this way, which TestKeyCoversHostAliases found), then simple folding
// (which also takes KELVIN SIGN to k and LONG S to s). On a normalization-insensitive host (APFS) the precomposed and
// decomposed spellings of a name must get the same key, and the standard library has no
// decomposition tables, so the key is coarser: every non-ASCII character is dropped, and so is
// a base character followed by combining marks, with the marks. "café" and "cafe" + U+0301 both
// become "caf". The characters whose canonical decomposition is a single ASCII character
// (KELVIN SIGN, GREEK QUESTION MARK, GREEK VARIA) are mapped first. Over-matching sends a change
// to quarantine, never through. On NTFS, trailing dots and spaces are ignored, as NTFS ignores
// them.
func (h Host) key(c string) string {
	if h.Windows {
		c = strings.TrimRight(c, ". ")
	}
	if !h.CaseInsensitive && !h.NormInsensitive {
		return c
	}
	var in []rune
	for _, r := range c {
		if f, ok := fullFold[r]; ok && h.CaseInsensitive {
			in = append(in, []rune(f)...)
			continue
		}
		in = append(in, r)
	}
	var out []rune
	for _, r := range in {
		if h.NormInsensitive {
			if a, ok := asciiSingletons[r]; ok {
				r = a
			}
		}
		if h.CaseInsensitive {
			r = foldRune(r)
		}
		if h.NormInsensitive {
			if unicode.In(r, unicode.Mn, unicode.Me) {
				if n := len(out); n > 0 && out[n-1] != '/' {
					out = out[:n-1] // the base character the mark composes with
				}
				continue
			}
			if r > 0x7e {
				continue
			}
		}
		out = append(out, r)
	}
	return string(out)
}

// shortName matches an NTFS 8.3 short name such as GIT~1, which can alias any long name.
func shortName(c string) bool {
	base, _, _ := strings.Cut(c, ".")
	i := strings.LastIndexByte(base, '~')
	if i < 1 || i == len(base)-1 || len(base) > 8 {
		return false
	}
	for _, r := range base[i+1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Local state under .git that each side keeps (5.6.4 item 1).
var gitLocal = map[string]bool{"MERGE_HEAD": true, "MERGE_MSG": true, "MERGE_MODE": true, "MERGE_AUTOSTASH": true,
	"CHERRY_PICK_HEAD": true, "REVERT_HEAD": true, "BISECT_LOG": true, "AUTO_MERGE": true,
	"rebase-merge": true, "rebase-apply": true, "sequencer": true}

// Never VM to host (rule 6), beyond the exec vectors: quarantined.
var gitNeverIn = map[string]bool{"FETCH_HEAD": true, "ORIG_HEAD": true, "logs": true, "shallow": true}

// Exec vectors at any depth of the work tree (rule 2): a component with one of these names makes
// the path a vector (directories) or the name itself is one (files).
var execDirs = []string{".vscode", ".idea", ".devcontainer", ".husky", ".githooks", ".mise"}
var execFiles = []string{".gitmodules", ".pre-commit-config.yaml", "lefthook.yml", "lefthook.yaml",
	"lefthook-local.yml", "lefthook-local.yaml", ".lfsconfig", ".envrc", ".tool-versions", "mise.toml",
	".mise.toml", "mise.local.toml", ".mise.local.toml"}

// Classify decides what happens to a VM-origin change at path p in the work tree.
func Classify(p string, h Host, r Repo) (Class, error) {
	parts, err := CleanPath(p, h)
	if err != nil {
		return Quarantine, err
	}
	keys := make([]string, len(parts))
	for i, c := range parts {
		if h.Windows && (shortName(c) || strings.Contains(c, ":")) {
			return Quarantine, nil // could alias anything, .git included
		}
		keys[i] = h.key(c)
	}
	eq := func(i int, name string) bool { return keys[i] == h.key(name) }

	// The repository's own git directory.
	if eq(0, ".git") {
		return classifyGit(parts[1:], keys[1:], h), nil
	}
	// A .git anywhere deeper is a nested repository's (or a submodule's): its config and hooks
	// would run on the host, and none of it is ours to merge.
	for i := 1; i < len(parts); i++ {
		if eq(i, ".git") {
			return Quarantine, nil
		}
	}
	// Rule 1: masked paths, built-in (repo root) and configured.
	if masked(parts, keys, h, r.MaskedPaths) {
		return Quarantine, nil
	}
	// Rule 2: exec vectors.
	for i := range parts {
		for _, d := range execDirs {
			if eq(i, d) {
				return Quarantine, nil
			}
		}
		if eq(i, ".claude") && i+1 < len(parts) {
			next := keys[i+1]
			if next == h.key("hooks") || strings.HasPrefix(next, h.key("settings")) && strings.HasSuffix(next, h.key(".json")) {
				return Quarantine, nil
			}
		}
	}
	last := len(parts) - 1
	for _, f := range execFiles {
		if eq(last, f) {
			return Quarantine, nil
		}
	}
	if strings.HasPrefix(keys[last], h.key(".lefthook")) {
		return Quarantine, nil
	}
	if r.HooksPath != "" {
		hp := strings.Split(strings.Trim(r.HooksPath, "/"), "/")
		if len(hp) <= len(parts) {
			match := true
			for i, c := range hp {
				if keys[i] != h.key(c) {
					match = false
					break
				}
			}
			if match {
				return Quarantine, nil
			}
		}
	}
	if eq(last, ".gitattributes") {
		return Attributes, nil
	}
	return Apply, nil
}

func masked(parts, keys []string, h Host, configured []string) bool {
	if len(parts) == 1 {
		for _, m := range tables.MaskedFilePaths {
			if keys[0] == h.key(m) {
				return true
			}
		}
		if strings.HasSuffix(keys[0], h.key(tables.MaskedOpenrcSuffix)) {
			return true
		}
	}
	if keys[0] == h.key(tables.MaskedDirPath) {
		return true
	}
	for _, m := range configured {
		// A mask covers its path and everything below it: a directory mask by definition, and a
		// file mask too, since a VM-side directory at that path would put files there.
		mp := strings.Split(strings.Trim(m, "/"), "/")
		if m == "" || len(mp) > len(parts) {
			continue
		}
		match := true
		for i, c := range mp {
			if keys[i] != h.key(c) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// classifyGit classifies a path under the repository's .git directory (parts excludes ".git").
func classifyGit(parts, keys []string, h Host) Class {
	if len(parts) == 0 {
		return Quarantine // .git itself as a file or link
	}
	k := keys[0]
	is := func(name string) bool { return k == h.key(name) }
	last := parts[len(parts)-1]
	if strings.HasSuffix(h.key(last), h.key(".lock")) {
		return Local
	}
	for name := range gitLocal {
		if is(name) {
			return Local
		}
	}
	switch {
	case len(parts) == 1 && is("HEAD"):
		return Head
	case len(parts) == 1 && is("index"):
		return Index
	case len(parts) == 1 && is("packed-refs"):
		return PackedRefs
	case is("refs") && len(parts) >= 3 && keys[1] == h.key("heads"):
		// The ref rules compare the name by this host's key too: on APFS refs/heads/MAIN is the
		// file refs/heads/main, so protection must not hang on the spelling.
		if !h.CaseInsensitive && !h.NormInsensitive || exactASCII(parts) {
			return Ref
		}
		return Quarantine // a branch name that only aliases on this host
	case is("objects"):
		if len(parts) >= 2 && keys[1] == h.key("info") {
			return Quarantine // alternates (rule 2)
		}
		if len(parts) == 3 && isHex(parts[1], 2) && isHex(parts[2], len(parts[2])) && (len(parts[2]) == 38 || len(parts[2]) == 62) {
			return Object
		}
		if len(parts) == 3 && parts[1] == "pack" && (strings.HasSuffix(parts[2], ".pack") || strings.HasSuffix(parts[2], ".idx")) &&
			strings.HasPrefix(parts[2], "pack-") {
			return Object
		}
		return Quarantine
	}
	for name := range gitNeverIn {
		if is(name) {
			return Quarantine
		}
	}
	// config, hooks/, info/, modules/, worktrees/, config.worktree, refs other than heads, and
	// anything not named above.
	return Quarantine
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func exactASCII(parts []string) bool {
	for _, p := range parts {
		for _, r := range p {
			if r > 0x7e {
				return false
			}
		}
	}
	return true
}
