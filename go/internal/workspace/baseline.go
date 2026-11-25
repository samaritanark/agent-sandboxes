package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
)

// The workspace baseline and diff of lib/filesystem.sh (capture_workspace_baseline,
// capture_workspace_diff): a sha256 of every file in the session's repos at launch and at stop,
// and files.log, the diff between them. v3 keeps it, computed in the VM (design 5.12).

var (
	pruneStart = regexp.MustCompile(`^prune_dirs:`)
	pruneEnd   = regexp.MustCompile(`^[^ \t\n\v\f\r#]`)
	pruneItem  = regexp.MustCompile(`^[ \t\n\v\f\r]*-[ \t\n\v\f\r]`)
	pruneLead  = regexp.MustCompile(`^[ \t\n\v\f\r]*-[ \t\n\v\f\r]*`)
	pruneCmt   = regexp.MustCompile(`[ \t\n\v\f\r]*#.*$`)
	pruneTrail = regexp.MustCompile(`[ \t\n\v\f\r]+$`)
)

// PruneDirs is _load_workspace_audit_prune_dirs: the prune_dirs: list of
// <root>/config/workspace-audit.yaml (nothing when the file is missing).
func PruneDirs(sandboxRoot string) []string {
	b, err := os.ReadFile(sandboxRoot + "/config/workspace-audit.yaml")
	if err != nil {
		return nil
	}
	var out []string
	in := false
	for _, l := range bashcompat.SplitRecords(b) {
		if pruneStart.MatchString(l) {
			in = true
			continue
		}
		if in && pruneEnd.MatchString(l) {
			in = false
		}
		if in && pruneItem.MatchString(l) {
			l = pruneLead.ReplaceAllString(l, "")
			l = pruneCmt.ReplaceAllString(l, "")
			l = pruneTrail.ReplaceAllString(l, "")
			if strings.HasPrefix(l, `"`) || strings.HasPrefix(l, "'") {
				l = l[1:]
			}
			if strings.HasSuffix(l, `"`) || strings.HasSuffix(l, "'") {
				l = l[:len(l)-1]
			}
			if l != "" {
				out = append(out, l)
			}
		}
	}
	return out
}

// sumLine is one line of GNU sha256sum (coreutils 9): a name holding a backslash, newline, or
// carriage return is escaped and the line marked with a leading backslash.
func sumLine(sum, name string) string {
	if strings.ContainsAny(name, "\\\n\r") {
		r := strings.NewReplacer(`\`, `\\`, "\n", `\n`, "\r", `\r`)
		return `\` + sum + "  " + r.Replace(name)
	}
	return sum + "  " + name
}

// HashWorkspace is _hash_workspace: `find WS \( -path WS/.git/objects -o -name D ... \) -prune -o
// -type f -exec sha256sum {} +`, sorted bytewise. Regular files only, links not followed;
// anything unreadable is left out, as its error goes to /dev/null.
//
// In legacy mode a prune name also matches the workspace itself (a repo named build/ or out/ got
// no baseline at all), and with a trailing slash on the workspace path the .git/objects pattern
// never matched. With WorkspaceHashPruneBelowRoot both apply to what is under the root, however
// its path is spelled.
func HashWorkspace(ws string, prune []string) []string {
	fixed := deviation.Fixed(deviation.WorkspaceHashPruneBelowRoot)
	objects := ws + "/.git/objects"
	pruned := func(path string, root bool) bool {
		if fixed {
			if root {
				return false
			}
			if strings.TrimLeft(strings.TrimPrefix(path, ws), "/") == ".git/objects" {
				return true
			}
		} else if bashcompat.Glob(objects, path) {
			return true
		}
		base := path
		if i := strings.LastIndex(strings.TrimRight(path, "/"), "/"); i >= 0 {
			base = strings.TrimRight(path, "/")[i+1:]
		}
		for _, d := range prune {
			if bashcompat.Glob(d, base) {
				return true
			}
		}
		return false
	}
	var lines []string
	var walk func(path string, root bool)
	walk = func(path string, root bool) {
		st, err := os.Lstat(path)
		if err != nil || pruned(path, root) {
			return
		}
		switch {
		case st.Mode().IsRegular():
			f, err := os.Open(path)
			if err != nil {
				return
			}
			h := sha256.New()
			_, err = io.Copy(h, f)
			f.Close()
			if err == nil {
				lines = append(lines, sumLine(hex.EncodeToString(h.Sum(nil)), path))
			}
		case st.IsDir():
			ents, err := os.ReadDir(path)
			if err != nil {
				return
			}
			for _, e := range ents {
				sep := "/"
				if strings.HasSuffix(path, "/") {
					sep = "" // find joins "dir/" and "x" as "dir/x"
				}
				walk(path+sep+e.Name(), false)
			}
		}
	}
	walk(ws, true)
	sort.Strings(lines)
	return lines
}

func writeLines(path string, lines []string) error {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// CaptureBaseline is capture_workspace_baseline: <logDir>/baseline.sha256 over every repo, and
// the line the bash prints.
func CaptureBaseline(logDir string, repos, prune []string) string {
	var all []string
	for _, r := range repos {
		all = append(all, HashWorkspace(r, prune)...)
	}
	writeLines(logDir+"/baseline.sha256", all)
	return fmt.Sprintf("  Baseline: %d files.", len(all))
}

// CaptureDiff is capture_workspace_diff: files.log (a header and `diff baseline current`) and the
// lines the bash prints. The bash's count, `diff | grep -c ... || echo 0` under pipefail, always
// printed a stray "0" line after it; with DiffCountOnce the count is printed once.
func CaptureDiff(logDir string, repos, prune []string) []string {
	base, cur, log := logDir+"/baseline.sha256", logDir+"/current.sha256", logDir+"/files.log"
	b, err := os.ReadFile(base)
	if err != nil {
		if st, e := os.Stat(base); e != nil || !st.Mode().IsRegular() {
			return []string{"  No baseline found; skipping diff."}
		}
	}
	var now []string
	for _, r := range repos {
		now = append(now, HashWorkspace(r, prune)...)
	}
	writeLines(cur, now)
	d := NormalDiff(bashcompat.SplitRecords(b), now)
	var out strings.Builder
	out.WriteString("=== Workspace diff for session (files modified/added/deleted) ===\n")
	out.WriteString("Baseline: " + base + "\n")
	out.WriteString("Current:  " + cur + "\n")
	out.WriteString("Diff:\n")
	n := 0
	for _, l := range d {
		out.WriteString(l + "\n")
		if strings.HasPrefix(l, "<") || strings.HasPrefix(l, ">") {
			n++
		}
	}
	os.WriteFile(log, []byte(out.String()), 0o644)
	os.Remove(cur)
	count := fmt.Sprint(n)
	if !deviation.Fixed(deviation.DiffCountOnce) {
		// `diff | grep -c ... || echo 0` under pipefail: diff fails when there are changes and
		// grep when there are none, so the echo always runs
		count += "\n0"
	}
	return strings.Split("  Workspace diff: "+count+" line(s) changed.", "\n")
}

// NormalDiff is GNU diff's normal format for two lists of distinct lines that share one order
// (each is a sorted hash listing, repo by repo): the common lines are then the only longest common
// subsequence, so the hunks are fully determined. Between two common lines, deletions and
// additions form one hunk: "Nd M", "N a M", or "N c M".
func NormalDiff(a, b []string) []string {
	inB := map[string]bool{}
	for _, l := range b {
		inB[l] = true
	}
	inA := map[string]bool{}
	for _, l := range a {
		inA[l] = true
	}
	rng := func(lo, hi int) string { // 1-based inclusive
		if lo == hi {
			return fmt.Sprint(lo)
		}
		return fmt.Sprintf("%d,%d", lo, hi)
	}
	var out []string
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		if i < len(a) && j < len(b) && a[i] == b[j] {
			i, j = i+1, j+1
			continue
		}
		di, dj := i, j
		for i < len(a) && !inB[a[i]] {
			i++
		}
		for j < len(b) && !inA[b[j]] {
			j++
		}
		if i == di && j == dj { // not one shared order after all: take a[i] as removed
			i++
		}
		switch {
		case i > di && j > dj:
			out = append(out, rng(di+1, i)+"c"+rng(dj+1, j))
		case i > di:
			out = append(out, rng(di+1, i)+"d"+fmt.Sprint(j))
		default:
			out = append(out, fmt.Sprint(i)+"a"+rng(dj+1, j))
		}
		for _, l := range a[di:i] {
			out = append(out, "< "+l)
		}
		if i > di && j > dj {
			out = append(out, "---")
		}
		for _, l := range b[dj:j] {
			out = append(out, "> "+l)
		}
	}
	return out
}
