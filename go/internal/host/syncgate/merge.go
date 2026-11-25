package syncgate

import (
	"bytes"
	"fmt"
	"sort"
)

// Rule 7's three-way merge of the index, by path: base is the index as last synced, host and vm
// the two sides now. A path's entries (all its stages together, so merge-conflict stages and their
// resolution travel as one) are taken from whichever side changed them; when both changed them
// differently the host wins and the conflict is reported (the one deliberate exception to
// "never pick a winner silently": only staging is lost, the agent's files are untouched).
//
// VM-side entries are validated before they are taken; a refused one leaves the host's entries in
// place and is reported:
//   - a path the classifier protects (masked, an exec vector, git state), or one that is not valid;
//   - a gitlink, added or changed;
//   - a file-type change (regular, symlink, gitlink) against the host's entry;
//   - an object id the host object store does not hold (hasObject), so nothing the host has not
//     verified becomes stageable.
// Hiding flags (assume-valid, skip-worktree) are cleared on every entry taken from the VM; the
// host's own entries keep theirs (the operator's sparse checkout or update-index settings).

// MergeNote is one path the merge could not take from the VM.
type MergeNote struct {
	Path   string
	Reason string
}

// MergeResult is the merged index and what was refused or conflicted.
type MergeResult struct {
	Entries   []Entry
	Withheld  []MergeNote
	Conflicts []MergeNote
}

func byPath(es []Entry) map[string][]Entry {
	m := map[string][]Entry{}
	for _, e := range es {
		m[e.Path] = append(m[e.Path], e)
	}
	for _, v := range m {
		sort.Slice(v, func(i, j int) bool { return v[i].Stage < v[j].Stage })
	}
	return m
}

func sameEntries(a, b []Entry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Stage != b[i].Stage || a[i].Mode != b[i].Mode || !bytes.Equal(a[i].ID, b[i].ID) || a[i].IntentToAdd != b[i].IntentToAdd {
			return false
		}
	}
	return true
}

func fileType(m uint32) uint32 { return m & 0o170000 }

// MergeIndex merges by path. h and repo decide which paths are protected; hasObject reports
// whether the host object store holds an object (a verified one).
func MergeIndex(base, host, vm []Entry, h Host, repo Repo, hasObject func(id []byte) bool) MergeResult {
	B, H, V := byPath(base), byPath(host), byPath(vm)
	paths := map[string]bool{}
	for _, m := range []map[string][]Entry{B, H, V} {
		for p := range m {
			paths[p] = true
		}
	}
	var res MergeResult
	take := func(es []Entry) { res.Entries = append(res.Entries, es...) }
	for p := range paths {
		b, hs, vs := B[p], H[p], V[p]
		switch {
		case sameEntries(vs, b), sameEntries(vs, hs):
			take(hs)
		case sameEntries(hs, b):
			if why := vmRefusal(p, hs, vs, h, repo, hasObject); why != "" {
				res.Withheld = append(res.Withheld, MergeNote{p, why})
				take(hs)
				continue
			}
			// a VM-origin entry never carries the flags that hide changes from git status
			for _, e := range vs {
				e.AssumeValid, e.SkipWorktree = false, false
				res.Entries = append(res.Entries, e)
			}
		default:
			res.Conflicts = append(res.Conflicts, MergeNote{p, "staged differently on the host and in the VM; the host's staging was kept"})
			take(hs)
		}
	}
	sort.Slice(res.Entries, func(i, j int) bool {
		if res.Entries[i].Path != res.Entries[j].Path {
			return res.Entries[i].Path < res.Entries[j].Path
		}
		return res.Entries[i].Stage < res.Entries[j].Stage
	})
	sort.Slice(res.Withheld, func(i, j int) bool { return res.Withheld[i].Path < res.Withheld[j].Path })
	sort.Slice(res.Conflicts, func(i, j int) bool { return res.Conflicts[i].Path < res.Conflicts[j].Path })
	return res
}

// vmRefusal is why the VM's entries for p (replacing the host's hs) are not taken, or "".
func vmRefusal(p string, hs, vs []Entry, h Host, repo Repo, hasObject func([]byte) bool) string {
	c, err := Classify(p, h, repo)
	if err != nil {
		return "invalid path: " + err.Error()
	}
	if c != Apply && c != Attributes {
		return fmt.Sprintf("protected path (%s)", c)
	}
	if !validIndexPath(p) {
		return "invalid path"
	}
	for _, e := range vs {
		if fileType(e.Mode) == 0o160000 {
			return "gitlink"
		}
		for _, o := range hs {
			if fileType(o.Mode) != fileType(e.Mode) {
				return fmt.Sprintf("file type change (%06o to %06o)", o.Mode, e.Mode)
			}
		}
		if !e.IntentToAdd && !hasObject(e.ID) {
			return "object " + fmt.Sprintf("%x", e.ID) + " is not in the host object store"
		}
	}
	return ""
}
