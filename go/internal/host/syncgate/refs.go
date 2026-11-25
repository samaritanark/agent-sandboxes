package syncgate

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Rule 6 for refs and HEAD. The engine reads each side's refs as files (loose refs over
// packed-refs, parsed with ParsePackedRefs, never copied) into Refs maps; DecideRefs says which
// VM-origin branch updates apply directly and which are quarantined, and DecideHead does the same
// for HEAD. Only refs/heads/* ever flows VM to host (the classifier quarantines the rest).

// Refs maps full ref names (refs/heads/x) to object ids.
type Refs map[string]string

// Objects is what the ref rules need from the host object store (after the VM's objects have
// been verified into it).
type Objects interface {
	Has(id string) bool
	IsAncestor(old, new string) (bool, error)
	Parents(id string) ([]string, error) // also proves id is a commit
}

// RefDecision is the outcome for one ref.
type RefDecision struct {
	Ref      string
	Old, New string // host value before, VM value ("" for none)
	Apply    bool
	Reason   string
}

// ValidBranch is git check-ref-format for a branch's full name under refs/heads/.
func ValidBranch(ref string) bool {
	name, ok := strings.CutPrefix(ref, "refs/heads/")
	if !ok || name == "" || name == "HEAD" || strings.HasPrefix(name, "-") || strings.HasSuffix(name, "/") || strings.HasSuffix(name, ".") ||
		strings.Contains(name, "..") || strings.Contains(name, "@{") || name == "@" {
		return false
	}
	for _, c := range strings.Split(name, "/") {
		if c == "" || strings.HasPrefix(c, ".") || strings.HasSuffix(c, ".lock") {
			return false
		}
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(" ~^:?*[\\", r) {
			return false
		}
	}
	return true
}

// ParsePackedRefs reads a packed-refs file strictly: an optional "# pack-refs with:" header, then
// "<id> <ref>" lines, each optionally followed by a "^<id>" peeled line.
func ParsePackedRefs(b []byte, idLen int) (Refs, error) {
	out := Refs{}
	lines := strings.Split(string(b), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	last := ""
	for i, l := range lines {
		switch {
		case i == 0 && strings.HasPrefix(l, "# pack-refs with:"):
		case strings.HasPrefix(l, "^"):
			if last == "" || !hexID(l[1:], idLen) {
				return nil, fmt.Errorf("packed-refs line %d: misplaced or malformed peeled line", i+1)
			}
			last = ""
		default:
			id, ref, ok := strings.Cut(l, " ")
			if !ok || !hexID(id, idLen) || !strings.HasPrefix(ref, "refs/") || strings.ContainsAny(ref, " \t\r") {
				return nil, fmt.Errorf("packed-refs line %d: malformed", i+1)
			}
			if _, dup := out[ref]; dup {
				return nil, fmt.Errorf("packed-refs line %d: %s repeated", i+1, ref)
			}
			out[ref] = id
			last = ref
		}
	}
	return out, nil
}

func hexID(s string, idLen int) bool { return isHex(s, 2*idLen) }

// Protected is the set of branch names the gate never moves directly: main, master, the host's
// origin default branch, and the configured list (overlays may add, never remove).
func Protected(originHead string, configured []string) []string {
	out := []string{"refs/heads/main", "refs/heads/master"}
	if b, ok := strings.CutPrefix(strings.TrimSpace(originHead), "ref: refs/remotes/origin/"); ok && b != "" {
		out = append(out, "refs/heads/"+b)
	}
	for _, c := range configured {
		out = append(out, "refs/heads/"+strings.TrimPrefix(c, "refs/heads/"))
	}
	return out
}

// refKey is a ref name's key on this host (refs are files under .git/refs, so they alias as
// file names do).
func (h Host) refKey(ref string) string {
	parts := strings.Split(ref, "/")
	for i, p := range parts {
		parts[i] = h.key(p)
	}
	return strings.Join(parts, "/")
}

// DecideRefs decides each VM-origin branch change. base is the refs as last synced, host and vm
// the two sides now.
func DecideRefs(base, host, vm Refs, protected []string, h Host, objs Objects) []RefDecision {
	prot := map[string]bool{}
	for _, p := range protected {
		prot[h.refKey(p)] = true
	}
	hostByKey := map[string]string{}
	for r := range host {
		hostByKey[h.refKey(r)] = r
	}
	names := map[string]bool{}
	for r := range vm {
		names[r] = true
	}
	for r := range base {
		names[r] = true
	}
	var out []RefDecision
	for r := range names {
		if !strings.HasPrefix(r, "refs/heads/") {
			continue
		}
		b, hv, v := base[r], host[r], vm[r]
		if v == b {
			continue // the VM did not touch it
		}
		d := RefDecision{Ref: r, Old: hv, New: v}
		switch {
		case !ValidBranch(r):
			d.Reason = "invalid branch name"
		case hostByKey[h.refKey(r)] != "" && hostByKey[h.refKey(r)] != r:
			d.Reason = "names the host branch " + hostByKey[h.refKey(r)] + " in another spelling"
		case prot[h.refKey(r)]:
			d.Reason = "protected branch"
		case hv != b:
			d.Reason = "changed on the host and in the VM since the last sync"
		case v == "":
			d.Reason = "branch deletion"
		case !objs.Has(v):
			d.Reason = "commit " + v + " is not in the host object store"
		default:
			if _, err := objs.Parents(v); err != nil {
				d.Reason = "not a commit: " + err.Error()
				break
			}
			if hv == "" {
				d.Apply, d.Reason = true, "new branch"
				break
			}
			ff, err := objs.IsAncestor(hv, v)
			switch {
			case err != nil:
				d.Reason = "cannot check ancestry: " + err.Error()
			case !ff:
				d.Reason = "not a fast-forward"
			default:
				d.Apply, d.Reason = true, "fast-forward"
			}
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// DecideHead checks a VM-origin HEAD. after is the host's branches once the applied ref updates
// are in; base and host are HEAD as last synced and on the host now. It returns the HEAD text to
// write, or an error saying why the change is refused (nil change when the VM did not move it).
func DecideHead(base, host, vm string, after Refs, h Host, objs Objects, idLen int) (string, error) {
	if vm == base {
		return "", nil
	}
	if host != base {
		return "", errors.New("HEAD changed on the host and in the VM since the last sync")
	}
	if ref, ok := strings.CutPrefix(vm, "ref: "); ok {
		ref = strings.TrimSuffix(ref, "\n")
		if strings.ContainsAny(ref, "\n\r") || !ValidBranch(ref) {
			return "", fmt.Errorf("HEAD %q is not a branch", vm)
		}
		if _, ok := after[ref]; !ok {
			return "", fmt.Errorf("HEAD names %s, which the host does not have", ref)
		}
		return "ref: " + ref + "\n", nil
	}
	id := strings.TrimSuffix(vm, "\n")
	if !hexID(id, idLen) || !objs.Has(id) {
		return "", fmt.Errorf("HEAD %q is neither a branch nor a commit the host holds", vm)
	}
	if _, err := objs.Parents(id); err != nil {
		return "", fmt.Errorf("detached HEAD is not a commit: %v", err)
	}
	return id + "\n", nil
}
