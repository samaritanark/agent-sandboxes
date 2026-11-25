package syncengine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/gitobj"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/gitref"
	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncgate"
	"github.com/samaritanark/agent-sandboxes/go/internal/syncproto"
)

// GitState is what the engine remembers about .git between syncs.
type GitState struct {
	Refs        map[string]string `json:"refs"`  // refs/heads/* both sides agreed on
	Head        string            `json:"head"`  // HEAD both sides agreed on
	Files       map[string]string `json:"files"` // other .git files: last-synced fingerprints
	IndexHostFP string            `json:"index_host"`
	IndexVMFP   string            `json:"index_vm"`
}

// ignoredFromVM are .git paths whose VM-side changes are dropped, not quarantined: design 5.6.2
// rule 6 says they never flow VM to host, and they change with every git command (reflogs,
// fetches), so reviewing them would bury the changes that matter.
func ignoredFromVM(p string) bool {
	for _, pre := range []string{".git/logs/", ".git/refs/remotes/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	switch p {
	case ".git/FETCH_HEAD", ".git/ORIG_HEAD", ".git/COMMIT_EDITMSG", ".git/gc.log", ".git/description":
		return true
	}
	return false
}

func fp(b []byte) string { return syncproto.Fingerprint("file", b, false, "") }

// writeFileAtomic writes p inside root through a lock-named temporary file (git's protocol for
// refs and the index: <p>.lock created exclusively, then renamed). It fails when the lock is held.
func writeFileAtomic(root *os.Root, p string, data []byte, mode fs.FileMode) error {
	if dir := path.Dir(p); dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	lock := p + ".lock"
	f, err := root.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("%s is locked: %w", p, err)
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = root.Rename(lock, p)
	}
	if err != nil {
		root.Remove(lock)
	}
	return err
}

func (e *Engine) vmRead(p string) ([]byte, string, error) {
	r, body, err := e.VM.Call(syncproto.Header{Op: syncproto.OpRead, Path: p}, nil)
	if err != nil {
		return nil, "", err
	}
	if r.Err != "" {
		return nil, "", errors.New(r.Err)
	}
	return body, r.FP, nil
}

func (e *Engine) vmWrite(p string, data []byte, base string) (string, bool, error) {
	r, _, err := e.VM.Call(syncproto.Header{Op: syncproto.OpWrite, Path: p, Base: base}, data)
	if err != nil {
		return "", false, err
	}
	if r.Err != "" {
		return "", false, errors.New(r.Err)
	}
	return r.FP, r.Conflict, nil
}

// refsOf collects refs/heads/* from loose ref files and packed-refs (loose wins), as read by get.
func refsOf(files map[string]string, get func(string) ([]byte, error), idLen int) (syncgate.Refs, error) {
	refs := syncgate.Refs{}
	if _, ok := files[".git/packed-refs"]; ok {
		b, err := get(".git/packed-refs")
		if err != nil {
			return nil, err
		}
		packed, err := syncgate.ParsePackedRefs(b, idLen)
		if err != nil {
			return nil, err
		}
		for r, id := range packed {
			if strings.HasPrefix(r, "refs/heads/") {
				refs[r] = id
			}
		}
	}
	for p := range files {
		ref, ok := strings.CutPrefix(p, ".git/")
		if !ok || !strings.HasPrefix(ref, "refs/heads/") || strings.HasSuffix(ref, ".lock") {
			continue
		}
		b, err := get(p)
		if err != nil {
			return nil, err
		}
		v := strings.TrimSpace(string(b))
		if strings.HasPrefix(v, "ref: ") {
			continue // a symbolic branch: not moved by the sync
		}
		refs[ref] = v
	}
	return refs, nil
}

// syncGit runs the git rules. host and vm are the two sides' .git scans.
func (e *Engine) syncGit(hg *hostGit, repo *gitref.Repo, st *State, host, vm map[string]string, rules syncgate.Repo, rep *Report) error {
	idLen := repo.HashLen / 2
	g := &st.Git
	if g.Refs == nil {
		g.Refs = map[string]string{}
	}
	if g.Files == nil {
		g.Files = map[string]string{}
	}
	hostRead := hg.ReadFile
	vmReadB := func(p string) ([]byte, error) { b, _, err := e.vmRead(p); return b, err }

	// 1. Objects: content-addressed and append-only; never deleted by the sync.
	var vmObjs []string
	for p := range vm {
		if syncproto.IsObjectPath(p) {
			if _, have := host[p]; !have {
				vmObjs = append(vmObjs, p)
			}
		}
	}
	sort.Strings(vmObjs)
	for _, p := range vmObjs {
		rel := strings.TrimPrefix(p, ".git/objects/")
		switch {
		case strings.HasPrefix(rel, "pack/") && strings.HasSuffix(rel, ".idx"):
			packPath := strings.TrimSuffix(p, ".idx") + ".pack"
			if _, ok := vm[packPath]; !ok {
				continue
			}
			ib, err := vmReadB(p)
			if err != nil {
				return err
			}
			pb, err := vmReadB(packPath)
			if err != nil {
				return err
			}
			if _, err := gitobj.VerifyPack(pb, ib, idLen); err != nil {
				rep.Quarantined = append(rep.Quarantined, p+" (pack refused: "+err.Error()+")")
				continue
			}
			if err := hg.writeObject(packPath, pb); err != nil {
				return err
			}
			if err := hg.writeObject(p, ib); err != nil {
				return err
			}
			rep.ToHost = append(rep.ToHost, packPath, p)
		case len(rel) == 2*idLen+1 && rel[2] == '/':
			raw, err := vmReadB(p)
			if err != nil {
				return err
			}
			if _, err := gitobj.VerifyLoose(raw, rel[:2]+rel[3:], idLen); err != nil {
				rep.Quarantined = append(rep.Quarantined, p+" (object refused: "+err.Error()+")")
				continue
			}
			if err := hg.writeObject(p, raw); err != nil {
				return err
			}
			rep.ToHost = append(rep.ToHost, p)
		}
	}
	for p := range host {
		if syncproto.IsObjectPath(p) {
			if _, have := vm[p]; !have {
				b, err := hostRead(p)
				if err != nil {
					return err
				}
				if _, _, err := e.vmWrite(p, b, ""); err != nil {
					return fmt.Errorf("VM write %s: %w", p, err)
				}
				rep.ToVM = append(rep.ToVM, p)
			}
		}
	}
	store, err := gitobj.Open(filepath.Join(repo.CommonDir, "objects"), idLen)
	if err != nil {
		return err
	}

	// 2. Branches.
	hostRefs, err := refsOf(host, hostRead, idLen)
	if err != nil {
		return err
	}
	vmRefs, err := refsOf(vm, vmReadB, idLen)
	if err != nil {
		rep.Notes = append(rep.Notes, "the VM's refs could not be read: "+err.Error())
		vmRefs = g.Refs
	}
	if len(g.Refs) == 0 && g.Head == "" { // first sync: the host's refs are the agreed state
		for r, v := range hostRefs {
			g.Refs[r] = v
		}
	}
	// A VM copy with no HEAD is new (or was reset): it gets the host's git state, and nothing it
	// lacks counts as a VM-side deletion.
	fresh := vm[".git/HEAD"] == ""
	if fresh {
		vmRefs = syncgate.Refs{}
		for r, v := range g.Refs {
			vmRefs[r] = v
		}
	}
	originHead, _ := hostRead(".git/refs/remotes/origin/HEAD")
	var decisions []syncgate.RefDecision
	if !fresh {
		decisions = syncgate.DecideRefs(g.Refs, hostRefs, vmRefs, syncgate.Protected(string(originHead), hg.otherWorktreeBranches()), e.Host, store)
	}
	for _, d := range decisions {
		key := ".git/" + d.Ref
		if d.Apply {
			if err := hg.writeAtomic(key, []byte(d.New+"\n")); err != nil {
				return err
			}
			hostRefs[d.Ref] = d.New
			g.Refs[d.Ref] = d.New
			rep.ToHost = append(rep.ToHost, key)
			rep.Ledger = append(rep.Ledger, fmt.Sprintf("%s %s -> %s (%s)", d.Ref, d.Old, d.New, d.Reason))
			continue
		}
		if withheld(*st, key, d.New) {
			continue
		}
		c := syncgate.Change{Path: key, Op: syncgate.OpWrite, Data: []byte(d.New + "\n")}
		if d.New == "" {
			c = syncgate.Change{Path: key, Op: syncgate.OpDelete}
		}
		if e.Store != nil {
			if _, err := e.Store.Put(e.Repo, c, d.Reason); err != nil {
				return err
			}
		}
		st.Withheld[key] = d.New
		rep.Quarantined = append(rep.Quarantined, key+" ("+d.Reason+")")
	}
	// host branch moves go to the VM as loose refs (which win over its packed-refs)
	for r, hv := range hostRefs {
		if !fresh && hv == g.Refs[r] && vmRefs[r] == hv {
			continue
		}
		if !fresh && vmRefs[r] != g.Refs[r] && vmRefs[r] != hv {
			continue // the VM moved it too: decided above
		}
		key := ".git/" + r
		if _, conflict, err := e.vmWrite(key, []byte(hv+"\n"), vm[key]); err != nil {
			return fmt.Errorf("VM write %s: %w", key, err)
		} else if !conflict {
			g.Refs[r] = hv
			rep.ToVM = append(rep.ToVM, key)
		}
	}

	// 3. HEAD.
	hostHead, _ := hostRead(".git/HEAD")
	vmHeadB, vmHeadFP, err := e.vmRead(".git/HEAD")
	if err != nil {
		return err
	}
	if g.Head == "" {
		g.Head = string(hostHead)
	}
	switch vmHead := string(vmHeadB); {
	case vmHeadFP == "":
		if _, _, err := e.vmWrite(".git/HEAD", hostHead, ""); err != nil {
			return err
		}
		g.Head = string(hostHead)
		rep.ToVM = append(rep.ToVM, ".git/HEAD")
	case vmHead == string(hostHead):
		g.Head = vmHead
	case vmHead != g.Head:
		text, err := syncgate.DecideHead(g.Head, string(hostHead), vmHead, hostRefs, e.Host, store, idLen)
		if err != nil {
			if !withheld(*st, ".git/HEAD", vmHeadFP) {
				if e.Store != nil {
					if _, perr := e.Store.Put(e.Repo, syncgate.Change{Path: ".git/HEAD", Op: syncgate.OpWrite, Data: vmHeadB}, err.Error()); perr != nil {
						return perr
					}
				}
				st.Withheld[".git/HEAD"] = vmHeadFP
				rep.Quarantined = append(rep.Quarantined, ".git/HEAD ("+err.Error()+")")
			}
		} else if text != "" {
			if err := hg.writeAtomic(".git/HEAD", []byte(text)); err != nil {
				return err
			}
			g.Head = text
			rep.ToHost = append(rep.ToHost, ".git/HEAD")
			rep.Ledger = append(rep.Ledger, "HEAD -> "+strings.TrimSpace(text))
		}
	case string(hostHead) != g.Head:
		if _, conflict, err := e.vmWrite(".git/HEAD", hostHead, vmHeadFP); err != nil {
			return err
		} else if !conflict {
			g.Head = string(hostHead)
			rep.ToVM = append(rep.ToVM, ".git/HEAD")
		}
	}

	// 4. The index, merged by entry.
	if err := e.syncIndex(hg, st, host, vm, rules, store, idLen, rep); err != nil {
		return err
	}

	// 5. Every other .git file: host to VM; VM changes ignored or quarantined.
	paths := map[string]bool{}
	for _, m := range []map[string]string{host, vm, g.Files} {
		for p := range m {
			paths[p] = true
		}
	}
	for p := range paths {
		if syncproto.IsObjectPath(p) || p == ".git/HEAD" || p == ".git/index" || p == ".git/packed-refs" ||
			strings.HasPrefix(p, ".git/refs/heads/") {
			continue
		}
		if c, _ := syncgate.Classify(p, e.Host, rules); c == syncgate.Local {
			continue
		}
		b, h, v := g.Files[p], host[p], vm[p]
		switch {
		case h == v:
			setBase(State{Base: g.Files}, p, h)
		case v == b: // host change
			if h == "dir" || h == "other" {
				continue
			}
			r, rel, err := hg.loc(p)
			if err != nil {
				return err
			}
			f, err := e.toVMFrom(r, rel, p, h, b)
			if err != nil {
				return err
			}
			if f == h {
				setBase(State{Base: g.Files}, p, h)
				rep.ToVM = append(rep.ToVM, p)
			}
		default: // the VM changed it
			if ignoredFromVM(p) || withheld(*st, p, v) {
				continue
			}
			c, got, err := e.fromVM(p, v, b)
			if err != nil {
				return err
			}
			if c == nil {
				continue
			}
			if e.Store != nil {
				if _, err := e.Store.Put(e.Repo, *c, "git state that never flows from the VM (rule 6)"); err != nil {
					return err
				}
			}
			st.Withheld[p] = got
			rep.Quarantined = append(rep.Quarantined, p)
		}
	}
	return nil
}

// writeObject stores a verified object or pack file read-only, if it is not there yet.
func writeObject(root *os.Root, p string, data []byte) error {
	if _, err := root.Lstat(p); err == nil {
		return nil
	}
	if err := root.MkdirAll(path.Dir(p), 0o755); err != nil {
		return err
	}
	var rb [6]byte
	sum := sha256.Sum256(append([]byte(p), data[:min(len(data), 64)]...))
	copy(rb[:], sum[:])
	tmp := path.Join(path.Dir(p), "tmp_sync_"+hex.EncodeToString(rb[:]))
	if err := root.WriteFile(tmp, data, 0o444); err != nil {
		return err
	}
	if err := root.Rename(tmp, p); err != nil {
		root.Remove(tmp)
		return err
	}
	return nil
}

// syncIndex merges the index three ways (rule 7) when either side's changed since the last sync.
func (e *Engine) syncIndex(hg *hostGit, st *State, host, vm map[string]string, rules syncgate.Repo, store *gitobj.Store, idLen int, rep *Report) error {
	g := &st.Git
	hFP, vFP := host[".git/index"], vm[".git/index"]
	if hFP == g.IndexHostFP && vFP == g.IndexVMFP {
		return nil
	}
	baseFile := e.StateFile + ".index"
	parse := func(b []byte) []syncgate.Entry {
		if len(b) == 0 {
			return nil
		}
		ix, err := syncgate.ParseIndex(b, idLen)
		if err != nil {
			return nil
		}
		return ix.Entries
	}
	hostB, _ := hg.ReadFile(".git/index")
	if hFP == "" {
		hostB = nil
	}
	var vmB []byte
	if vFP != "" {
		var err error
		if vmB, _, err = e.vmRead(".git/index"); err != nil {
			return err
		}
	}
	baseB, err := os.ReadFile(baseFile)
	if err != nil {
		baseB = hostB // first sync: the host's index is the agreed state
	}
	vmEntries := parse(vmB)
	if vFP != "" && vmEntries == nil && len(vmB) > 0 {
		rep.Notes = append(rep.Notes, "the VM's index did not parse; the host's staging was kept")
		vmEntries = parse(baseB)
	}
	if vFP == "" {
		vmEntries = parse(baseB) // the VM has none yet: no VM-side changes
	}
	hasObject := func(id []byte) bool { return store.Has(hex.EncodeToString(id)) }
	res := syncgate.MergeIndex(parse(baseB), parse(hostB), vmEntries, e.Host, rules, hasObject)
	for _, w := range res.Withheld {
		rep.Notes = append(rep.Notes, "staging of "+w.Path+" withheld: "+w.Reason)
	}
	for _, c := range res.Conflicts {
		rep.Conflicts = append(rep.Conflicts, "index:"+c.Path)
	}
	merged, err := syncgate.WriteIndex(res.Entries, idLen)
	if err != nil {
		return err
	}
	newHost := hFP
	if !syncgate.SameEntries(res.Entries, parse(hostB)) || hostB == nil && len(res.Entries) > 0 {
		if err := hg.writeAtomic(".git/index", merged); err != nil {
			rep.Notes = append(rep.Notes, "the host index is in use; staging sync deferred")
			return nil
		}
		newHost = fp(merged)
		rep.ToHost = append(rep.ToHost, ".git/index")
	}
	newVM := vFP
	if !syncgate.SameEntries(res.Entries, parse(vmB)) || vmB == nil && len(res.Entries) > 0 {
		f, conflict, err := e.vmWrite(".git/index", merged, vFP)
		if err != nil {
			return err
		}
		if conflict {
			return nil // the VM changed it again: next round
		}
		newVM = f
		rep.ToVM = append(rep.ToVM, ".git/index")
	}
	if err := os.MkdirAll(filepath.Dir(baseFile), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(baseFile, merged, 0o600); err != nil {
		return err
	}
	g.IndexHostFP, g.IndexVMFP = newHost, newVM
	return nil
}
