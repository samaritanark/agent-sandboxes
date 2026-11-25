// Package syncengine is the host side of the workspace sync (design 5.6; our own engine, the
// owner's decision of 2026-11-25). One Sync call reconciles a host work tree with its VM copy
// three ways, against the fingerprints recorded at the last sync:
//
//   - changed on the host only: sent to the VM (masked paths never cross, rule 1);
//   - changed in the VM only: handed to the sync gate (applied, or quarantined for review);
//   - changed on both sides: the VM's version is quarantined as a conflict, the host's is kept.
//
// The VM side is hostile: every path it reports is re-validated and every fingerprint recomputed
// from the bytes received. This increment covers the work tree; .git is handled separately (the
// ref, index, and object rules) and skipped here.
package syncengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/host/syncgate"
	"github.com/samaritanark/agent-sandboxes/go/internal/syncproto"
)

// VM is the agent on the other end.
type VM interface {
	Call(h syncproto.Header, body []byte) (syncproto.Header, []byte, error)
}

// StreamVM talks to an agent over a pair of streams (the SSH session's stdin and stdout).
type StreamVM struct {
	W io.Writer
	R io.Reader
}

func (s *StreamVM) Call(h syncproto.Header, body []byte) (syncproto.Header, []byte, error) {
	if err := syncproto.Write(s.W, h, body); err != nil {
		return syncproto.Header{}, nil, err
	}
	return syncproto.Read(s.R)
}

// State is what the engine remembers between syncs, per repository.
type State struct {
	Base     map[string]string `json:"base"`     // path -> fingerprint both sides had at the last sync
	Withheld map[string]string `json:"withheld"` // path -> the VM fingerprint already quarantined
}

// Engine syncs one repository.
type Engine struct {
	Repo      string // the host work tree
	Host      syncgate.Host
	StateFile string
	Store     *syncgate.Store // the quarantine
	VM        VM
}

// Report is what one Sync did.
type Report struct {
	ToVM, ToHost, Quarantined, Conflicts []string
	Refused                              []string // VM-reported paths that were not valid
}

func (e *Engine) load() (State, error) {
	s := State{Base: map[string]string{}, Withheld: map[string]string{}}
	b, err := os.ReadFile(e.StateFile)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("sync state %s: %w", e.StateFile, err)
	}
	if s.Base == nil {
		s.Base = map[string]string{}
	}
	if s.Withheld == nil {
		s.Withheld = map[string]string{}
	}
	return s, nil
}

func (e *Engine) save(s State) error {
	b, _ := json.Marshal(s)
	if err := os.MkdirAll(filepath.Dir(e.StateFile), 0o700); err != nil {
		return err
	}
	tmp := e.StateFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, e.StateFile)
}

// inGit is a path the work-tree sync leaves to the git rules.
func inGit(p string, h syncgate.Host) bool {
	first, _, _ := strings.Cut(p, "/")
	return strings.EqualFold(first, ".git")
}

// hostScan fingerprints every file and symlink in the work tree, outside .git, through os.Root.
func (e *Engine) hostScan(root *os.Root) (map[string]string, error) {
	out := map[string]string{}
	err := fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if p == "." {
			return nil
		}
		if d.IsDir() {
			if inGit(p, e.Host) {
				return fs.SkipDir
			}
			return nil
		}
		fp, _, err := hostFP(root, p)
		if err == nil {
			out[p] = fp
		}
		return nil
	})
	return out, err
}

func hostFP(root *os.Root, p string) (string, []byte, error) {
	st, err := root.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	switch {
	case st.Mode()&fs.ModeSymlink != 0:
		t, err := root.Readlink(p)
		return syncproto.Fingerprint("link", nil, false, t), nil, err
	case st.Mode().IsRegular():
		if st.Size() > syncproto.MaxBody {
			return "other", nil, nil
		}
		b, err := root.ReadFile(p)
		return syncproto.Fingerprint("file", b, st.Mode()&0o111 != 0, ""), b, err
	case st.IsDir():
		return "dir", nil, nil
	}
	return "other", nil, nil
}

// Sync runs one reconciliation.
func (e *Engine) Sync() (Report, error) {
	var rep Report
	state, err := e.load()
	if err != nil {
		return rep, err
	}
	masks, err := syncgate.RepoMaskedPaths(e.Repo)
	if err != nil {
		return rep, fmt.Errorf("cannot read the repository's masked paths, so nothing is synced: %w", err)
	}
	rules := syncgate.Repo{MaskedPaths: masks}
	root, err := os.OpenRoot(e.Repo)
	if err != nil {
		return rep, err
	}
	defer root.Close()
	host, err := e.hostScan(root)
	if err != nil {
		return rep, err
	}
	scan, _, err := e.VM.Call(syncproto.Header{Op: syncproto.OpScan}, nil)
	if err != nil {
		return rep, fmt.Errorf("VM scan: %w", err)
	}
	if scan.Err != "" {
		return rep, fmt.Errorf("VM scan: %s", scan.Err)
	}
	vm := map[string]string{}
	for _, en := range scan.Entries {
		if _, err := syncgate.CleanPath(en.Path, e.Host); err != nil {
			rep.Refused = append(rep.Refused, en.Path)
			continue
		}
		vm[en.Path] = en.FP
	}

	paths := map[string]bool{}
	for _, m := range []map[string]string{host, vm, state.Base} {
		for p := range m {
			if !inGit(p, e.Host) {
				paths[p] = true
			}
		}
	}
	sorted := make([]string, 0, len(paths))
	for p := range paths {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)

	var batch []syncgate.Change
	vmFP := map[string]string{} // the VM fingerprint each batched change was read at
	for _, p := range sorted {
		b, h, v := state.Base[p], host[p], vm[p]
		if syncgate.IsMasked(p, e.Host, rules) {
			// Rule 1: never crosses. A VM version is kept for review (once), never written.
			if v != "" && v != h && !withheld(state, p, v) {
				c, got, err := e.fromVM(p, v, b)
				if err != nil {
					return rep, err
				}
				if c != nil && e.Store != nil {
					if _, err := e.Store.Put(e.Repo, *c, "masked path (never synced to the host)"); err != nil {
						return rep, err
					}
				}
				if c != nil {
					state.Withheld[p] = got
					rep.Quarantined = append(rep.Quarantined, p)
				}
			}
			continue
		}
		switch {
		case h == v:
			setBase(state, p, h)
			delete(state.Withheld, p)
		case v == b: // host only
			if h == "dir" || h == "other" {
				continue
			}
			fp, err := e.toVM(root, p, h, b)
			if err != nil {
				return rep, err
			}
			if fp == h { // otherwise the VM path changed meanwhile: next round
				setBase(state, p, h)
				rep.ToVM = append(rep.ToVM, p)
			}
		case h == b: // VM only
			if withheld(state, p, v) {
				continue
			}
			c, got, err := e.fromVM(p, v, b)
			if err != nil {
				return rep, err
			}
			if c == nil {
				continue // the VM path changed again while being read; next round
			}
			batch = append(batch, *c)
			vmFP[p] = got
		default: // both
			if withheld(state, p, v) {
				continue
			}
			c, got, err := e.fromVM(p, v, b)
			if err != nil {
				return rep, err
			}
			if c == nil {
				continue
			}
			if e.Store != nil {
				if _, err := e.Store.Put(e.Repo, *c, "changed on the host and in the VM since the last sync (conflict)"); err != nil {
					return rep, err
				}
			}
			state.Withheld[p] = got
			rep.Conflicts = append(rep.Conflicts, p)
		}
	}
	if len(batch) > 0 {
		ap := &syncgate.Applier{Repo: e.Repo, Host: e.Host, Rules: rules,
			Quarantine: func(c syncgate.Change, why string) error {
				if e.Store == nil {
					return nil
				}
				_, err := e.Store.Put(e.Repo, c, why)
				return err
			}}
		outs, err := ap.Apply(batch)
		if err != nil {
			return rep, err
		}
		for _, o := range outs {
			if o.Applied {
				setBase(state, o.Path, vmFP[o.Path])
				delete(state.Withheld, o.Path)
				rep.ToHost = append(rep.ToHost, o.Path)
			} else {
				state.Withheld[o.Path] = vmFP[o.Path]
				rep.Quarantined = append(rep.Quarantined, o.Path)
			}
		}
	}
	return rep, e.save(state)
}

// toVM sends the host's version of p (fingerprint h) to the VM, on condition that the VM still has
// base there. It returns the VM's fingerprint afterwards.
func (e *Engine) toVM(root *os.Root, p, h, base string) (string, error) {
	req := syncproto.Header{Path: p, Base: base}
	var body []byte
	switch {
	case h == "":
		req.Op = syncproto.OpDelete
	case strings.HasPrefix(h, "link:"):
		req.Op, req.Target = syncproto.OpSymlink, strings.TrimPrefix(h, "link:")
	default:
		fp, data, err := hostFP(root, p)
		if err != nil {
			return "", err
		}
		if fp != h {
			return "", nil // changed while syncing: next round
		}
		req.Op, body, req.Exec = syncproto.OpWrite, data, strings.HasSuffix(h, ":x")
	}
	r, _, err := e.VM.Call(req, body)
	if err != nil {
		return "", fmt.Errorf("VM %s %s: %w", req.Op, p, err)
	}
	if r.Err != "" {
		return "", fmt.Errorf("VM %s %s: %s", req.Op, p, r.Err)
	}
	return r.FP, nil
}

// fromVM reads the VM's version of p and returns it as a change for the gate, with the
// fingerprint recomputed from what was received (the VM's own report is not trusted). nil when
// the path changed again since the scan.
func (e *Engine) fromVM(p, v, base string) (*syncgate.Change, string, error) {
	c := &syncgate.Change{Path: p, Base: base}
	if v == "" {
		c.Op = syncgate.OpDelete
		return c, "", nil
	}
	r, body, err := e.VM.Call(syncproto.Header{Op: syncproto.OpRead, Path: p}, nil)
	if err != nil {
		return nil, "", fmt.Errorf("VM read %s: %w", p, err)
	}
	if r.Err != "" {
		return nil, "", fmt.Errorf("VM read %s: %s", p, r.Err)
	}
	var got string
	switch {
	case strings.HasPrefix(r.FP, "link:"):
		c.Op, c.Target = syncgate.OpSymlink, r.Target
		got = syncproto.Fingerprint("link", nil, false, r.Target)
	case strings.HasPrefix(r.FP, "file:"):
		c.Op, c.Data, c.Exec = syncgate.OpWrite, body, strings.HasSuffix(r.FP, ":x")
		got = syncproto.Fingerprint("file", body, c.Exec, "")
	case r.FP == "":
		c.Op = syncgate.OpDelete
	default:
		return nil, "", nil // a directory or special file where a file was: left for review next round
	}
	if got != v {
		return nil, "", nil
	}
	return c, got, nil
}

// withheld: this VM version of p was already quarantined (a deletion has the empty fingerprint,
// so presence in the map is what counts, not the zero value).
func withheld(s State, p, v string) bool {
	w, ok := s.Withheld[p]
	return ok && w == v
}

func setBase(s State, p, fp string) {
	if fp == "" {
		delete(s.Base, p)
	} else {
		s.Base[p] = fp
	}
}
