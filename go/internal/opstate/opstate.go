// Package opstate is the operator-state push of design 5.1.4: the host binary sends an enumerated
// set of files from ~/.sandbox to /var/lib/sandbox/operator in the VM before each proxied command.
// The set is an allowlist in code, never "the whole directory". Both halves live here: Build (host)
// and Receive (VM). The archive is a tar stream of regular files only, with strict names and size
// caps; each managed item is replaced whole in the VM, and anything else there is left alone.
//
// Not yet pushed (they need the broker and per-session bindings): secrets, agent tokens during
// onboarding, linked overlay checkouts, and a session's infra kubeconfigs and tokens.
package opstate

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Item is one managed path under ~/.sandbox: a file, or a directory pushed whole.
type Item struct {
	Name string
	Dir  bool
}

// Managed is the pushed set.
var Managed = []Item{{"config.yaml", false}, {"profiles", true}, {"vetting", true}, {"extra-ca-certs", true}, {"egress-rules.yaml", false}}

// Limits.
const (
	MaxFile  = 1 << 20
	MaxTotal = 16 << 20
	MaxFiles = 2000
	MaxDepth = 8
)

func managed(name string) (Item, bool) {
	top, _, _ := strings.Cut(name, "/")
	for _, it := range Managed {
		if it.Name == top && (it.Dir || name == top) {
			return it, true
		}
	}
	return Item{}, false
}

// validName: a relative slash path under a managed item, no empty, dot, or hidden-traversal
// component, no control characters, not too deep.
func validName(name string) bool {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") || len(name) > 1024 {
		return false
	}
	parts := strings.Split(name, "/")
	if len(parts) > MaxDepth {
		return false
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return false
		}
		for _, r := range p {
			if r < 0x20 || r == 0x7f {
				return false
			}
		}
	}
	_, ok := managed(name)
	return ok
}

// Build collects the managed set from stateDir (~/.sandbox) into a tar stream. A symlink or other
// non-regular file is left out with a warning (the push never follows links); a missing item is
// simply absent, which tells the VM to remove its copy.
func Build(stateDir string) ([]byte, []string, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	var warnings []string
	total, count := 0, 0
	add := func(rel string, b []byte) error {
		count++
		total += len(b)
		if count > MaxFiles || total > MaxTotal {
			return fmt.Errorf("operator state is larger than %d files or %d bytes", MaxFiles, MaxTotal)
		}
		if err := tw.WriteHeader(&tar.Header{Name: rel, Mode: 0o600, Size: int64(len(b)), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	readFile := func(full, rel string, st fs.FileInfo) error {
		if !st.Mode().IsRegular() {
			warnings = append(warnings, fmt.Sprintf("not pushed to the VM (not a regular file): ~/.sandbox/%s", rel))
			return nil
		}
		if st.Size() > MaxFile {
			warnings = append(warnings, fmt.Sprintf("not pushed to the VM (larger than %d bytes): ~/.sandbox/%s", MaxFile, rel))
			return nil
		}
		if !validName(rel) {
			warnings = append(warnings, fmt.Sprintf("not pushed to the VM (name): ~/.sandbox/%s", rel))
			return nil
		}
		b, err := os.ReadFile(full)
		if err != nil {
			return err
		}
		return add(rel, b)
	}
	for _, it := range Managed {
		full := filepath.Join(stateDir, it.Name)
		st, err := os.Lstat(full)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if !it.Dir {
			if err := readFile(full, it.Name, st); err != nil {
				return nil, nil, err
			}
			continue
		}
		if !st.IsDir() {
			warnings = append(warnings, fmt.Sprintf("not pushed to the VM (not a directory): ~/.sandbox/%s", it.Name))
			continue
		}
		var files []string
		err = filepath.WalkDir(full, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type()&fs.ModeSymlink != 0 {
				rel, _ := filepath.Rel(stateDir, p)
				warnings = append(warnings, "not pushed to the VM (a symlink): ~/.sandbox/"+filepath.ToSlash(rel))
				return nil
			}
			if !d.IsDir() {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
		sort.Strings(files)
		for _, p := range files {
			st, err := os.Lstat(p)
			if err != nil {
				return nil, nil, err
			}
			rel, _ := filepath.Rel(stateDir, p)
			if err := readFile(p, filepath.ToSlash(rel), st); err != nil {
				return nil, nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), warnings, nil
}

// Receive reads a pushed archive (at most MaxTotal plus framing from r) and installs it under
// dest: every managed item is replaced whole by its pushed version (removed when absent), files
// 0600 and directories 0700, through a staging directory and renames. Anything else in dest stays.
func Receive(r io.Reader, dest string) error {
	files := map[string][]byte{}
	tr := tar.NewReader(io.LimitReader(r, MaxTotal+MaxFiles*2048+1<<16))
	total := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("operator state: %w", err)
		}
		if h.Typeflag != tar.TypeReg || !validName(h.Name) || h.Size < 0 || h.Size > MaxFile {
			return fmt.Errorf("operator state: refused entry %q", h.Name)
		}
		if _, dup := files[h.Name]; dup || len(files) >= MaxFiles {
			return fmt.Errorf("operator state: repeated entry or too many files at %q", h.Name)
		}
		total += int(h.Size)
		if total > MaxTotal {
			return errors.New("operator state: too large")
		}
		b, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil || int64(len(b)) != h.Size {
			return fmt.Errorf("operator state: short entry %q", h.Name)
		}
		files[h.Name] = b
	}
	// a file item and a directory item cannot both be claimed by one name
	for n := range files {
		for m := range files {
			if strings.HasPrefix(m, n+"/") {
				return fmt.Errorf("operator state: %q is both a file and a directory", n)
			}
		}
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	var rb [6]byte
	rand.Read(rb[:])
	stage := filepath.Join(dest, ".incoming-"+hex.EncodeToString(rb[:]))
	if err := os.Mkdir(stage, 0o700); err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	for name, b := range files {
		p := filepath.Join(stage, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return err
		}
	}
	for _, it := range Managed {
		final := filepath.Join(dest, it.Name)
		old := filepath.Join(stage, ".old-"+it.Name)
		if _, err := os.Lstat(final); err == nil {
			if err := os.Rename(final, old); err != nil {
				return err
			}
		}
		if _, err := os.Lstat(filepath.Join(stage, it.Name)); err == nil {
			if err := os.Rename(filepath.Join(stage, it.Name), final); err != nil {
				return err
			}
		}
	}
	return nil
}
