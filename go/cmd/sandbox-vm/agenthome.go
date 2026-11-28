package main

// The homes of the agents whose login cannot be brokered (OQ-01; cli.setUpAgentHome): one per
// agent and tier under sessionspec.AgentHomeStore, owned by the agent's user, which its sessions
// mount writable. The agent controls what is inside between launches (another of its sessions at
// the tier may be running), so nothing here follows a link: paths are checked with Lstat and files
// are created exclusively, without following, then renamed into place.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/samaritanark/agent-sandboxes/go/internal/agents"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// maxHomeFile bounds a settings file read from an agent home.
const maxHomeFile = 1 << 20

func prepareAgentHome(store string, uid int) func(string, int, map[string][]byte) ([]string, error) {
	return func(agent string, tier int, seed map[string][]byte) ([]string, error) {
		if !sessionspec.Unbrokered[agent] || tier < 1 || tier > 3 {
			return nil, fmt.Errorf("no agent home for %s at tier %d", agent, tier)
		}
		home := filepath.Join(store, agent, "tier"+strconv.Itoa(tier))
		if err := os.MkdirAll(filepath.Dir(home), 0o700); err != nil {
			return nil, err
		}
		for p := filepath.Dir(home); p != filepath.Dir(store); p = filepath.Dir(p) {
			if st, err := os.Lstat(p); err != nil || !st.IsDir() {
				return nil, fmt.Errorf("%s is not a directory", p)
			}
		}
		if err := os.Mkdir(home, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if st, err := os.Lstat(home); err != nil || !st.IsDir() {
			return nil, fmt.Errorf("%s is not a directory", home)
		}
		if err := os.Lchown(home, uid, -1); err != nil {
			return nil, err
		}
		for name, content := range seed {
			if !validFileName(name) {
				return nil, fmt.Errorf("bad seed file name %q", name)
			}
			if _, err := os.Lstat(filepath.Join(home, name)); errors.Is(err, os.ErrNotExist) {
				if err := writeHomeFile(home, name, content, uid); err != nil {
					return nil, err
				}
			}
		}
		if agent != "grok" {
			return nil, nil
		}
		cfg, err := readHomeFile(filepath.Join(home, "config.toml"))
		if err != nil {
			return nil, err
		}
		out, warnings := agents.GrokConfig(cfg)
		if out != nil {
			if err := writeHomeFile(home, "config.toml", out, uid); err != nil {
				return nil, err
			}
		}
		return warnings, nil
	}
}

// validFileName is one path element.
func validFileName(n string) bool {
	return n != "" && n != "." && n != ".." && len(n) <= 255 && filepath.Base(n) == n && !containsNUL(n)
}

func containsNUL(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return true
		}
	}
	return false
}

// readHomeFile reads a regular file (nil when there is none); a link or anything else is refused.
func readHomeFile(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %v", p, err)
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxHomeFile+1))
	if err == nil && len(b) > maxHomeFile {
		err = fmt.Errorf("%s is larger than %d bytes", p, maxHomeFile)
	}
	return b, err
}

// writeHomeFile replaces home/name with content, owned by uid, mode 0600.
func writeHomeFile(home, name string, content []byte, uid int) error {
	tmp := filepath.Join(home, ".sandbox-"+name+".tmp")
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(content)
	if err == nil {
		err = f.Chown(uid, -1)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(home, name))
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}
