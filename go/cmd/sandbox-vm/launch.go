package main

// run's launch through sandboxd (design 5.4.3): the session spec goes to sandboxd's socket, the
// terminal attaches through it, and the pinned agent images and workspace copies are the VM's.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/agents"
	"github.com/samaritanark/agent-sandboxes/go/internal/cli"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/attachclient"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/daemon"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/limits"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// AgentImages lists the image's preloaded agent images by tag, each pinned by digest (design 5.3:
// the tested baseline ships in the image).
const AgentImages = "/usr/lib/sandbox/agent-images.json"

type sandboxd struct{}

func call(req daemon.Request) error {
	resp, err := daemon.Call(context.Background(), daemon.Socket, req)
	if err != nil {
		return fmt.Errorf("cannot reach sandboxd: %w", err)
	}
	if !resp.OK {
		return errors.New(strings.TrimSpace(resp.Error))
	}
	return nil
}

func (sandboxd) Start(spec *sessionspec.Spec) error {
	b, err := spec.Encode()
	if err != nil {
		return err
	}
	return call(daemon.Request{Op: "start", Spec: b})
}

func (sandboxd) Attach(id string, cmd []string) (int, error) {
	return attachclient.Attach(daemon.Socket, id, cmd)
}

func (sandboxd) List() ([]cli.SessionState, error) {
	resp, err := daemon.Call(context.Background(), daemon.Socket, daemon.Request{Op: "list"})
	if err != nil {
		return nil, fmt.Errorf("cannot reach sandboxd: %w", err)
	}
	if !resp.OK {
		return nil, errors.New(strings.TrimSpace(resp.Error))
	}
	var out []cli.SessionState
	for _, s := range resp.Sessions {
		if !s.State.Ended() {
			out = append(out, cli.SessionState{ID: s.ID, State: string(s.State)})
		}
	}
	return out, nil
}

func (sandboxd) Live(id string) (bool, error) {
	resp, err := daemon.Call(context.Background(), daemon.Socket, daemon.Request{Op: "list"})
	if err != nil {
		return false, fmt.Errorf("cannot reach sandboxd: %w", err)
	}
	if !resp.OK {
		return false, errors.New(strings.TrimSpace(resp.Error))
	}
	for _, s := range resp.Sessions {
		if s.ID == id {
			return !s.State.Ended(), nil
		}
	}
	return false, nil
}

func (sandboxd) Stop(id, reason string) error {
	return call(daemon.Request{Op: "stop", ID: id, Reason: reason})
}

// agentImage reads tag's pinned reference from AgentImages.
func agentImage(files ...string) func(string) (string, error) {
	return func(tag string) (string, error) {
		var errs []string
		for _, file := range files {
			b, err := os.ReadFile(file)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return "", err
			}
			var m map[string]string
			if err := json.Unmarshal(b, &m); err != nil {
				return "", fmt.Errorf("%s: %v", file, err)
			}
			if ref, ok := m[tag]; ok {
				return ref, nil
			}
			errs = append(errs, file)
		}
		if len(errs) == 0 {
			return "", errors.New("this VM has no agent images yet; build them with: sandbox rebuild")
		}
		return "", fmt.Errorf("%s is neither preloaded in this image nor built in this VM (sandbox rebuild --agent ...)", tag)
	}
}

var workspaceCopy = regexp.MustCompile(`^` + regexp.QuoteMeta(sessionspec.WorkspaceStore) + `/[0-9a-f]{16}$`)

// workspaceCopyOf is the sync engine's copy a repository path names in the VM: the copy itself, or
// a link to it (the host links each synced repository's host path to its copy).
func workspaceCopyOf(root string) func(string) (string, error) {
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	return func(repo string) (string, error) {
		p, err := filepath.EvalSymlinks(filepath.Join(root, repo))
		if err == nil {
			if root != "/" {
				p = strings.TrimPrefix(p, root)
			}
		}
		if err != nil || !workspaceCopy.MatchString(p) {
			return "", fmt.Errorf("%s has no workspace copy in the sandbox VM; the host syncs each repository before 'run'", repo)
		}
		return p, nil
	}
}

// vmMemory is the VM's memory, which the agent's default limit scales with.
func vmMemory() (int, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return limits.MemTotalMiB(f)
}

// writeMCPConfig writes a session's MCP configuration under sandboxd's directory for it
// (sessionspec.SessionStore/<id>/mcp/config.json), where the spec mounts it read-only.
func writeMCPConfig(store string) func(string, []byte) (string, error) {
	return func(id string, content []byte) (string, error) {
		if !sessionID.MatchString(id) {
			return "", fmt.Errorf("not a session id: %q", id)
		}
		sess := filepath.Join(store, id)
		if err := os.MkdirAll(sess, 0o700); err != nil {
			return "", err
		}
		dir := filepath.Join(sess, daemon.MCPDir)
		if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return "", err
		}
		if st, err := os.Lstat(dir); err != nil || !st.IsDir() {
			return "", fmt.Errorf("%s is not a directory", dir)
		}
		tmp := filepath.Join(dir, ".config.json.tmp")
		if err := os.WriteFile(tmp, content, 0o644); err != nil {
			return "", err
		}
		return dir, os.Rename(tmp, filepath.Join(dir, agents.MCPConfigFile))
	}
}

var sessionID = regexp.MustCompile(`^ses-[0-9]{8}-[0-9]{6}-[0-9a-f]{4}$`)

// writeAgentFiles stages a session's agent configuration (a writable copy, owned by the agent's
// user) in sandboxd's directory for the session, and makes its history directory: the session's own
// at tier 1, else the agent's for this tier and repository set (sessionspec.HistoryPath).
func writeAgentFiles(store, historyStore string, uid int) func(string, cli.AgentFiles) error {
	return func(id string, f cli.AgentFiles) error {
		if !sessionID.MatchString(id) || !agentName.MatchString(f.Agent) {
			return fmt.Errorf("bad session %q or agent %q", id, f.Agent)
		}
		sess := filepath.Join(store, id)
		if err := os.MkdirAll(sess, 0o700); err != nil {
			return err
		}
		dir := filepath.Join(sess, cli.AgentConfigDir)
		if err := freshDir(dir, uid); err != nil {
			return err
		}
		for name, content := range f.Config {
			if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
				return fmt.Errorf("bad configuration file name %q", name)
			}
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, content, 0o600); err != nil {
				return err
			}
			if err := os.Lchown(p, uid, -1); err != nil {
				return err
			}
		}
		history := filepath.Join(sess, cli.SessionHistoryDir)
		if f.HistoryKey != "" {
			var err error
			if history, err = historyDir(historyStore, f.Agent, f.Tier, f.HistoryKey, uid); err != nil {
				return err
			}
			return nil
		}
		if err := os.Mkdir(history, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		st, err := os.Lstat(history)
		if err != nil || !st.IsDir() {
			return fmt.Errorf("%s is not a directory", history)
		}
		return os.Lchown(history, uid, -1)
	}
}

// freshDir makes dir empty and owned by uid (a leftover is removed first, never followed).
func freshDir(dir string, uid int) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	return os.Lchown(dir, uid, -1)
}

var (
	agentName    = regexp.MustCompile(`^[a-z]{1,16}$`)
	historyKeyRE = regexp.MustCompile(`^[0-9a-f]{16,64}$`)
)

// refreshCredential has sandboxd renew an agent's OAuth login and returns its expiry.
func refreshCredential(ref string) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	resp, err := daemon.Call(ctx, daemon.Socket, daemon.Request{Op: "broker-refresh", ID: ref})
	if err == nil && !resp.OK {
		err = errors.New(resp.Error)
	}
	return resp.Exp, err
}

// historyDir makes (if needed) agent's history directory for tier and repository-set key under
// historyStore, owned by uid, with no link anywhere below the store, and returns it.
func historyDir(historyStore, agent string, tier int, key string, uid int) (string, error) {
	if !agentName.MatchString(agent) || !historyKeyRE.MatchString(key) || tier < 2 || tier > 3 {
		return "", fmt.Errorf("bad history key %q for %s at tier %d", key, agent, tier)
	}
	history := filepath.Join(historyStore, agent, "tier"+strconv.Itoa(tier), key)
	if err := os.MkdirAll(filepath.Dir(history), 0o700); err != nil {
		return "", err
	}
	for p := filepath.Dir(history); p != historyStore; p = filepath.Dir(p) {
		if st, err := os.Lstat(p); err != nil || !st.IsDir() {
			return "", fmt.Errorf("%s is not a directory", p)
		}
	}
	if err := os.Mkdir(history, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	if st, err := os.Lstat(history); err != nil || !st.IsDir() {
		return "", fmt.Errorf("%s is not a directory", history)
	}
	return history, os.Lchown(history, uid, -1)
}
