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
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/cli"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/attachclient"
	"github.com/samaritanark/agent-sandboxes/go/internal/sandboxd/daemon"
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
func agentImage(file string) func(string) (string, error) {
	return func(tag string) (string, error) {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("this image lists no preloaded agent images (%v)", err)
		}
		var m map[string]string
		if err := json.Unmarshal(b, &m); err != nil {
			return "", fmt.Errorf("%s: %v", file, err)
		}
		ref, ok := m[tag]
		if !ok {
			return "", fmt.Errorf("%s is not preloaded in this image", tag)
		}
		return ref, nil
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
