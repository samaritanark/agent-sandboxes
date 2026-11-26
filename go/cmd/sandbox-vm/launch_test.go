package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// TestWorkspaceCopyOf: a repository path that is, or links to, a workspace copy names it; any other
// path is refused.
func TestWorkspaceCopyOf(t *testing.T) {
	root := t.TempDir()
	cp := filepath.Join(root, sessionspec.WorkspaceStore, "0123456789abcdef")
	os.MkdirAll(cp, 0o755)
	os.MkdirAll(filepath.Join(root, "Users/op/code"), 0o755)
	os.Symlink("../../../var/lib/sandbox/workspaces/0123456789abcdef", filepath.Join(root, "Users/op/code/app"))
	os.MkdirAll(filepath.Join(root, "Users/op/code/plain"), 0o755)
	os.MkdirAll(filepath.Join(root, sessionspec.WorkspaceStore, "0123456789abcdef-x"), 0o755)
	f := workspaceCopyOf(root)
	for _, p := range []string{"/Users/op/code/app", sessionspec.WorkspaceStore + "/0123456789abcdef"} {
		if got, err := f(p); err != nil || got != sessionspec.WorkspaceStore+"/0123456789abcdef" {
			t.Errorf("%s: %q %v", p, got, err)
		}
	}
	for _, p := range []string{"/Users/op/code/plain", "/Users/op/code/missing", sessionspec.WorkspaceStore + "/0123456789abcdef-x", sessionspec.WorkspaceStore} {
		if got, err := f(p); err == nil {
			t.Errorf("%s: accepted as %q", p, got)
		}
	}
}

func TestAgentImage(t *testing.T) {
	f := filepath.Join(t.TempDir(), "images.json")
	os.WriteFile(f, []byte(`{"sandbox:claude":"docker.io/library/sandbox@sha256:abc"}`), 0o644)
	if ref, err := agentImage(f)("sandbox:claude"); err != nil || ref != "docker.io/library/sandbox@sha256:abc" {
		t.Errorf("%q %v", ref, err)
	}
	if _, err := agentImage(f)("sandbox:codex"); err == nil || !strings.Contains(err.Error(), "not preloaded") {
		t.Errorf("%v", err)
	}
	if _, err := agentImage(f + ".missing")("sandbox:claude"); err == nil {
		t.Error("no list")
	}
}
