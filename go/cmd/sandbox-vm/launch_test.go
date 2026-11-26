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
	os.WriteFile(f, []byte(`{"sandbox:claude":"docker.io/library/sandbox@sha256:abc","sandbox:codex":"docker.io/library/sandbox@sha256:base"}`), 0o644)
	if ref, err := agentImage(f)("sandbox:claude"); err != nil || ref != "docker.io/library/sandbox@sha256:abc" {
		t.Errorf("%q %v", ref, err)
	}
	if _, err := agentImage(f)("sandbox:grok"); err == nil || !strings.Contains(err.Error(), "neither preloaded") {
		t.Errorf("%v", err)
	}
	if _, err := agentImage(f + ".missing")("sandbox:claude"); err == nil || !strings.Contains(err.Error(), "sandbox rebuild") {
		t.Errorf("no list: %v", err)
	}
	// the VM's own builds come first, then the image's baseline
	built := filepath.Join(t.TempDir(), "built.json")
	os.WriteFile(built, []byte(`{"sandbox:claude":"docker.io/library/sandbox@sha256:new"}`), 0o644)
	look := agentImage(built, f)
	if ref, _ := look("sandbox:claude"); ref != "docker.io/library/sandbox@sha256:new" {
		t.Errorf("built not first: %q", ref)
	}
	if ref, _ := look("sandbox:codex"); ref != "docker.io/library/sandbox@sha256:base" {
		t.Errorf("baseline: %q", ref)
	}
	os.WriteFile(built, []byte(`{`), 0o644)
	if _, err := look("sandbox:claude"); err == nil {
		t.Error("a broken map read")
	}
}

func TestWriteMCPConfig(t *testing.T) {
	store := t.TempDir()
	w := writeMCPConfig(store)
	dir, err := w("ses-20261126-213445-5114", []byte(`{"mcpServers":{}}`))
	if err != nil || dir != filepath.Join(store, "ses-20261126-213445-5114", "mcp") {
		t.Fatalf("%q %v", dir, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	st, _ := os.Stat(filepath.Join(dir, "config.json"))
	if string(b) != `{"mcpServers":{}}` || st.Mode().Perm() != 0o644 {
		t.Errorf("%q %v", b, st.Mode())
	}
	if _, err := w("../etc", nil); err == nil {
		t.Error("a path as a session id")
	}
	// a link planted where the directory goes is refused
	os.MkdirAll(filepath.Join(store, "ses-20261126-213445-0000"), 0o700)
	os.Symlink(t.TempDir(), filepath.Join(store, "ses-20261126-213445-0000", "mcp"))
	if _, err := w("ses-20261126-213445-0000", nil); err == nil {
		t.Error("wrote through a link")
	}
}
