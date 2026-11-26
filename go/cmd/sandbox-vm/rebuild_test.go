package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNerdctlBuilder: a build runs nerdctl in sandboxd's namespace, reads the digest from the
// image store, and the pin tags the image by digest and records it under its short tag.
func TestNerdctlBuilder(t *testing.T) {
	const dg = "sha256:" + "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"
	var calls []string
	ls := "REF TYPE DIGEST SIZE PLATFORMS LABELS\ndocker.io/library/sandbox:claude application/vnd.oci.image.manifest.v1+json " + dg + " 1.0 GiB linux/arm64 -\n" +
		"docker.io/library/sandbox:claude-infra application/vnd.oci.image.manifest.v1+json sha256:" + strings.Repeat("9", 64) + " 1.0 GiB linux/arm64 -\n"
	b := nerdctlBuilder{mapFile: filepath.Join(t.TempDir(), "agent-images.json"),
		run: func(n string, a []string, _ io.Writer) error {
			calls = append(calls, n+" "+strings.Join(a, " "))
			return nil
		},
		output: func(n string, a []string) (string, error) {
			calls = append(calls, n+" "+strings.Join(a, " "))
			return ls, nil
		}}
	got, err := b.Build("docker.io/library/sandbox:claude", "/d", "Dockerfile.claude", []string{"--build-arg", "X=1"}, true, io.Discard)
	if err != nil || got != dg {
		t.Fatalf("%q %v", got, err)
	}
	if calls[0] != "nerdctl --namespace sandbox build --no-cache -t docker.io/library/sandbox:claude -f /d/Dockerfile.claude --build-arg X=1 /d" ||
		calls[1] != "ctr --namespace sandbox images ls name==docker.io/library/sandbox:claude" {
		t.Errorf("calls %q", calls)
	}
	os.WriteFile(b.mapFile, []byte(`{"sandbox:codex":"docker.io/library/sandbox@sha256:old"}`), 0o644)
	if err := b.Pin("docker.io/library/sandbox:claude", dg); err != nil {
		t.Fatal(err)
	}
	if calls[2] != "ctr --namespace sandbox images tag --force docker.io/library/sandbox:claude docker.io/library/sandbox@"+dg {
		t.Errorf("tag %q", calls[2])
	}
	var m map[string]string
	raw, _ := os.ReadFile(b.mapFile)
	json.Unmarshal(raw, &m)
	if m["sandbox:claude"] != "docker.io/library/sandbox@"+dg || m["sandbox:codex"] == "" {
		t.Errorf("map %v", m)
	}
	if ref, _ := agentImage(b.mapFile)("sandbox:claude"); ref != "docker.io/library/sandbox@"+dg {
		t.Errorf("run would not find it: %q", ref)
	}
	// no digest, or a bad one: refused
	b.output = func(string, []string) (string, error) { return "REF TYPE DIGEST\n", nil }
	if _, err := b.Build("docker.io/library/sandbox:claude", "/d", "Dockerfile.claude", nil, false, io.Discard); err == nil {
		t.Error("no digest accepted")
	}
	if err := b.Pin("docker.io/library/sandbox:claude", "sha256:short"); err == nil {
		t.Error("bad digest pinned")
	}
	if _, short, ok := splitTag("docker.io/library/sandbox:claude-infra"); !ok || short != "sandbox:claude-infra" {
		t.Errorf("short %q", short)
	}
	if _, _, ok := splitTag("localhost:5000/x"); ok {
		t.Error("a port read as a tag")
	}
}
