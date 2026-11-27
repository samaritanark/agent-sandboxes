package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeBuilder struct {
	built  []string
	pinned []string
	noBase bool
}

func (f *fakeBuilder) Exists(tag string) bool { return !f.noBase }

func (f *fakeBuilder) Build(tag, dir, dockerfile string, args []string, noCache bool, _ io.Writer) (string, error) {
	f.built = append(f.built, strings.TrimSpace(tag+" "+dockerfile+" "+strings.Join(args, " ")+map[bool]string{true: " nocache"}[noCache]))
	return "sha256:" + strings.Repeat("0", 64), nil
}

func (f *fakeBuilder) Pin(tag, digest string) error { f.pinned = append(f.pinned, tag); return nil }

// TestRebuild: v2's order and arguments, each build pinned and logged; bad flags refused.
func TestRebuild(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "docker"), 0o755)
	for _, f := range []string{"base", "claude", "codex", "opencode", "copilot", "grok", "shell", "infra"} {
		os.WriteFile(filepath.Join(root, "docker", "Dockerfile."+f), nil, 0o644)
	}
	run := func(args ...string) (int, *fakeBuilder, string, string) {
		fb := &fakeBuilder{}
		e := Env{SandboxRoot: root, LogsDir: filepath.Join(root, "logs"), Builder: fb, Now: func() int64 { return 1800000000 }}
		var out, errb bytes.Buffer
		rc := Run(append([]string{"rebuild"}, args...), e, &out, &errb)
		return rc, fb, out.String(), errb.String()
	}
	rc, fb, out, _ := run("--agent", "codex", "--codex-version", "0.2.1", "--tier3", "--no-cache")
	want := []string{"docker.io/library/sandbox:codex Dockerfile.codex --build-arg CODEX_VERSION=0.2.1 nocache",
		"docker.io/library/sandbox:codex-infra Dockerfile.infra --build-arg BASE_IMAGE=sandbox:codex nocache"}
	if rc != 0 || strings.Join(fb.built, "\n") != strings.Join(want, "\n") || len(fb.pinned) != 2 {
		t.Fatalf("%d %q %q", rc, fb.built, out)
	}
	if !strings.Contains(out, "==> Rebuild complete. Build log: "+filepath.Join(root, "logs", "image-builds.log")) {
		t.Errorf("%q", out)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "logs", "image-builds.log")); !strings.HasPrefix(string(b), "2027-01-15T08:00:00Z  docker.io/library/sandbox:codex  sha256:") {
		t.Errorf("log %q", b)
	}
	_, fb, _, _ = run()
	if len(fb.built) != 12 || !strings.HasPrefix(fb.built[0], "docker.io/library/sandbox:base ") ||
		fb.built[1] != "docker.io/library/sandbox:claude Dockerfile.claude --build-arg CLAUDE_CODE_INSTALL_REV=20270115080000" {
		t.Errorf("all: %q", fb.built)
	}
	for _, c := range [][]string{{"--agent", "nope"}, {"--bogus"}, {"--grok-version", "1;rm"}, {"--agent"}} {
		if rc, fb, _, errs := run(c...); rc != 1 || len(fb.built) != 0 || !strings.Contains(errs, "ERROR") {
			t.Errorf("%v: %d %q", c, rc, errs)
		}
	}
	// no base yet: an agent alone is refused with what to run; base and all build it first
	nb := &fakeBuilder{noBase: true}
	var errb bytes.Buffer
	if rc := Run([]string{"rebuild", "--agent", "claude"}, Env{SandboxRoot: root, LogsDir: t.TempDir(), Builder: nb, Now: func() int64 { return 0 }}, io.Discard, &errb); rc != 1 ||
		len(nb.built) != 0 || !strings.Contains(errb.String(), "sandbox rebuild --agent base") {
		t.Errorf("no base: %d %q %q", rc, nb.built, errb.String())
	}
	if rc := Run([]string{"rebuild", "--agent", "base"}, Env{SandboxRoot: root, LogsDir: t.TempDir(), Builder: nb, Now: func() int64 { return 0 }}, io.Discard, io.Discard); rc != 0 || len(nb.built) != 1 {
		t.Errorf("base: %d %q", rc, nb.built)
	}
	if rc := Run([]string{"rebuild"}, Env{SandboxRoot: root}, io.Discard, io.Discard); rc != 1 {
		t.Error("ran without a builder")
	}
}
