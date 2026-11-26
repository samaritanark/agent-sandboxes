package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

const testDigest = "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestBuildSpec: a launch's spec mounts each repository's VM copy at v2's path with its masks and
// read-only exec vectors over it, carries v2's environment and the session's allowlist and block
// lists, sizes the agent as v2's pod, and passes sandboxd's own checks.
func TestBuildSpec(t *testing.T) {
	home := t.TempDir()
	e := fixtureEnv("full", home, "", nil)
	e.OrgBlockList = filepath.Join(home, "org.yaml")
	os.WriteFile(e.OrgBlockList, []byte("blocked_domains:\n  - \"*.pastebin.com\"\nblocked_cidrs:\n  - 169.254.0.0/16\n"), 0o644)
	copies := map[string]string{}
	ids := map[string]string{"app": "0123456789abcdef", "lib": "fedcba9876543210"}
	for _, r := range []string{"app", "lib"} {
		d := filepath.Join(home, "copies", ids[r])
		os.MkdirAll(filepath.Join(d, ".git", "hooks"), 0o755)
		os.WriteFile(filepath.Join(d, ".git", "config"), nil, 0o644)
		os.WriteFile(filepath.Join(d, ".env"), []byte("X=1"), 0o644)
		copies["/host/code/"+r] = d
	}
	c := &cmdCtx{env: e}
	s := LaunchSpec{Agent: "claude", Tier: "2", Name: "multi/claude", Repos: []string{"/host/code/app", "/host/code/lib"}, KeepAlive: true, Profile: "dev"}
	rec := SessionRecord{ID: "ses-20261126-101500-ab12", PodName: "sandbox-multi-claude-ab12", Policy: PolicyRequest{Extras: []string{"example.org", "*.example.net"}}}
	spec, err := c.buildSpec(s, rec, SpecInputs{Image: "docker.io/library/sandbox" + testDigest,
		WorkspaceCopy: func(r string) (string, error) { return copies[r], nil }})
	if err != nil {
		t.Fatal(err)
	}
	var ms []string
	for _, m := range spec.Mounts {
		ms = append(ms, string(m.Kind)+" "+strings.TrimPrefix(m.Source, home)+" "+m.Target)
	}
	want := []string{
		"workspace /copies/0123456789abcdef /workspace/app", "mask-file  /workspace/app/.env",
		"readonly /copies/0123456789abcdef/.git/config /workspace/app/.git/config", "readonly /copies/0123456789abcdef/.git/hooks /workspace/app/.git/hooks",
		"workspace /copies/fedcba9876543210 /workspace/lib", "mask-file  /workspace/lib/.env",
		"readonly /copies/fedcba9876543210/.git/config /workspace/lib/.git/config", "readonly /copies/fedcba9876543210/.git/hooks /workspace/lib/.git/hooks",
	}
	if strings.Join(ms, "\n") != strings.Join(want, "\n") {
		t.Errorf("mounts\n%s\nwant\n%s", strings.Join(ms, "\n"), strings.Join(want, "\n"))
	}
	allow := strings.Join(spec.Egress.Allow, " ")
	if !strings.Contains(allow, "api.anthropic.com") || !strings.HasSuffix(allow, "example.org *.example.net example.net") {
		t.Errorf("allow %s", allow)
	}
	if strings.Join(spec.Egress.BlockDomains, " ") != "*.pastebin.com" || strings.Join(spec.Egress.BlockCIDRs, " ") != "169.254.0.0/16" {
		t.Errorf("block %+v", spec.Egress)
	}
	if spec.Name != "sandbox-multi-claude-ab12" || spec.Audit["name"] != "multi/claude" || spec.Audit["profile"] != "dev" || !spec.KeepAlive || spec.Tier != 2 {
		t.Errorf("%+v", spec)
	}
	if spec.Resources.MemoryMiB != 6144 || spec.Resources.CPUs != 4 || strings.Join(spec.Command, " ") != "sleep infinity" {
		t.Errorf("%+v %q", spec.Resources, spec.Command)
	}
	var env []string
	for _, v := range spec.Env {
		env = append(env, v.Name+"="+v.Value)
	}
	if strings.Join(env, " ") != "HOME=/home/agent TERM=xterm-256color COLORTERM=truecolor CLAUDE_CONFIG_DIR=/home/agent/.claude" {
		t.Errorf("env %q", env)
	}
	// sandboxd accepts it once the copies are where the sync engine keeps them
	for i := range spec.Mounts {
		if spec.Mounts[i].Source != "" {
			spec.Mounts[i].Source = strings.Replace(spec.Mounts[i].Source, home+"/copies/", sessionspec.WorkspaceStore+"/", 1)
		}
	}
	if err := spec.Validate(sessionspec.Options{}); err != nil {
		t.Errorf("sandboxd refuses it: %v", err)
	}
	if n := specName(strings.Repeat("ab-", 30)); len(n) != 62 || strings.HasSuffix(n, "-") {
		t.Errorf("long name %q", n)
	}
	if n := strings.Repeat("a", 64); len(specName(n)) != 63 {
		t.Errorf("64 bytes kept: %q", specName(n))
	}
	if n := strings.Repeat("a", 63); specName(n) != n {
		t.Errorf("63 bytes cut: %q", specName(n))
	}
}

func TestAgentMemory(t *testing.T) {
	dep := func(mem int) sessionspec.Dependency {
		return sessionspec.Dependency{Resources: sessionspec.Resources{MemoryMiB: mem}}
	}
	for _, c := range []struct {
		vm   int
		deps []sessionspec.Dependency
		want int
	}{
		{0, nil, 6144},     // unknown: v2's limit
		{7936, nil, 5632},  // an 8 GiB VM's MemTotal, less 2048 and 256
		{16384, nil, 6144}, // capped
		{7936, []sessionspec.Dependency{dep(512)}, 4864}, // 5632 - 768
	} {
		if got := agentMemory(c.vm, c.deps); got != c.want {
			t.Errorf("agentMemory(%d, %d deps) = %d, want %d", c.vm, len(c.deps), got, c.want)
		}
	}
}

func TestQuantities(t *testing.T) {
	for q, want := range map[string]float64{"1": 1, "250m": 0.25, "2000m": 2} {
		if got, err := cpus(q); err != nil || got != want {
			t.Errorf("%s: %v %v", q, got, err)
		}
	}
	for q, want := range map[string]int{"512Mi": 512, "1Gi": 1024} {
		if got, err := mebibytes(q); err != nil || got != want {
			t.Errorf("%s: %v %v", q, got, err)
		}
	}
	for _, q := range []string{"", "1.5", "-1", "1Gi", "m", "x1"} {
		if _, err := cpus(q); err == nil {
			t.Errorf("%q accepted as CPUs", q)
		}
	}
	for _, q := range []string{"", "1", "1.5Gi", "-1Mi", "1Ki", "1G", "x1Mi"} {
		if _, err := mebibytes(q); err == nil {
			t.Errorf("%q accepted as memory", q)
		}
	}
}
