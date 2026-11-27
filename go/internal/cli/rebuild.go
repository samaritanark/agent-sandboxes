package cli

// `sandbox rebuild` (v2's cmd_rebuild) in the appliance VM: v2's Dockerfiles built with nerdctl and
// buildkit into the containerd namespace sandboxd runs sessions from (design 5.3.1, OQ-11), each
// result pinned by digest in the VM's own agent image map, which run reads before the image's
// baseline. v2's flags and order are kept. Two changes: a build's record in image-builds.log is
// its digest rather than the harness's --version (v2 ran the new image under runc outside any
// microVM to ask it; here nothing the build fetched runs outside a session), and the builder line
// names the VM's containerd.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ImageBuilder builds agent images in the VM (sandbox-vm's nerdctl and buildkit).
type ImageBuilder interface {
	// Build builds tag from dockerfile in dir with the extra build arguments, its output going to
	// out, and returns the image's digest.
	Build(tag, dir, dockerfile string, args []string, noCache bool, out io.Writer) (digest string, err error)
	// Pin makes tag's agent image the one run uses (the VM's image map), by digest.
	Pin(tag, digest string) error
	// Exists is whether the image store has tag (the base the agent images build on).
	Exists(tag string) bool
}

var rebuildVersion = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$`)

func cmdRebuild(c *cmdCtx, args []string) {
	agent, tier3, noCache := "all", false, false
	versions := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		val := func(flag string) (string, bool) {
			if v, ok := strings.CutPrefix(a, flag+"="); ok {
				return v, true
			}
			if a != flag {
				return "", false
			}
			if i+1 >= len(args) || args[i+1] == "" {
				c.die("%s requires a value", flag)
			}
			i++
			return args[i], true
		}
		if v, ok := val("--agent"); ok {
			agent = v
			continue
		}
		matched := false
		for _, f := range []string{"--codex-version", "--opencode-version", "--copilot-version", "--grok-version"} {
			if v, ok := val(f); ok {
				if !rebuildVersion.MatchString(v) {
					c.die("%s: '%s' is not a version.", f, v)
				}
				versions[f], matched = v, true
			}
		}
		switch {
		case matched:
		case a == "--tier3":
			tier3 = true
		case a == "--no-cache":
			noCache = true
		case a == "--help" || a == "-h":
			c.usage("usage_rebuild")
		default:
			c.die("Unknown option: %s (run 'sandbox rebuild --help')", a)
		}
	}
	switch agent {
	case "claude", "codex", "opencode", "copilot", "grok", "shell", "base", "all":
	default:
		c.die("Invalid --agent: %s (must be claude, codex, opencode, copilot, grok, shell, base, or all)", agent)
	}
	b := c.env.Builder
	if b == nil {
		c.die("'rebuild' needs the sandbox VM's image builder; run it through the host's sandbox command.")
	}
	dockerDir := filepath.Join(c.env.SandboxRoot, "docker")
	logsDir := c.env.LogsDir
	os.MkdirAll(logsDir, 0o755)
	buildLog := filepath.Join(logsDir, "image-builds.log")

	c.out("==> Rebuilding sandbox image(s): %s", agent)
	c.out("    Builder:  nerdctl + buildkit (into the sandbox VM's containerd)")
	c.out("    No-cache: %v", noCache)
	c.out("    Tier 3:   %v", tier3)
	c.out("")

	one := func(tag, dockerfile string, extra ...string) {
		if _, err := os.Stat(filepath.Join(dockerDir, dockerfile)); err != nil {
			c.die("Dockerfile not found: %s", filepath.Join(dockerDir, dockerfile))
		}
		c.out("==> Building %s (%s)", tag, dockerfile)
		digest, err := b.Build(tag, dockerDir, dockerfile, extra, noCache, c.stdout)
		if err != nil {
			c.die("building %s failed: %v", tag, err)
		}
		if err := b.Pin(tag, digest); err != nil {
			c.die("could not record %s for sessions: %v", tag, err)
		}
		if f, err := os.OpenFile(buildLog, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644); err == nil {
			fmt.Fprintf(f, "%s  %s  %s\n", c.stamp(), tag, digest)
			f.Close()
		}
		c.out("    Recorded: %s → %s", tag, digest)
	}
	arg := func(flag, name string) []string {
		if v := versions[flag]; v != "" {
			return []string{"--build-arg", name + "=" + v}
		}
		return nil
	}
	is := func(n string) bool { return agent == n || agent == "all" }
	// the agent images build FROM sandbox:base; without it buildkit looks for it on Docker Hub
	if agent != "base" && agent != "all" && !b.Exists("docker.io/library/sandbox:base") {
		c.die("The base image is not built yet; the agent images build on it. Run first: sandbox rebuild --agent base")
	}
	if is("base") {
		one("docker.io/library/sandbox:base", "Dockerfile.base")
	}
	if is("claude") {
		one("docker.io/library/sandbox:claude", "Dockerfile.claude", "--build-arg", "CLAUDE_CODE_INSTALL_REV="+c.now().Format("20060102150405"))
	}
	if is("codex") {
		one("docker.io/library/sandbox:codex", "Dockerfile.codex", arg("--codex-version", "CODEX_VERSION")...)
	}
	if is("opencode") {
		one("docker.io/library/sandbox:opencode", "Dockerfile.opencode", arg("--opencode-version", "OPENCODE_VERSION")...)
	}
	if is("copilot") {
		one("docker.io/library/sandbox:copilot", "Dockerfile.copilot", arg("--copilot-version", "COPILOT_CLI_VERSION")...)
	}
	if is("grok") {
		one("docker.io/library/sandbox:grok", "Dockerfile.grok", arg("--grok-version", "GROK_CLI_VERSION")...)
	}
	if is("shell") {
		one("docker.io/library/sandbox:shell", "Dockerfile.shell")
	}
	if tier3 || agent == "all" {
		for _, a := range []string{"claude", "codex", "opencode", "copilot", "grok"} {
			if is(a) {
				one("docker.io/library/sandbox:"+a+"-infra", "Dockerfile.infra", "--build-arg", "BASE_IMAGE=sandbox:"+a)
			}
		}
	}
	c.out("")
	c.out("==> Rebuild complete. Build log: %s", buildLog)
}
