package cli

// The launch half of `sandbox run` (cmd_run Steps 8 to 12): in v2 the CLI applied a network policy
// and a pod, waited for it, attached with `kubectl exec -it`, and tore the session down when the
// attach ended. In v3 it hands sandboxd one session spec and attaches through it; sandboxd builds
// the session (network, gateway, microVMs) and holds its lease while the terminal is attached.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/agents"
	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// Sessions is sandboxd as run uses it.
type Sessions interface {
	// Start builds the session a spec describes; it returns once the agent's microVM runs.
	Start(spec *sessionspec.Spec) error
	// Attach runs cmd in the session's agent microVM with the CLI's own terminal and returns its
	// exit status.
	Attach(id string, cmd []string) (int, error)
	// Stop ends a session.
	Stop(id, reason string) error
	// Live is whether sandboxd holds the session and it has not ended.
	Live(id string) (bool, error)
	// List is every session sandboxd holds that has not ended, with its state (sandboxd's:
	// REQUESTED, ADMITTED, STARTING, RUNNING, STOPPING, FAILED).
	List() ([]SessionState, error)
}

// SessionState is one session as sandboxd reports it.
type SessionState struct{ ID, State string }

// LaunchEnv is what run needs from the VM to launch: sandboxd, the pinned agent images, and the
// workspace copies. Each is nil in the differential tests, where RunHandoff stands in.
type LaunchEnv struct {
	Sessions Sessions
	// AgentImage is the image an agent's tag names, pinned by digest (the image's preloaded
	// baseline, design 5.3).
	AgentImage func(tag string) (string, error)
	// WorkspaceCopy is the VM copy of a repository the run names (design 5.6).
	WorkspaceCopy func(repo string) (string, error)
	// VMMemoryMiB is the VM's memory, which the agent's default limit scales with; nil means
	// v2's fixed 6 GiB.
	VMMemoryMiB func() (int, error)
}

// agentDesc and tierDesc are print_session_banner's descriptions.
var agentDesc = map[string]string{"claude": "claude (Anthropic OAuth)", "codex": "codex (OpenAI OAuth)",
	"opencode": "opencode (vLLM proxy)", "copilot": "copilot (GitHub OAuth)", "grok": "grok (xAI OAuth)"}
var tierDesc = map[string]string{"1": "1 — Ephemeral", "2": "2 — Project", "3": "3 — Infra"}

// banner is print_session_banner. The runtime line names Kata, which v3 runs, not gVisor.
func (c *cmdCtx) banner(s LaunchSpec, rec SessionRecord) {
	or := func(m map[string]string, k string) string {
		if v, ok := m[k]; ok {
			return v
		}
		return k
	}
	sep := "  ────────────────────────────────────────────────"
	row := func(k, v string) { c.out("  %-9s  %s", k, v) }
	c.out("%s", sep)
	c.out("  SANDBOX SESSION")
	c.out("%s", sep)
	row("Session", rec.ID)
	if s.Name != "" {
		row("Name", s.Name)
	}
	row("Agent", or(agentDesc, s.Agent))
	row("Tier", or(tierDesc, s.Tier))
	if s.Profile != "" {
		row("Profile", s.Profile)
	}
	if s.Overlay != "" {
		row("Overlay", c.tilde(s.Overlay))
	}
	switch len(s.Repos) {
	case 0:
		row("Repo", "emptyDir (ephemeral)")
	case 1:
		row("Repo", c.tilde(s.Repos[0]))
	default:
		row("Repos", fmt.Sprintf("%d mounted under /workspace:", len(s.Repos)))
		for _, r := range s.Repos {
			c.out("             /workspace/%s  ←  %s", bashcompat.Basename(r), c.tilde(r))
		}
	}
	row("Egress", fmt.Sprintf("%s + tier%s (%d domains)", s.Agent, s.Tier, rec.DomainCount))
	row("Runtime", "kata")
	row("Log", c.tilde(rec.LogDir))
	c.out("%s", sep)
}

// agentCommand is the command run attaches: the agent, its inner-sandbox flags, and its pinned
// conversation id.
func agentCommand(agent, sessionID string) []string {
	cmd := append([]string{agent}, strings.Fields(agents.SandboxFlags(agent))...)
	if sessionID != "" {
		cmd = append(cmd, agents.SessionIDFlag(agent), sessionID)
	}
	return cmd
}

// launch is cmd_run Steps 8 to 12 on sandboxd.
func (c *cmdCtx) launch(s LaunchSpec, rec SessionRecord) {
	l := c.env.Launch
	// what this build cannot launch yet says so before anything is built
	switch {
	case s.Agent == "opencode":
		c.die("'run' with opencode is not yet available in the Go port: its API key needs a credential binding (design 5.9.4).")
	case len(s.InfraKubeconfigs) > 0:
		c.die("'run' with --infra-kubeconfig is not yet available in the Go port: its credentials go to the gateway (design 5.9.5).")
	case strings.TrimSpace(s.MCPs) != "":
		c.die("'run' with MCP dependencies is not yet available in the Go port of the sandbox CLI.")
	}
	c.out("==> Building pod manifest...")
	tag := strings.TrimPrefix(rec.Image, "docker.io/library/")
	image, err := l.AgentImage(tag)
	if err != nil {
		c.die("No runnable image for agent '%s' (tier %s): %v", s.Agent, s.Tier, err)
	}
	in := SpecInputs{Image: image, WorkspaceCopy: l.WorkspaceCopy}
	if l.VMMemoryMiB != nil {
		if in.VMMemoryMiB, err = l.VMMemoryMiB(); err != nil {
			c.die("The VM's memory: %v", err)
		}
	}
	spec, err := c.buildSpec(s, rec, in)
	if err != nil {
		c.die("%v", err)
	}
	for _, l := range c.l7Rules(spec) {
		c.out("%s", l)
	}
	for _, l := range c.bindSecrets(spec, s, rec) {
		c.out("%s", l)
	}
	for _, l := range c.registryWarnings(spec) {
		c.errOut("%s", l)
	}
	if s.DryRun {
		b, _ := json.MarshalIndent(spec, "", "  ")
		c.out("")
		c.out("==> DRY RUN — Session spec:")
		c.out("%s", b)
		c.out("")
		c.out("Dry run complete. No resources applied.")
		return
	}
	c.out("==> Starting session...")
	if err := l.Sessions.Start(spec); err != nil {
		c.die("Session %s failed to start: %v", rec.ID, err)
	}
	c.out("")
	c.banner(s, rec)
	c.out("")
	c.out("==> Attaching to session (Ctrl-D or 'exit' to end)...")
	if _, err := l.Sessions.Attach(rec.ID, agentCommand(s.Agent, rec.AgentSessionID)); err != nil {
		c.warn("%v", err)
	}
	c.out("")
	if s.KeepAlive {
		c.out("==> Disconnected from session %s (pod kept alive).", rec.ID)
		c.out("    Resume:  sandbox resume %s", rec.ID)
		c.out("    Stop:    sandbox stop %s", rec.ID)
		c.out("    Logs:    %s", rec.LogDir)
		return
	}
	c.out("==> Disconnected — tearing down session to free cluster resources...")
	c.stopSession(rec.ID)
	c.out("")
	c.out("    Conversation history preserved in ~/.sandbox/agent-home/%s/", s.Agent)
	c.out("    To continue: start a new session and use the agent's /resume command.")
}
