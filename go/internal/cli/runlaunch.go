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
	"github.com/samaritanark/agent-sandboxes/go/internal/catalogue"
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
	// WriteMCPConfig writes the agent's MCP configuration for session id where sandboxd mounts it
	// from (its session directory) and returns that directory; nil refuses MCP dependencies.
	WriteMCPConfig func(id string, content []byte) (string, error)
	// WriteAgentFiles writes a session's agent configuration and makes its history directory
	// (setUpAgent); nil refuses agents that need them.
	WriteAgentFiles func(id string, f AgentFiles) error
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
	case len(s.InfraKubeconfigs) > 0:
		c.die("'run' with --infra-kubeconfig is not yet available in the Go port: its credentials go to the gateway (design 5.9.5).")
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
	if s.Agent == "opencode" {
		c.bindOpencode(spec, s)
	}
	agentFiles := c.setUpAgent(spec, s, rec)
	mcp := c.mcpConfig(s, rec)
	if mcp != "" {
		spec.Mounts = append(spec.Mounts, sessionspec.Mount{Kind: sessionspec.MCPConfig,
			Source: sessionspec.SessionStore + "/" + rec.ID + "/" + MCPDir, Target: agents.MCPConfigDir, ReadOnly: true})
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
	if agentFiles != nil {
		if l.WriteAgentFiles == nil {
			c.die("'run' needs the sandbox VM's session store for the agent's configuration.")
		}
		if err := l.WriteAgentFiles(rec.ID, *agentFiles); err != nil {
			c.die("could not stage the agent's configuration and history: %v", err)
		}
	}
	if mcp != "" {
		if l.WriteMCPConfig == nil {
			c.die("'run' with MCP dependencies needs the sandbox VM's session store.")
		}
		if _, err := l.WriteMCPConfig(rec.ID, []byte(mcp)); err != nil {
			c.die("could not write the session's MCP configuration: %v", err)
		}
	}
	c.out("==> Starting session...")
	if err := l.Sessions.Start(spec); err != nil {
		c.die("Session %s failed to start: %v", rec.ID, err)
	}
	c.out("")
	c.banner(s, rec)
	c.out("")
	c.out("==> Attaching to session (Ctrl-D or 'exit' to end)...")
	cmd := agentCommand(s.Agent, rec.AgentSessionID)
	if mcp != "" {
		cmd = append(cmd, agents.MCPLaunchArgs(s.Agent)...)
	}
	if _, err := l.Sessions.Attach(rec.ID, cmd); err != nil {
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
	c.closingHistory(s.Agent, s.Tier)
}

// MCPDir is where in the session's directory its MCP configuration goes (sandboxd's
// daemon.MCPDir, which removes it with the session).
const MCPDir = "mcp"

// mcpConfig is the agent's MCP configuration for the launch's MCP dependencies (v2's
// render_agent_mcp_config), each at its v3 address: the gateway forwards
// <name>.deps.sandbox.internal:<port> to the dependency's microVM (design 5.8.6). "" when there are
// none.
func (c *cmdCtx) mcpConfig(s LaunchSpec, rec SessionRecord) string {
	var records []string
	for _, d := range rec.Dependencies {
		if d.Kind != "mcp" {
			continue
		}
		url := "http://" + d.Name + ".deps.sandbox.internal:" + d.Port + catalogue.Field(d.Path, "mcp_path", "/mcp")
		records = append(records, d.Name+"|"+catalogue.Field(d.Path, "mcp_transport", "http")+"|"+url)
	}
	if len(records) == 0 {
		return ""
	}
	cfg, err := agents.RenderMCPConfig(s.Agent, records)
	if err != nil {
		c.die("%v", err)
	}
	return cfg
}

// closingHistory says where the agent's conversation history is (design 5.7): with an adapter,
// in the VM per agent, tier, and repository set, or gone with a tier 1 session; otherwise v2's
// line.
func (c *cmdCtx) closingHistory(agent, tierV string) {
	if _, ok := adapters[agent]; !ok {
		c.out("    Conversation history preserved in ~/.sandbox/agent-home/%s/", agent)
		c.out("    To continue: start a new session and use the agent's /resume command.")
		return
	}
	if tierV == "1" {
		c.out("    Conversation history went with the session (tier 1 keeps none).")
		return
	}
	c.out("    Conversation history is kept in the sandbox VM for this agent, tier %s, and repository.", tierV)
	c.out("    To continue: start a new session at tier %s on the same repository and use the agent's /resume command.", tierV)
}
