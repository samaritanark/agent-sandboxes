package cli

// The agent's own credential, configuration, and history (design 5.7, 5.9.4; owner decision,
// tenth round: no agent home holding tokens). Claude Code is the first agent with a broker adapter:
// `sandbox onboard` on the host seals the long-lived OAuth token `claude setup-token` prints into
// the broker store (agent.claude, bound to api.anthropic.com), and the session's
// CLAUDE_CODE_OAUTH_TOKEN holds a placeholder the gateway replaces. Its configuration is re-staged
// at every launch as a writable copy discarded at teardown, and its history (projects/: transcripts
// and per-project memory) persists per agent, tier, and repository set, tier 1's with the session.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// AgentRef is an agent's credential in the broker store.
func AgentRef(agent string) string { return "agent." + agent }

// agentAdapter is what a brokered agent needs: the variable its token goes in, the hosts and the
// injection, where its configuration and history live, and the files staged from the operator's
// onboarded copy (~/.sandbox/agent-config/<agent>/).
type agentAdapter struct {
	tokenVar   string
	hosts      []string
	inject     string
	configDir  string // in the guest
	historyDir string // in the guest, inside configDir
	staged     []string
	generated  map[string]string // file: content, written when the operator's copy has none
	env        []sessionspec.EnvVar
}

var adapters = map[string]agentAdapter{
	"claude": {
		tokenVar: "CLAUDE_CODE_OAUTH_TOKEN", hosts: []string{"api.anthropic.com"}, inject: "bearer",
		configDir: AgentHome + "/.claude", historyDir: AgentHome + "/.claude/projects",
		staged:    []string{"settings.json", "CLAUDE.md"},
		generated: map[string]string{".claude.json": `{"hasCompletedOnboarding": true}` + "\n"},
		// S2: the harness's own updater stays off in a session (updates come through the image)
		env: []sessionspec.EnvVar{{Name: "DISABLE_AUTOUPDATER", Value: "1"}, {Name: "DISABLE_UPDATES", Value: "1"}},
	},
}

// AgentFiles is what the VM writes for a session's agent: its configuration files, and whether it
// keeps history.
type AgentFiles struct {
	Agent      string
	Tier       int
	HistoryKey string            // the repository set's key; "" at tier 1
	Config     map[string][]byte // file name: content
}

// historyKey is a launch's repository-set key: the one workspace copy's ID, or a hash of the
// sorted IDs of several (design 5.7 item 2).
func historyKey(copies []string) string {
	var ids []string
	for _, c := range copies {
		ids = append(ids, path.Base(c))
	}
	if len(ids) == 1 {
		return ids[0]
	}
	sort.Strings(ids)
	h := sha256.Sum256([]byte(strings.Join(ids, "\n")))
	return hex.EncodeToString(h[:16])
}

// setUpAgent adds the agent's credential binding, configuration, and history to spec, and returns
// the files the VM writes before the start. It stops the launch for an agent without an adapter
// (other than opencode, whose key is brokered by the host) or one not onboarded.
func (c *cmdCtx) setUpAgent(spec *sessionspec.Spec, s LaunchSpec, rec SessionRecord) *AgentFiles {
	ad, ok := adapters[s.Agent]
	if !ok {
		if s.Agent == "opencode" {
			return nil
		}
		c.die("'run' with %s is not yet available in v3: its credential broker adapter is not built (design 5.9.4). Use --agent claude.", s.Agent)
	}
	ref := AgentRef(s.Agent)
	if c.env.CredentialPresent == nil || !c.env.CredentialPresent(ref) {
		c.die("%s is not onboarded in this sandbox VM. On the host, run 'claude setup-token', then: sandbox onboard --agent %s", s.Agent, s.Agent)
	}
	bound := false
	if c.env.CredentialBinding != nil {
		sealed, have := c.env.CredentialBinding(ref)
		bound = have && sealed.Allows(ad.hosts, ad.inject, false) == nil
	}
	for _, h := range ad.hosts {
		bound = bound && sessionspec.Reachable(h, spec.Egress)
	}
	if !bound {
		c.die("%s's credential in this sandbox VM is not bound to %s; run 'sandbox onboard --agent %s' on the host again.", s.Agent, strings.Join(ad.hosts, ", "), s.Agent)
	}
	ph := placeholder()
	spec.Bindings = append(spec.Bindings, sessionspec.Binding{Ref: ref, Hosts: ad.hosts, Inject: ad.inject, Placeholder: ph, EnvVar: ad.tokenVar})
	spec.Env = append(spec.Env, sessionspec.EnvVar{Name: ad.tokenVar, Value: ph})
	spec.Env = append(spec.Env, ad.env...)

	f := &AgentFiles{Agent: s.Agent, Tier: spec.Tier, Config: map[string][]byte{}}
	src := filepath.Join(c.env.Home, ".sandbox", "agent-config", s.Agent)
	for _, name := range ad.staged {
		if b, err := os.ReadFile(filepath.Join(src, name)); err == nil {
			f.Config[name] = b
		}
	}
	for name, content := range ad.generated {
		if _, have := f.Config[name]; !have {
			f.Config[name] = []byte(content)
		}
	}
	sess := sessionspec.SessionStore + "/" + rec.ID
	spec.Mounts = append(spec.Mounts, sessionspec.Mount{Kind: sessionspec.AgentConfig, Source: sess + "/" + AgentConfigDir, Target: ad.configDir})
	history := sess + "/" + SessionHistoryDir
	if spec.Tier >= 2 {
		var copies []string
		for _, m := range spec.Mounts {
			if m.Kind == sessionspec.Workspace {
				copies = append(copies, m.Source)
			}
		}
		if len(copies) > 0 {
			f.HistoryKey = historyKey(copies)
			history = sessionspec.HistoryPath(s.Agent, spec.Tier, f.HistoryKey)
		}
	}
	spec.Mounts = append(spec.Mounts, sessionspec.Mount{Kind: sessionspec.History, Source: history, Target: ad.historyDir})
	c.out("==> %s: credential brokered to %s; configuration re-staged; history %s", s.Agent, strings.Join(ad.hosts, ", "),
		map[bool]string{true: "kept for this agent, tier, and repository set", false: "kept for this session only"}[f.HistoryKey != ""])
	return f
}

// AgentConfigDir and SessionHistoryDir are sandboxd's names (daemon.AgentConfigDir,
// daemon.SessionHistoryDir) in a session's directory.
const (
	AgentConfigDir    = "agent-config"
	SessionHistoryDir = "history"
)
