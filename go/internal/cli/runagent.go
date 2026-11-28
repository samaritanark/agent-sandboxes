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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/samaritanark/agent-sandboxes/go/internal/audit"
	"github.com/samaritanark/agent-sandboxes/go/internal/sessionspec"
)

// AgentRef is an agent's credential in the broker store.
func AgentRef(agent string) string { return "agent." + agent }

// agentAdapter is what a brokered agent needs: the variable its token goes in, the hosts and the
// injection, where its configuration and history live, and the files staged from the operator's
// onboarded copy (~/.sandbox/agent-config/<agent>/).
type agentAdapter struct {
	tokenVar   string // the variable its token goes in ("" for a token in a file: tokenFile)
	tokenFile  bool   // the token is in a generated file (codex's auth.json), as a JWT look-alike
	refresh    bool   // the broker refreshes the login before a launch (an OAuth login)
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
		generated: map[string]string{".claude.json": ""}, // claudeJSON
		// S2: the harness's own updater stays off in a session (updates come through the image)
		env: []sessionspec.EnvVar{{Name: "DISABLE_AUTOUPDATER", Value: "1"}, {Name: "DISABLE_UPDATES", Value: "1"}},
	},
	// Codex with a ChatGPT login: the broker holds and refreshes it; the guest's auth.json holds a
	// JWT look-alike access token whose signature is the placeholder (S2: Codex decodes the
	// token's expiry and account but checks no signature) and sends it only to chatgpt.com.
	"codex": {
		tokenFile: true, refresh: true, hosts: []string{"chatgpt.com"}, inject: "bearer",
		configDir: AgentHome + "/.codex", historyDir: AgentHome + "/.codex/sessions",
		staged: []string{"config.toml", "AGENTS.md"},
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
	if h, ok := unbrokered[s.Agent]; ok {
		c.setUpAgentHome(spec, s, rec, h)
		return nil
	}
	ad, ok := adapters[s.Agent]
	if !ok {
		if s.Agent == "opencode" {
			return nil
		}
		c.die("'run' with %s is not yet available in v3: its credential broker adapter is not built (design 5.9.4). Use --agent claude.", s.Agent)
	}
	ref := AgentRef(s.Agent)
	if c.env.CredentialPresent == nil || !c.env.CredentialPresent(ref) {
		how := "run 'claude setup-token', then: sandbox onboard --agent claude"
		if s.Agent != "claude" {
			how = "run: sandbox onboard --agent " + s.Agent
		}
		c.die("%s is not onboarded in this sandbox VM. On the host, %s", s.Agent, how)
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
	f := &AgentFiles{Agent: s.Agent, Tier: spec.Tier, Config: map[string][]byte{}}
	if ad.tokenFile {
		// an OAuth login: refreshed first if it expires within the launch's longest life
		var exp int64
		if ad.refresh {
			if c.env.Launch.RefreshCredential == nil {
				c.die("%s's login needs the credential broker in the sandbox VM.", s.Agent)
			}
			var err error
			if exp, err = c.env.Launch.RefreshCredential(ref); err != nil {
				c.die("%s's login could not be renewed: %v\n  Onboard it again on the host: sandbox onboard --agent %s", s.Agent, err, s.Agent)
			}
		}
		prefix, auth := c.codexAuthJSON(ph, exp)
		f.Config["auth.json"] = auth
		spec.Bindings = append(spec.Bindings, sessionspec.Binding{Ref: ref, Hosts: ad.hosts, Inject: ad.inject, Placeholder: ph, Prefix: prefix})
	} else {
		spec.Bindings = append(spec.Bindings, sessionspec.Binding{Ref: ref, Hosts: ad.hosts, Inject: ad.inject, Placeholder: ph, EnvVar: ad.tokenVar})
		spec.Env = append(spec.Env, sessionspec.EnvVar{Name: ad.tokenVar, Value: ph})
	}
	spec.Env = append(spec.Env, ad.env...)

	src := filepath.Join(c.env.Home, ".sandbox", "agent-config", s.Agent)
	for _, name := range ad.staged {
		if b, err := os.ReadFile(filepath.Join(src, name)); err == nil {
			f.Config[name] = b
		}
	}
	for name, content := range ad.generated {
		if _, have := f.Config[name]; !have {
			if s.Agent == "claude" && name == ".claude.json" {
				content = claudeJSON(spec)
			}
			f.Config[name] = []byte(content)
		}
	}
	if s.Agent == "codex" {
		f.Config["config.toml"] = codexConfig(f.Config["config.toml"])
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

// agentHome is an agent whose login cannot be brokered (OQ-01): its own home in the guest, kept in
// the VM per tier, which its own device login writes; the files staged from the operator's
// onboarded copy (~/.sandbox/agent-config/<agent>/) that seed a new home; and how it signs in.
type agentHome struct {
	dir       string
	account   string
	login     string
	staged    []string
	generated map[string]string // seed files for a new home, when the operator staged none
}

// copilotConfig is a new Copilot home's config.json: /workspace trusted (the session is the
// boundary, as for Claude Code), so Copilot does not ask at the first launch of each tier. Copilot
// keeps writing the file itself (its login, more folders).
const copilotConfig = `// User settings belong in settings.json.
// This file is managed automatically.
{
  "trustedFolders": [
    "/workspace"
  ]
}
`

var unbrokered = map[string]agentHome{
	"copilot": {dir: AgentHome + "/.copilot", account: "GitHub", login: "sign in when Copilot asks (or with /login): a device login",
		generated: map[string]string{"config.json": copilotConfig}},
	"grok": {dir: AgentHome + "/.grok", account: "xAI", login: "sign in when Grok asks (grok login --device-auth): a device login", staged: []string{"config.toml"}},
}

// setUpAgentHome mounts an unbrokered agent's home (sessionspec.AgentHome), warns that the agent
// holds its own login, and records it in the session's audit record (OQ-01: allowed with a
// warning and an audit record per session).
func (c *cmdCtx) setUpAgentHome(spec *sessionspec.Spec, s LaunchSpec, rec SessionRecord, h agentHome) {
	if c.env.Launch.PrepareAgentHome == nil {
		c.die("'run' with %s needs the sandbox VM's agent homes.", s.Agent)
	}
	seed := map[string][]byte{}
	src := filepath.Join(c.env.Home, ".sandbox", "agent-config", s.Agent)
	for _, name := range h.staged {
		if b, err := os.ReadFile(filepath.Join(src, name)); err == nil {
			seed[name] = b
		}
	}
	for name, content := range h.generated {
		if _, have := seed[name]; !have {
			seed[name] = []byte(content)
		}
	}
	warnings, err := c.env.Launch.PrepareAgentHome(s.Agent, spec.Tier, seed)
	if err != nil {
		c.die("could not prepare %s's home in the sandbox VM: %v", s.Agent, err)
	}
	for _, w := range warnings {
		c.warn("%s", w)
	}
	spec.Mounts = append(spec.Mounts, sessionspec.Mount{Kind: sessionspec.AgentHome, Source: sessionspec.AgentHomePath(s.Agent, spec.Tier), Target: h.dir})
	msg := fmt.Sprintf("%s's %s login cannot be brokered: the agent holds it, in its home in the sandbox VM (kept for tier %d sessions of %s), and can use it from any host this session's allowlist allows.",
		s.Agent, h.account, spec.Tier, s.Agent)
	c.warn("%s", msg)
	if isDir(rec.LogDir) {
		audit.LogEvent(rec.LogDir, "unbrokered-credential", msg, c.stamp())
	}
	c.out("==> %s: not brokered (OQ-01); %s, kept in the sandbox VM for tier %d", s.Agent, h.login, spec.Tier)
}

// AgentConfigDir and SessionHistoryDir are sandboxd's names (daemon.AgentConfigDir,
// daemon.SessionHistoryDir) in a session's directory.
const (
	AgentConfigDir    = "agent-config"
	SessionHistoryDir = "history"
)

// claudeJSON is the .claude.json a claude session starts with: the first-run wizard done, and the
// session's workspaces trusted (the session is the boundary; a fresh copy at every launch would
// otherwise ask at every launch).
func claudeJSON(spec *sessionspec.Spec) string {
	projects := map[string]any{}
	trust := map[string]bool{"hasTrustDialogAccepted": true}
	for _, m := range spec.Mounts {
		if m.Kind == sessionspec.Workspace {
			projects[m.Target] = trust
			// several repositories are mounted under /workspace, where the agent starts (the
			// image's WORKDIR); it holds only those repositories, each trusted here already
			if path.Dir(m.Target) == "/workspace" {
				projects["/workspace"] = trust
			}
		}
	}
	// a session with no repository starts in an empty /workspace that goes with it: nothing there
	// to distrust, and v2's kept agent home remembered the answer after the first session
	if len(projects) == 0 {
		projects["/workspace"] = trust
	}
	b, _ := json.Marshal(map[string]any{"hasCompletedOnboarding": true, "projects": projects})
	return string(b) + "\n"
}

// codexDefaults are the settings every codex session has: the harness's own updater off (S2; updates
// come through the image) and its login read from auth.json, never a keyring.
var codexDefaults = []string{"check_for_update_on_startup = false", `cli_auth_credentials_store = "file"`}

// codexConfig is the operator's config.toml with codexDefaults put first for each key it does not
// set (top-level keys before any table, so the file stays valid TOML).
func codexConfig(op []byte) []byte {
	var head []string
	for _, kv := range codexDefaults {
		key := strings.TrimSpace(strings.SplitN(kv, "=", 2)[0])
		if !regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s*=`).Match(op) {
			head = append(head, kv)
		}
	}
	out := strings.Join(head, "\n")
	if out != "" {
		out += "\n"
	}
	return append([]byte(out), op...)
}

// codexIdentity is the non-secret account onboarding recorded (the host's
// ~/.sandbox/agent-config/codex/identity.json).
type codexIdentity struct {
	AccountID string `json:"account_id"`
	Email     string `json:"email"`
	Plan      string `json:"plan"`
	UserID    string `json:"user_id"`
}

// codexAuthJSON is the guest's auth.json: a ChatGPT login whose access token is a JWT look-alike
// (header and claims, then the placeholder as its signature) expiring when the real one does, an id
// token carrying only the account's non-secret claims, and no usable refresh token. It returns the
// access token's prefix (all before the placeholder) and the file.
func (c *cmdCtx) codexAuthJSON(ph string, exp int64) (string, []byte) {
	b, err := os.ReadFile(filepath.Join(c.env.Home, ".sandbox", "agent-config", "codex", "identity.json"))
	var id codexIdentity
	if err == nil {
		err = json.Unmarshal(b, &id)
	}
	if err != nil || id.AccountID == "" {
		c.die("codex's account is unknown here; on the host, run: sandbox onboard --agent codex")
	}
	seg := func(v any) string {
		j, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(j)
	}
	header := seg(map[string]string{"alg": "none", "typ": "JWT"})
	claims := map[string]any{"chatgpt_account_id": id.AccountID, "chatgpt_plan_type": id.Plan, "chatgpt_user_id": id.UserID}
	prefix := header + "." + seg(map[string]any{"exp": exp, "https://api.openai.com/auth": claims}) + "."
	idToken := header + "." + seg(map[string]any{"exp": exp, "email": id.Email, "https://api.openai.com/auth": claims,
		"https://api.openai.com/profile": map[string]string{"email": id.Email}}) + ".c2FuZGJveA"
	auth := map[string]any{
		"auth_mode": "chatgpt", "OPENAI_API_KEY": nil,
		"tokens": map[string]any{"id_token": idToken, "access_token": prefix + ph,
			"refresh_token": "brokered-by-the-sandbox", "account_id": id.AccountID},
		"last_refresh": c.now().Format(time.RFC3339),
	}
	out, _ := json.MarshalIndent(auth, "", "  ")
	return prefix, append(out, '\n')
}
