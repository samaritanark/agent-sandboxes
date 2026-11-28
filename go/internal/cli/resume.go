package cli

import (
	"errors"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/agents"
	"github.com/samaritanark/agent-sandboxes/go/internal/audit"
	"github.com/samaritanark/agent-sandboxes/go/internal/bashcompat"
	"github.com/samaritanark/agent-sandboxes/go/internal/config"
	"github.com/samaritanark/agent-sandboxes/go/internal/jqjson"
	"github.com/samaritanark/agent-sandboxes/go/internal/tier"
	"github.com/samaritanark/agent-sandboxes/go/internal/workspace"
)

// ManifestRequest is what v2 handed build_pod_manifest to recreate a torn-down session's
// workload. In v3 it becomes part of the session spec sandboxd takes.
type ManifestRequest struct {
	SessionID, Agent, Tier, Image, Name, User, PodName string
	Repos                                              []string
}

// AttachRequest is the reconnect: the session's workload and the agent command run in it.
type AttachRequest struct {
	SessionID, Pod string
	Command        []string
	KeepAlive      bool
}

// jqLines is `jq -r 'EXPR[]? // empty'`-style output over a list field: strings raw, other values
// in jq's layout; missing or null gives nothing.
func jqLines(v jqjson.Value) []string {
	var out []string
	if v.Kind != jqjson.Array {
		return nil
	}
	for _, x := range v.Arr {
		switch x.Kind {
		case jqjson.Null, jqjson.Bool:
			if x.Kind == jqjson.Null || !x.B {
				continue // `// empty` drops null and false
			}
			out = append(out, "true")
		case jqjson.String:
			out = append(out, x.Str)
		default:
			out = append(out, strings.TrimSuffix(jqjson.Encode(x), "\n"))
		}
	}
	return out
}

// resumeExtras is _resume_extras_json: the recorded allowlist minus the agent and tier defaults
// (an agent whose domains cannot be listed contributes none).
func (c *cmdCtx) resumeExtras(rec jqjson.Value, agent, tierV string) []string {
	ad, _ := agents.Domains(agent, c.env.OpencodeBaseURL)
	return stringsMinus(jqLines(rec.Get("allowed_domains")), ad, tier.Domains(tierV))
}

// resumeBlocker is _resume_recreate_blocker: why a torn-down session cannot be rebuilt from its
// record, or "" when it can.
func (c *cmdCtx) resumeBlocker(sj string) string {
	tierV, agent, profile := jqAlt(sj, "tier", "1"), jqAlt(sj, "agent", "claude"), jqAlt(sj, "profile", "")
	switch {
	case c.env.IsMacOS:
		return "macOS rebuilds the VM-local workspace copy on launch"
	case bashcompat.ArithCmp(tierV, "3", "eq"):
		return "tier 3 infra credentials are never persisted"
	case profile != "":
		return "it used profile '" + profile + "' (dependencies/secrets re-resolve at launch)"
	case agent == "opencode":
		return "opencode reads its key + model list from your environment at launch"
	}
	return ""
}

// resumeGuide is _resume_guide_command: the `sandbox run` line for an equivalent session.
func (c *cmdCtx) resumeGuide(rec jqjson.Value) string {
	agent, tierV := jqRawField(rec, "agent", "claude"), jqRawField(rec, "tier", "1")
	profile, name := jqRawField(rec, "profile", ""), jqRawField(rec, "name", "")
	cmd := "sandbox run --agent " + agent + " --tier " + tierV
	if profile != "" {
		cmd += " --profile " + profile
	}
	for _, r := range jqLines(rec.Get("repos")) {
		if r != "" {
			cmd += " --repo " + r
		}
	}
	if name != "" {
		cmd += " --name '" + name + "'"
	}
	for _, d := range c.resumeExtras(rec, agent, tierV) {
		if d != "" {
			cmd += " --allow-domain " + d
		}
	}
	return cmd
}

// cmdResume is cmd_resume: reconnect to a session, recreating its workload from the record when
// it was torn down and the record allows it, after re-running the workspace gates. The workload
// itself is sandboxd's in v3.
func cmdResume(c *cmdCtx, args []string) {
	var keepAlive, acceptUnmasked, acceptUnvetted, acceptDrift bool
	sessionID := ""
	for _, a := range args {
		switch {
		case a == "--keep-alive":
			keepAlive = true
		case a == "--i-accept-unmasked-secrets":
			acceptUnmasked = true
		case a == "--i-accept-unvetted-repo":
			acceptUnvetted = true
		case a == "--i-accept-vetting-drift":
			acceptDrift = true
		case a == "--help" || a == "-h":
			for _, l := range []string{
				"Usage: sandbox resume <SESSION_ID> [--keep-alive]",
				"                      [--i-accept-unmasked-secrets] [--i-accept-unvetted-repo]",
				"                      [--i-accept-vetting-drift]",
				"",
				"Reconnects to a session. If its pod is still running, re-attaches.",
				"If the pod was torn down, recreates it from the recorded session",
				"state when possible (Linux, tier 1/2, no profile, non-opencode);",
				"otherwise prints the 'sandbox run' command to relaunch an equivalent.",
				"",
				"Recreating a Tier 2/3 pod re-runs the workspace gates against the LIVE",
				"repo (the agent may have changed it since launch). The --i-accept-*",
				"flags waive a gate exactly as on 'sandbox run' — so a session launched",
				"with a waiver can be resumed — while the default still fails closed.",
				"Each waiver used is recorded in the session's audit log.",
			} {
				c.out("%s", l)
			}
			panic(exit(0))
		case strings.HasPrefix(a, "-"):
			c.die("Unknown option: %s", a)
		case sessionID == "":
			sessionID = a
		default:
			c.die("Unexpected argument: %s", a)
		}
	}
	if sessionID == "" {
		c.die("Usage: sandbox resume <SESSION_ID> [--keep-alive]")
	}
	logDir := c.env.LogsDir + "/" + sessionID
	sj := logDir + "/session.json"
	pod := jqAlt(sj, "pod_name", "")
	if pod == "" {
		pod = "sandbox-" + sessionID
	}
	if !config.IsFile(sj) {
		c.die("Session not found: %s (no session.json in %s)", sessionID, logDir)
	}
	agent := jqAlt(sj, "agent", "claude")
	agentSessionID := jqAlt(sj, "agent_session_id", "")

	onSandboxd := c.env.Launch.Sessions != nil && c.env.SessionPhase == nil
	if onSandboxd {
		c.resumeHooks()
	}
	if c.env.SessionPhase == nil || c.env.RecreateSession == nil || c.env.Attach == nil {
		c.die("'resume' is not yet available in the Go port of the sandbox CLI: the session runtime (sandboxd) does not exist yet.")
	}
	exists, phase := c.env.SessionPhase(sessionID, pod)
	mcp := false
	if !exists {
		b := c.resumeBlocker(sj)
		if onSandboxd {
			b = c.recreateBlocker(sj)
		}
		if b != "" {
			rec, _ := sessionRecord(sj)
			c.errOut("Session %s's pod was torn down and can't be auto-recreated:", sessionID)
			c.errOut("  %s.", b)
			c.errOut("")
			c.errOut("Relaunch an equivalent session (its conversation history is preserved in")
			c.errOut("~/.sandbox/agent-home/%s/ and continues via the agent's /resume):", agent)
			c.errOut("")
			c.errOut("  %s", c.resumeGuide(rec))
			panic(exit(1))
		}
		if onSandboxd {
			mcp = c.recreateOnSandboxd(sessionID, keepAlive, acceptUnmasked, acceptUnvetted, acceptDrift)
		} else {
			c.recreateSession(sessionID, acceptUnmasked, acceptUnvetted, acceptDrift)
		}
	} else if phase != "Running" {
		c.die("Pod is not running (phase: %s). Use 'sandbox stop %s' to clean up.", phase, sessionID)
	}

	c.out("==> Resuming session: %s", sessionID)
	c.out("    Agent: %s  |  Log: %s", agent, c.tilde(logDir))
	c.out("")
	cmd := []string{agent}
	cmd = append(cmd, strings.Fields(agents.SandboxFlags(agent))...)
	if rf := agents.ResumeFlag(agent); agentSessionID != "" && rf != "" {
		cmd = append(cmd, rf, agentSessionID)
	}
	if mcp || onSandboxd && recordHasMCP(sj) {
		cmd = append(cmd, agents.MCPLaunchArgs(agent)...)
	}
	c.env.Attach(AttachRequest{SessionID: sessionID, Pod: pod, Command: cmd, KeepAlive: keepAlive})
}

// resumeHooks are resume's session hooks on sandboxd: a session is live or gone (sandboxd has no
// pending phase a client must wait out), and the attach is run's, with v2's closing lines.
func (c *cmdCtx) resumeHooks() {
	s := c.env.Launch.Sessions
	c.env.SessionPhase = func(id, _ string) (bool, string) {
		live, err := s.Live(id)
		if err != nil {
			c.die("Cannot ask sandboxd about session %s: %v", id, err)
		}
		if !live {
			return false, ""
		}
		return true, "Running"
	}
	c.env.RecreateSession = func(PolicyRequest, ManifestRequest) error {
		return errors.New("recreating a stopped session is not yet available in v3")
	}
	c.env.Attach = func(r AttachRequest) {
		if _, err := s.Attach(r.SessionID, r.Command); err != nil {
			c.warn("%v", err)
		}
		c.out("")
		if r.KeepAlive {
			c.out("==> Disconnected from session %s (pod kept alive).", r.SessionID)
			c.out("    Resume:  sandbox resume %s", r.SessionID)
			c.out("    Stop:    sandbox stop %s", r.SessionID)
			return
		}
		c.out("==> Disconnected — tearing down session to free cluster resources...")
		c.stopSession(r.SessionID)
		c.out("")
		agent := jqAlt(c.env.LogsDir+"/"+r.SessionID+"/session.json", "agent", "claude")
		c.closingHistory(agent, jqAlt(c.env.LogsDir+"/"+r.SessionID+"/session.json", "tier", "1"))
	}
}

// recreateSession is recreate_session_pod: re-gate the live workspace (tier 2/3), then hand the
// session's policy and workload to the runtime.
func (c *cmdCtx) recreateSession(sessionID string, acceptUnmasked, acceptUnvetted, acceptDrift bool) {
	logDir := c.env.LogsDir + "/" + sessionID
	sj := logDir + "/session.json"
	pod := jqAlt(sj, "pod_name", "")
	if pod == "" {
		pod = "sandbox-" + sessionID
	}
	rec, _ := sessionRecord(sj)
	agent, tierV := jqRawField(rec, "agent", "claude"), jqRawField(rec, "tier", "1")
	name, user := jqRawField(rec, "name", ""), jqRawField(rec, "user", "unknown")
	repos := jqLines(rec.Get("repos"))
	extras := c.resumeExtras(rec, agent, tierV)

	c.recheckGates(logDir, agent, tierV, repos, acceptUnmasked, acceptUnvetted, acceptDrift)

	c.out("==> Recreating pod for %s (%s, tier %s)...", sessionID, agent, tierV)
	policy := PolicyRequest{SessionID: sessionID, Agent: agent, Tier: tierV,
		KubeAPICIDR: jqRawField(rec, "kube_api_cidr", ""), KubeAPIPort: jqRawField(rec, "kube_api_port", ""),
		KubeHostEntity: jqRawField(rec, "kube_host_entity", ""), Extras: extras}
	manifest := ManifestRequest{SessionID: sessionID, Agent: agent, Tier: tierV, Image: "docker.io/library/sandbox:" + agent,
		Name: name, User: user, PodName: pod, Repos: repos}
	if err := c.env.RecreateSession(policy, manifest); err != nil {
		c.die("%v", err)
	}
	c.out("==> Applying CiliumNetworkPolicy...")
	c.out("==> Applying pod...")
	c.out("==> Waiting for pod to become Ready...")
}

// recordHasMCP is whether a session's record lists an MCP dependency (its agent then starts with
// the MCP configuration's flags, as at run).
func recordHasMCP(sj string) bool {
	rec, ok := sessionRecord(sj)
	if !ok {
		return false
	}
	if deps := rec.Get("dependencies"); deps.Kind == jqjson.Array {
		for _, d := range deps.Arr {
			if jqRawField(d, "kind", "") == "mcp" {
				return true
			}
		}
	}
	return false
}

// recreateBlocker is why a stopped session cannot be started again on sandboxd from its record,
// or "" when it can. The agent's login is in the broker store, and the workspace and history in
// the VM; what is missing is what only the host's pre-pass of `sandbox run` sends (bound secrets,
// opencode's key) or what the record does not hold (tier 3's token files).
func (c *cmdCtx) recreateBlocker(sj string) string {
	tierV, agent, profile := jqAlt(sj, "tier", "1"), jqAlt(sj, "agent", "claude"), jqAlt(sj, "profile", "")
	switch {
	case bashcompat.ArithCmp(tierV, "3", "eq"):
		return "tier 3's --infra-token files are not recorded, so they cannot be brokered again"
	case agent == "opencode":
		return "opencode's key comes from your shell at each launch"
	case profile != "" && !config.IsNumericProfile(profile):
		p, ok := config.FindProfilePath(c.env.Env, profile)
		if !ok {
			return "its profile '" + profile + "' no longer exists"
		}
		if len(config.ExtractYAMLList(p, "secrets")) > 0 {
			return "its profile '" + profile + "' binds secrets, which only 'sandbox run' sends from your machine"
		}
	}
	return ""
}

// recreateOnSandboxd starts a stopped session again from its record (design 5.14): the workspace
// gates run again, then the session is built as at run, with its ID, repositories, runtime,
// extra domains, and the profile's dependencies, and the agent resumes its conversation. It
// returns whether the session has MCP dependencies.
func (c *cmdCtx) recreateOnSandboxd(sessionID string, keepAlive, acceptUnmasked, acceptUnvetted, acceptDrift bool) bool {
	logDir := c.env.LogsDir + "/" + sessionID
	sj := logDir + "/session.json"
	rec, _ := sessionRecord(sj)
	agent, tierV := jqRawField(rec, "agent", "claude"), jqRawField(rec, "tier", "1")
	repos := jqLines(rec.Get("repos"))
	c.recheckGates(logDir, agent, tierV, repos, acceptUnmasked, acceptUnvetted, acceptDrift)
	s := LaunchSpec{Agent: agent, Tier: tierV, Repos: repos, Name: jqRawField(rec, "name", ""),
		Profile: jqRawField(rec, "profile", ""), Overlay: jqRawField(rec, "overlay", ""),
		Domains: c.resumeExtras(rec, agent, tierV), KeepAlive: keepAlive, Runtime: jqRawField(rec, "runtime", "")}
	var mcps, services string
	if s.Profile != "" && !config.IsNumericProfile(s.Profile) {
		if p, ok := config.FindProfilePath(c.env.Env, s.Profile); ok {
			mcps = strings.Join(config.ExtractYAMLList(p, "mcps"), ",")
			services = strings.Join(config.ExtractYAMLList(p, "services"), ",")
		}
	}
	r := SessionRecord{ID: sessionID, PodName: jqRawField(rec, "pod_name", "sandbox-"+sessionID), LogDir: logDir,
		Image: sessionImage(agent), DomainCount: len(jqLines(rec.Get("allowed_domains")))}
	deps, ok := c.resolveDependencies(sessionID, agent, mcps, services)
	if !ok {
		c.die("Dependency resolution failed; the session was not recreated.")
	}
	r.Dependencies = deps
	r.Policy = PolicyRequest{SessionID: sessionID, Agent: agent, Tier: tierV, Extras: s.Domains}
	c.out("==> Recreating session %s (%s, tier %s)...", sessionID, agent, tierV)
	mcp, _ := c.startSession(s, r)
	audit.SetField(logDir, "end_time", jqjson.Value{}) // running again
	audit.LogEvent(logDir, "recreated", "Recreated from its record by 'sandbox resume'", c.stamp())
	return mcp != ""
}

// sessionImage is the agent's image tag for a tier 1 or 2 session.
func sessionImage(agent string) string { return "docker.io/library/sandbox:" + agent }

// recheckGates runs a tier 2 or 3 session's workspace gates again before it is recreated.
func (c *cmdCtx) recheckGates(logDir, agent, tierV string, repos []string, acceptUnmasked, acceptUnvetted, acceptDrift bool) {
	if tierAtLeast(tierV, "2") && len(repos) > 0 {
		c.out("==> Re-checking workspace gates before recreate...")
		for _, r := range repos {
			for _, l := range workspace.Prescan(r) {
				c.out("%s", l)
			}
		}
		c.maskTypeCheck(repos)
		var overrides []audit.Override
		vs, ss, _ := c.workspaceGates(agent, c.env.OpencodeBaseURL, repos, acceptUnmasked, acceptUnvetted, acceptDrift, &overrides)
		if vs != "" {
			audit.LogEvent(logDir, "vetting", vs, c.stamp())
		}
		if ss != "" {
			audit.LogEvent(logDir, "secret-scan", ss, c.stamp())
		}
		audit.FlushOverrides(logDir, overrides, c.stamp())
	}
}

// tierAtLeast is `[[ "$tier" -ge N ]]` on a recorded tier.
func tierAtLeast(t, n string) bool {
	return bashcompat.ArithCmp(t, n, "gt") || bashcompat.ArithCmp(t, n, "eq")
}

var resumeSessionIDRE = regexp.MustCompile(`^ses-[0-9]{8}-[0-9]{6}-[0-9a-f]{4}$`)

// SessionRepos is the repositories session id's record names (the host syncs them before a
// resume); ok is false when there is no such record.
func SessionRepos(id string, env Env) (repos []string, ok bool) {
	if !resumeSessionIDRE.MatchString(id) {
		return nil, false
	}
	rec, ok := sessionRecord(filepath.Join(env.LogsDir, id, "session.json"))
	if !ok {
		return nil, false
	}
	for _, r := range jqLines(rec.Get("repos")) {
		if r != "" {
			repos = append(repos, r)
		}
	}
	return repos, true
}
