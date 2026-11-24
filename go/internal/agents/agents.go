// Package agents is lib/agents.sh (the per-agent tables: egress domains, CLI flags, MCP wiring,
// credential type, the opencode inference endpoint) and the host-environment check of
// lib/credentials.sh. The Kubernetes-secret half of lib/credentials.sh is not ported: v3 keeps
// credentials in the broker (design 5.9).
package agents

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/samaritanark/agent-sandboxes/go/internal/deviation"
	"github.com/samaritanark/agent-sandboxes/go/internal/jqjson"
)

// Valid is VALID_AGENTS.
var Valid = []string{"claude", "codex", "opencode", "copilot", "grok"}

// Validate is validate_agent: nil for a known agent, else the refusal the bash prints before
// exiting (its second line is a single space).
func Validate(agent string) error {
	for _, a := range Valid {
		if a == agent {
			return nil
		}
	}
	return fmt.Errorf("ERROR: Unknown agent '%s'. Valid agents: claude, codex, opencode, copilot, grok.\n ", agent)
}

var domains = map[string][]string{
	"claude": {"claude.ai", "*.claude.ai", "claude.com", "*.claude.com", "api.anthropic.com",
		"console.anthropic.com", "statsig.anthropic.com", "sentry.io"},
	"codex": {"api.openai.com", "auth.openai.com", "auth0.openai.com", "chatgpt.com", "cdn.openai.com"},
	"copilot": {"github.com", "api.github.com", "*.githubcopilot.com", "*.individual.githubcopilot.com",
		"*.business.githubcopilot.com", "*.enterprise.githubcopilot.com", "copilot-proxy.githubusercontent.com",
		"origin-tracker.githubusercontent.com", "copilot-telemetry.githubusercontent.com", "collector.github.com",
		"default.exp-tas.com"},
	"grok": {"api.x.ai", "accounts.x.ai", "auth.x.ai", "grok.com"},
}

// Domains is get_agent_domains: the agent's egress allowlist. For opencode it is the host of
// OPENCODE_BASE_URL (baseURL), and an error when that has none.
func Domains(agent, baseURL string) ([]string, error) {
	if d, ok := domains[agent]; ok {
		return append([]string(nil), d...), nil
	}
	if agent != "opencode" {
		return nil, fmt.Errorf("ERROR: Unknown agent: %s", agent)
	}
	host := InferenceEndpoint(agent, baseURL)
	if host != "" {
		return []string{host}, nil
	}
	if baseURL != "" {
		return nil, fmt.Errorf("ERROR: OPENCODE_BASE_URL ('%s') has no host.\n"+
			"  Set it to the full URL of an OpenAI-compatible endpoint, e.g.\n"+
			"  https://api.openai.com/v1 or https://vllm.internal:8000/v1.", baseURL)
	}
	return nil, fmt.Errorf("ERROR: OPENCODE_BASE_URL not set in host environment.\n" +
		"  Set it to the URL of an OpenAI-compatible endpoint.")
}

// InferenceEndpoint is resolve_inference_endpoint: for opencode, the bare host of baseURL (scheme,
// path, userinfo, and port removed); "" for the other agents.
func InferenceEndpoint(agent, baseURL string) string {
	if agent != "opencode" || baseURL == "" {
		return ""
	}
	h := baseURL
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.Index(h, "/"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	if i := strings.Index(h, ":"); i >= 0 {
		h = h[:i]
	}
	return h
}

// SessionIDFlag, ResumeFlag and SandboxFlags are get_agent_session_id_flag,
// get_agent_resume_flag and get_agent_sandbox_flags.
func SessionIDFlag(agent string) string {
	if agent == "claude" {
		return "--session-id"
	}
	return ""
}

func ResumeFlag(agent string) string {
	if agent == "claude" {
		return "--resume"
	}
	return ""
}

func SandboxFlags(agent string) string {
	switch agent {
	case "codex":
		return "--sandbox danger-full-access"
	case "grok":
		return "--disallowed-tools web_search,x_search,web_fetch"
	}
	return ""
}

// MCP config location inside the sandbox (SANDBOX_MCP_CONFIG_DIR, SANDBOX_MCP_CONFIG_FILE).
const (
	MCPConfigDir  = "/home/agent/.sandbox-mcp"
	MCPConfigFile = "config.json"
)

// SupportsMCP is agent_supports_mcp.
func SupportsMCP(agent string) bool { return agent == "claude" }

// MCPLaunchArgs is get_agent_mcp_launch_args.
func MCPLaunchArgs(agent string) []string {
	if agent == "claude" {
		return []string{"--mcp-config", MCPConfigDir + "/" + MCPConfigFile, "--strict-mcp-config"}
	}
	return nil
}

// RenderMCPConfig is render_agent_mcp_config: records "name|transport|url" become
// {"mcpServers": {name: {"type": transport, "url": url}}} in jq's layout (a repeated name keeps
// its first position and the last value). A record without '|' is used whole for all three.
func RenderMCPConfig(agent string, records []string) (string, error) {
	servers := jqjson.NewObject()
	for _, rec := range records {
		if rec == "" {
			continue
		}
		name := rec
		if i := strings.Index(rec, "|"); i >= 0 {
			name = rec[:i]
		}
		rest := rec
		if i := strings.Index(rec, "|"); i >= 0 {
			rest = rec[i+1:]
		}
		transport, url := rest, rest
		if i := strings.Index(rest, "|"); i >= 0 {
			transport, url = rest[:i], rest[i+1:]
		}
		entry := jqjson.NewObject()
		entry, _ = entry.Set("type", jqjson.Str(transport))
		entry, _ = entry.Set("url", jqjson.Str(url))
		servers, _ = servers.Set(name, entry)
	}
	if agent != "claude" {
		return "", fmt.Errorf("ERROR: render_agent_mcp_config: agent '%s' has no MCP wiring.", agent)
	}
	out := jqjson.NewObject()
	out, _ = out.Set("mcpServers", servers)
	return jqjson.Encode(out), nil
}

// CredentialType is get_agent_credential_type.
func CredentialType(agent string) string {
	switch agent {
	case "claude", "codex", "copilot", "grok":
		return "oauth"
	case "opencode":
		return "apikey"
	}
	return "unknown"
}

// HostEnvBlocklist and HostEnvBlocklistPrefixes are HOST_ENV_BLOCKLIST and
// HOST_ENV_BLOCKLIST_PATTERNS: host variables never passed into a sandbox.
var (
	HostEnvBlocklist = []string{"KUBECONFIG", "SSH_AUTH_SOCK", "DOCKER_HOST", "KUBERNETES_SERVICE_HOST",
		"KUBERNETES_SERVICE_PORT", "COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "GROK_DEPLOYMENT_KEY"}
	HostEnvBlocklistPrefixes = []string{"OS_", "AWS_", "GOOGLE_", "AZURE_", "TELEPORT_", "TSH_", "ANTHROPIC_", "OPENAI_"}
)

var exportedName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// CheckHostEnv is check_host_env_not_leaked: an advisory warning per blocked variable set in the
// host environment (environ, as os.Environ), and a summary line on stdout.
//
// In legacy mode the prefix matches come from `env` output read line by line, so a value
// containing a newline followed by a blocked prefix reports a variable that does not exist, and a
// prefix-matched variable counts even when empty; with EnvCheckByName the names come from the
// environment entries and an empty value does not count, as for the exact names. (The bash's
// OPENCODE_API_KEY exemption never applied: no prefix matches it.)
func CheckHostEnv(agent string, environ []string) (stderr, stdout []string) {
	val := map[string]string{}
	for _, e := range environ {
		if k, v, ok := strings.Cut(e, "="); ok {
			if _, seen := val[k]; !seen {
				val[k] = v
			}
		}
	}
	n := 0
	warn := func(name string) {
		stderr = append(stderr, fmt.Sprintf("  WARN: Host env var '%s' is set. It will NOT be passed to the sandbox.", name))
		n++
	}
	for _, v := range HostEnvBlocklist {
		if val[v] != "" {
			warn(v)
		}
	}
	byName := deviation.Fixed(deviation.EnvCheckByName)
	for _, p := range HostEnvBlocklistPrefixes {
		if byName {
			for _, e := range environ {
				k, v, _ := strings.Cut(e, "=")
				if strings.HasPrefix(k, p) && v != "" && exportedName.MatchString(k) {
					warn(k)
				}
			}
			continue
		}
		for _, e := range environ {
			for _, line := range strings.Split(e, "\n") {
				if !strings.HasPrefix(line, p) {
					continue
				}
				name := line
				if i := strings.Index(line, "="); i >= 0 {
					name = line[:i]
				}
				if name == "OPENCODE_API_KEY" && agent == "opencode" {
					continue
				}
				warn(name)
			}
		}
	}
	if n > 0 {
		stdout = append(stdout, fmt.Sprintf("  %d host env var(s) detected that will be blocked.", n))
	}
	return stderr, stdout
}
