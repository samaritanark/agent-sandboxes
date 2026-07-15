#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/agents.sh — Agent profiles and domain lists
set -euo pipefail

# VALID_AGENTS — supported agent identifiers
VALID_AGENTS=("claude" "codex" "opencode" "copilot" "grok")

# validate_agent — die if agent is not supported
validate_agent() {
  local agent="$1"
  case "${agent}" in
    claude|codex|opencode|copilot|grok) return 0 ;;
    *)
      echo "ERROR: Unknown agent '${agent}'. Valid agents: claude, codex, opencode, copilot, grok." >&2
      echo " " >&2
      exit 1
      ;;
  esac
}

# get_agent_domains — print newline-separated list of allowed domains for agent
get_agent_domains() {
  local agent="$1"
  case "${agent}" in
    claude)
      # Claude Code spans claude.ai AND claude.com (endpoints are migrating to
      # claude.com — login/OAuth uses platform.claude.com). The apex + wildcard
      # pair for each covers the apex itself plus subdomains like
      # downloads.claude.ai (update fetches) and platform.claude.com (login).
      # Both wildcards previously "worked" only because the old wildcard DNS
      # rule let claude.com resolve and it shares CDN IPs already cached from
      # claude.ai; with the DNS proxy scoped to this allowlist, claude.com must
      # be listed explicitly or login fails (no DNS resolution).
      cat <<'EOF'
claude.ai
*.claude.ai
claude.com
*.claude.com
api.anthropic.com
console.anthropic.com
statsig.anthropic.com
sentry.io
EOF
      ;;
    codex)
      cat <<'EOF'
api.openai.com
auth.openai.com
auth0.openai.com
chatgpt.com
cdn.openai.com
EOF
      ;;
    copilot)
      # GitHub Copilot CLI (@github/copilot). Unlike claude/codex, whose control
      # planes are narrow SaaS hostnames, Copilot's control plane IS github.com +
      # api.github.com — the same hosts a Tier 2 session uses for git. So a Tier 1
      # Copilot sandbox is inherently less isolated than a Tier 1 Claude sandbox:
      # the agent cannot reach its brain without github.com being resolvable. That
      # is an accepted, documented cost of this agent (see README / PRINCIPLES.md);
      # the FQDN allowlist still forecloses arbitrary egress, and the coupled L7
      # DNS filter (lib/policy.sh) still closes the resolver-tunnel channel.
      #
      #   github.com                       login + /copilot/* control paths
      #   api.github.com                   /user + /copilot_internal/* token+config
      #   *.githubcopilot.com              model API/proxy for the plan-agnostic
      #                                    hosts (e.g. api.githubcopilot.com)
      #   *.individual.githubcopilot.com   Free/Pro (individual) plan namespace
      #   *.business.githubcopilot.com     Business plan namespace
      #   *.enterprise.githubcopilot.com   Enterprise plan namespace
      #
      # The per-plan namespaces are REQUIRED and cannot be folded into the bare
      # *.githubcopilot.com pattern: a Cilium DNS matchPattern turns '*' into
      # [-a-zA-Z0-9_]* (a single label — it does not cross a dot), so
      # *.githubcopilot.com matches api.githubcopilot.com but never the two-label
      # api.individual.githubcopilot.com the Free/Pro plan actually routes model
      # traffic AND the bundled github-mcp-server through. Each plan namespace has
      # multiple subdomains (api, proxy, telemetry, ...), so GitHub's own firewall
      # docs prescribe a per-plan wildcard rather than enumerated hosts:
      # https://docs.github.com/en/copilot/reference/copilot-allowlist-reference
      #
      #   copilot-proxy.githubusercontent.com   completions proxy
      #   origin-tracker.githubusercontent.com  content attribution
      #   copilot-telemetry.githubusercontent.com  telemetry
      #   collector.github.com             analytics
      #   default.exp-tas.com              feature experimentation
      cat <<'EOF'
github.com
api.github.com
*.githubcopilot.com
*.individual.githubcopilot.com
*.business.githubcopilot.com
*.enterprise.githubcopilot.com
copilot-proxy.githubusercontent.com
origin-tracker.githubusercontent.com
copilot-telemetry.githubusercontent.com
collector.github.com
default.exp-tas.com
EOF
      ;;
    grok)
      # Official xAI Grok Build CLI (`grok`, installed from x.ai/cli/install.sh).
      # Auth is OAuth (grok login --device-auth in the pod) against auth.x.ai; the
      # OAuth token persists to ~/.grok/auth.json. Unlike Copilot, the control
      # plane is a set of narrow xAI SaaS hostnames, so a Tier 1 Grok sandbox is
      # as isolated as a Tier 1 Claude one.
      #
      #   api.x.ai          model API (/v1/responses, ...)
      #   accounts.x.ai     OAuth 2.0 PKCE account/authorize endpoints
      #   auth.x.ai         device-code login flow (grok login --device-auth)
      #   grok.com          SuperGrok subscription surface used during login
      #
      # All plain matchName hosts — no wildcards needed. NOTE: api.x.ai is not a
      # pure model-inference channel — Grok's server-side web_search/x_search
      # tools run on xAI and stream web/X content back over it, invisibly to this
      # allowlist. Those tools (and client-side web_fetch) are removed at launch
      # by get_agent_sandbox_flags, so web access flows through curl/wget, whose
      # pod-originated egress this allowlist DOES bound. See that function.
      cat <<'EOF'
api.x.ai
accounts.x.ai
auth.x.ai
grok.com
EOF
      ;;
    opencode)
      # Egress for opencode is restricted to the single OpenAI-compatible
      # endpoint hostname extracted from OPENCODE_BASE_URL (e.g. an OpenAI
      # proxy, an internal vLLM/Ollama instance, or api.openai.com itself
      # — whichever the operator has chosen to route through).
      local host
      host="$(resolve_inference_endpoint opencode)"
      if [[ -z "${host}" ]]; then
        if [[ -n "${OPENCODE_BASE_URL:-}" ]]; then
          echo "ERROR: OPENCODE_BASE_URL ('${OPENCODE_BASE_URL}') has no host." >&2
          echo "  Set it to the full URL of an OpenAI-compatible endpoint, e.g." >&2
          echo "  https://api.openai.com/v1 or https://vllm.internal:8000/v1." >&2
        else
          echo "ERROR: OPENCODE_BASE_URL not set in host environment." >&2
          echo "  Set it to the URL of an OpenAI-compatible endpoint." >&2
        fi
        exit 1
      fi
      echo "${host}"
      ;;
    *)
      echo "ERROR: Unknown agent: ${agent}" >&2
      exit 1
      ;;
  esac
}

# resolve_inference_endpoint <agent> — print the bare hostname of the model
# inference endpoint this agent talks to, or NOTHING if the agent uses a fixed
# vendor API (claude/codex/grok) or the endpoint is unconfigured. Unlike
# get_agent_domains this is PURE: it never errors or exits, so callers can probe
# an endpoint's identity without committing to a launch. An empty result means
# "no caller-chosen endpoint", which callers treat as untrusted.
#
# Today only opencode has an operator-chosen endpoint (OPENCODE_BASE_URL). The
# scheme, userinfo, path, and port are stripped so the result is the same
# bare-host form the egress allowlist uses and that inference_endpoint_is_trusted
# matches against the overlay's trusted_inference_endpoints list.
#
# Userinfo (`user:pass@`) MUST be stripped before the port: the port strip cuts
# at the first colon, which in `user:pass@host` is the userinfo separator, not
# the port. Without the `##*@` step a URL like `https://trusted:x@evil.com/v1`
# would resolve to `trusted` — matching the trusted list while the client dials
# evil.com. Path is dropped first so an `@` embedded in the path can't be
# mistaken for a userinfo separator. A URL with no host after the userinfo
# (`https://user@/v1`) resolves to empty, which callers treat as untrusted /
# unconfigured (fail closed).
resolve_inference_endpoint() {
  local agent="$1"
  case "${agent}" in
    opencode)
      local base_url="${OPENCODE_BASE_URL:-}"
      [[ -n "${base_url}" ]] || return 0
      local host="${base_url#*://}"
      host="${host%%/*}"      # drop path
      host="${host##*@}"      # drop userinfo (before the port strip below)
      host="${host%%:*}"      # drop port
      echo "${host}"
      ;;
    *) return 0 ;;
  esac
}

# get_agent_session_id_flag — print the CLI flag a fresh agent session uses to
# accept a caller-supplied conversation ID, or nothing if the agent has no such
# flag. A deterministic ID lets the audit layer copy the exact transcript file
# for this session instead of correlating by modification time, which is
# ambiguous when two sessions of the same agent run concurrently (lib/audit.sh).
get_agent_session_id_flag() {
  case "$1" in
    claude) echo "--session-id" ;;
    *)      echo "" ;;
  esac
}

# get_agent_resume_flag — print the CLI flag used to re-attach to an existing
# conversation by ID, or nothing if unsupported. Used by 'sandbox resume' so a
# reconnect continues the same conversation (and the same transcript file).
get_agent_resume_flag() {
  case "$1" in
    claude) echo "--resume" ;;
    *)      echo "" ;;
  esac
}

# get_agent_sandbox_flags — print extra per-agent launch flags that harden the
# session's security posture, or nothing if the agent needs none. Two agents use
# this hook today.
#
# Codex ("--sandbox danger-full-access"): disables Codex's OWN in-process OS
# sandbox (bubblewrap), whose netns setup configures loopback via a netlink
# RTM_NEWADDR call gVisor doesn't emulate — so bwrap aborts ("loopback: Failed
# RTM_NEWADDR: No child processes") before Codex can even read a file. The pod
# already IS the boundary (gVisor kernel isolation + Cilium default-deny egress +
# filesystem masking), so that inner sandbox is redundant as well as broken. The
# flag is sandbox-only and leaves "--ask-for-approval" (Codex's human-in-the-loop
# prompts) untouched, so it is NOT a bypass-approvals posture. It also duplicates
# the intent of the staged config.toml sandbox_mode key (lib/onboard.sh) on
# purpose, as defense-in-depth: the launch flag overrides config and so works
# even when an agent-home was staged before this change (no 're-run sandbox
# onboard' required), when a pre-existing sandbox_mode key would otherwise be
# left alone, or when Codex rewrites config.toml at runtime.
#
# Grok ("--disallowed-tools web_search,x_search,web_fetch"): removes Grok's
# built-in web tools from the model request. web_search and x_search are
# SERVER-SIDE tools — xAI executes the crawl and only the allowed api.x.ai
# channel is dialed — so Cilium's egress allowlist can neither see nor bound
# them; dropping them client-side, before the request leaves the pod, is the
# only control. ("--disable-web-search" is insufficient: it drops web_search but
# leaves x_search live — verified against grok 0.2.93.) web_fetch is dropped too
# so all web access is forced onto curl/wget in the shell, which egresses from
# the pod and IS bound by the Cilium allowlist — making that allowlist the single
# source of truth, with no parallel web_fetch domain list to keep in sync. This
# is defense-in-depth with the pod egress policy and leaves Grok's approval
# prompts untouched, so shell fetches stay human-gated (verified: grok reaches
# for curl unprompted, and the interactive session still asks before running it).
get_agent_sandbox_flags() {
  case "$1" in
    codex) echo "--sandbox danger-full-access" ;;
    grok)  echo "--disallowed-tools web_search,x_search,web_fetch" ;;
    *)     echo "" ;;
  esac
}

# Where a per-session MCP config is mounted inside the pod. A dedicated dir
# (NOT the shared agent-home hostPath) so the config is session-scoped: the
# agent-home mount is reused across every session of an agent, and writing a
# session's MCP servers there would race concurrent sessions and leak a
# torn-down dependency's endpoint into the next session. The config lands here
# via a per-session ConfigMap mounted read-only (lib/manifest.sh). (Phase 5)
SANDBOX_MCP_CONFIG_DIR="/home/agent/.sandbox-mcp"
SANDBOX_MCP_CONFIG_FILE="config.json"

# agent_supports_mcp <agent> — return 0 if this CLI's per-session MCP wiring is
# implemented. Claude is the reference. Codex (config.toml [mcp_servers]) and
# opencode (mcp config) have native MCP support but are not wired here yet, so
# they fail closed: a profile that declares mcps: for them is a hard error
# rather than a silently-ignored dependency.
agent_supports_mcp() {
  case "$1" in
    claude) return 0 ;;
    *)      return 1 ;;
  esac
}

# get_agent_mcp_launch_args <agent> — print the launch flags that load ONLY the
# session MCP config file, one token per line (caller reads into an array). For
# Claude: --mcp-config <file> --strict-mcp-config, where --strict-mcp-config
# makes Claude ignore every other MCP source (project/user) and use exactly the
# session-scoped file — so the agent sees the declared dependencies and nothing
# else. Empty output for agents without MCP wiring.
get_agent_mcp_launch_args() {
  local agent="$1"
  case "${agent}" in
    claude)
      printf '%s\n' "--mcp-config" "${SANDBOX_MCP_CONFIG_DIR}/${SANDBOX_MCP_CONFIG_FILE}" "--strict-mcp-config"
      ;;
    *) : ;;
  esac
}

# render_agent_mcp_config <agent> <name|transport|url> [...] — print the MCP
# config file content for the agent. Built with jq (a required tool, see
# check_prerequisites) so names/URLs are safely JSON-encoded. For Claude the
# shape is {"mcpServers": {"<name>": {"type": "http"|"sse", "url": "..."}}}.
render_agent_mcp_config() {
  local agent="$1"
  shift

  local servers="{}"
  local rec name rest transport url
  for rec in "$@"; do
    [[ -z "${rec}" ]] && continue
    name="${rec%%|*}"
    rest="${rec#*|}"
    transport="${rest%%|*}"
    url="${rest#*|}"
    servers="$(echo "${servers}" \
      | jq --arg n "${name}" --arg t "${transport}" --arg u "${url}" \
           '.[$n] = {type: $t, url: $u}')"
  done

  case "${agent}" in
    claude) echo "${servers}" | jq '{mcpServers: .}' ;;
    *)
      echo "ERROR: render_agent_mcp_config: agent '${agent}' has no MCP wiring." >&2
      return 1
      ;;
  esac
}

# get_agent_credential_type — returns "oauth" or "apikey"
get_agent_credential_type() {
  local agent="$1"
  case "${agent}" in
    claude|codex|copilot|grok)  echo "oauth" ;;
    opencode)              echo "apikey" ;;
    *)                     echo "unknown" ;;
  esac
}
