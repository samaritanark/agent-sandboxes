#!/usr/bin/env bash
# lib/agents.sh — Agent profiles and domain lists
set -euo pipefail

# VALID_AGENTS — supported agent identifiers
VALID_AGENTS=("claude" "codex" "opencode")

# validate_agent — die if agent is not supported
validate_agent() {
  local agent="$1"
  case "${agent}" in
    claude|codex|opencode) return 0 ;;
    *)
      echo "ERROR: Unknown agent '${agent}'. Valid agents: claude, codex, opencode." >&2
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
      # *.claude.ai covers downloads.claude.ai (Claude Code update fetches)
      # and any other claude.ai subdomain; matchName claude.ai keeps the apex.
      cat <<'EOF'
claude.ai
*.claude.ai
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
    opencode)
      # Egress for opencode is restricted to the single OpenAI-compatible
      # endpoint hostname extracted from OPENCODE_BASE_URL (e.g. an OpenAI
      # proxy, an internal vLLM/Ollama instance, or api.openai.com itself
      # — whichever the operator has chosen to route through).
      local base_url="${OPENCODE_BASE_URL:-}"
      if [[ -z "${base_url}" ]]; then
        echo "ERROR: OPENCODE_BASE_URL not set in host environment." >&2
        echo "  Set it to the URL of an OpenAI-compatible endpoint." >&2
        exit 1
      fi
      local host="${base_url#*://}"
      host="${host%%/*}"
      host="${host%%:*}"
      echo "${host}"
      ;;
    *)
      echo "ERROR: Unknown agent: ${agent}" >&2
      exit 1
      ;;
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

# get_agent_credential_type — returns "oauth" or "apikey"
get_agent_credential_type() {
  local agent="$1"
  case "${agent}" in
    claude|codex)  echo "oauth" ;;
    opencode)      echo "apikey" ;;
    *)             echo "unknown" ;;
  esac
}
