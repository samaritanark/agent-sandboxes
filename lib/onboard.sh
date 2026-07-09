#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/onboard.sh — One-time host-to-sandbox credential staging
#
# 'sandbox onboard' copies an operator's existing host-side agent CLI
# state into ~/.sandbox/agent-home/<agent>/ so the first sandbox session
# uses already-authenticated OAuth tokens instead of triggering a fresh
# login. It only touches OAuth state and benign settings files — see
# PRINCIPLES.md ("Credential isolation", rule 1):
#
#   "Agents never hold long-lived API keys directly. Provider credentials
#    (LLM keys, cloud tokens) are injected at runtime via Kubernetes
#    Secrets keyed to the session, not baked into images, config files,
#    or shell rcs that the agent could read."
#
# So:
#   - claude / codex (OAuth): onboard stages the credential file.
#   - opencode (API key): onboard refuses and points the operator at
#     'sandbox secret' (Phase 4), which keeps the key host-side and
#     injects a session-scoped K8s Secret at launch.
#
# Files copied per agent (best-effort; missing files are skipped silently):
#
#   claude  ~/.claude/.credentials.json  → ~/.sandbox/agent-home/claude/.credentials.json
#           ~/.claude/settings.json       → ~/.sandbox/agent-home/claude/settings.json
#
#   codex   ~/.codex/auth.json            → ~/.sandbox/agent-home/codex/auth.json
#           ~/.codex/config.toml          → ~/.sandbox/agent-home/codex/config.toml
#
#   copilot ~/.copilot/config.json        → ~/.sandbox/agent-home/copilot/config.json
#
#   grok    ~/.grok/auth.json             → ~/.sandbox/agent-home/grok/auth.json
#           ~/.grok/config.toml           → ~/.sandbox/agent-home/grok/config.toml
#                                           (only when it pins no per-model key)
#
# Copilot onboard is best-effort by nature: the CLI stores its OAuth token in
# the OS keychain when one is available (typical on a macOS/Linux-desktop host),
# in which case ~/.copilot/config.json holds no token and there is nothing to
# copy. That is fine — the pod has no keychain/libsecret, so the first in-pod
# 'copilot login' (device flow) writes the token to the plaintext config.json in
# the mounted agent-home, where it then persists across sessions. Onboard only
# short-circuits that first login when the host already keeps a plaintext token
# (headless Linux host, or one without libsecret).
#
# Grok is likewise best-effort: ~/.grok/auth.json exists only after a host-side
# 'grok login'. When absent, onboard is a no-op and the first in-pod 'grok login
# --device-auth' persists the token into the mounted agent-home. config.toml is
# staged only when it carries no per-model api_key/env_key — such a key outranks
# the OAuth session token and would defeat the OAuth-only path (see _onboard_grok).
#
# Conversation history (~/.claude/projects/, ~/.codex/sessions/,
# ~/.copilot/history/, ~/.grok/sessions/) is intentionally NOT copied — the
# sandbox starts fresh.
set -euo pipefail

ONBOARD_AGENT_HOME_BASE="${HOME}/.sandbox/agent-home"

# Forbidden host env vars: onboard never persists these and warns if
# they're set. Matches lib/credentials.sh:HOST_ENV_BLOCKLIST_PATTERNS for
# the LLM-provider keys; the runtime block remains the source of truth.
ONBOARD_FORBIDDEN_ENV=(
  "ANTHROPIC_API_KEY"
  "ANTHROPIC_AUTH_TOKEN"
  "OPENAI_API_KEY"
  "COPILOT_GITHUB_TOKEN"
  "GH_TOKEN"
  "GITHUB_TOKEN"
  "GROK_DEPLOYMENT_KEY"
)

# warn_forbidden_env — emit a warning for each forbidden var that's
# currently set in the host shell. Returns the count via stdout for the
# caller's summary line.
warn_forbidden_env() {
  local count=0
  local var
  for var in "${ONBOARD_FORBIDDEN_ENV[@]}"; do
    if [[ -n "${!var:-}" ]]; then
      echo "  WARN: host env '${var}' is set." >&2
      echo "        onboard will NOT copy it. PRINCIPLES.md rule 1 forbids" >&2
      echo "        baking long-lived API keys into agent state." >&2
      (( count++ )) || true
    fi
  done
  echo "${count}"
}

# stage_file — copy <src> to <dst> with mode 0600. Honors --dry-run /
# --force semantics from the caller via the two boolean args.
#
# Args: stage_file <src> <dst> <dry_run:true|false> <force:true|false>
# Returns the action via stdout: "copied" | "skipped-exists" | "missing-src"
stage_file() {
  local src="$1"
  local dst="$2"
  local dry_run="$3"
  local force="$4"

  if [[ ! -f "${src}" ]]; then
    echo "missing-src"
    return 0
  fi

  if [[ -f "${dst}" ]] && [[ "${force}" != "true" ]]; then
    echo "skipped-exists"
    return 0
  fi

  if [[ "${dry_run}" == "true" ]]; then
    echo "copied"
    return 0
  fi

  mkdir -p "$(dirname "${dst}")"
  cp -f "${src}" "${dst}"
  chmod 0600 "${dst}"
  echo "copied"
}

# print_stage_result — pretty-print a stage_file outcome with a
# host-relative source path for readability.
print_stage_result() {
  local agent="$1" src="$2" dst="$3" result="$4"
  local src_disp="${src/#${HOME}/\~}"
  local dst_disp="${dst/#${HOME}/\~}"
  case "${result}" in
    copied)
      echo "  ${agent}: staged ${src_disp} → ${dst_disp}"
      ;;
    skipped-exists)
      echo "  ${agent}: ${dst_disp} already exists — re-run with --force to overwrite."
      ;;
    missing-src)
      echo "  ${agent}: no host-side state at ${src_disp} — skipping."
      ;;
  esac
}

# onboard_agent <agent> <dry_run> <force> — stage OAuth state + settings
# for one agent. Returns 0 if any file was actionable (copied or
# skipped-existing), or for opencode which always exits 0 after
# printing the refusal. Caller decides what to print summary-wise.
onboard_agent() {
  local agent="$1"
  local dry_run="$2"
  local force="$3"

  case "${agent}" in
    claude)
      _onboard_claude "${dry_run}" "${force}"
      ;;
    codex)
      _onboard_codex "${dry_run}" "${force}"
      ;;
    copilot)
      _onboard_copilot "${dry_run}" "${force}"
      ;;
    grok)
      _onboard_grok "${dry_run}" "${force}"
      ;;
    opencode)
      _onboard_opencode_refuse
      ;;
    *)
      echo "  ${agent}: not a known agent — skipping." >&2
      return 1
      ;;
  esac
}

_onboard_claude() {
  local dry_run="$1" force="$2"
  local agent_home="${ONBOARD_AGENT_HOME_BASE}/claude"
  mkdir -p "${agent_home}"

  local src dst result
  for pair in \
    "${HOME}/.claude/.credentials.json|${agent_home}/.credentials.json" \
    "${HOME}/.claude/settings.json|${agent_home}/settings.json"
  do
    src="${pair%|*}"
    dst="${pair##*|}"
    result="$(stage_file "${src}" "${dst}" "${dry_run}" "${force}")"
    print_stage_result claude "${src}" "${dst}" "${result}"
  done
}

_onboard_codex() {
  local dry_run="$1" force="$2"
  local agent_home="${ONBOARD_AGENT_HOME_BASE}/codex"
  mkdir -p "${agent_home}"

  local src dst result
  for pair in \
    "${HOME}/.codex/auth.json|${agent_home}/auth.json" \
    "${HOME}/.codex/config.toml|${agent_home}/config.toml"
  do
    src="${pair%|*}"
    dst="${pair##*|}"
    result="$(stage_file "${src}" "${dst}" "${dry_run}" "${force}")"
    print_stage_result codex "${src}" "${dst}" "${result}"
  done

  ensure_codex_sandbox_mode "${agent_home}/config.toml" "${dry_run}"
}

# ensure_codex_sandbox_mode <config.toml> <dry_run> — guarantee the staged
# Codex config disables Codex's own OS-level sandbox.
#
# Codex wraps every shell/apply_patch operation in bubblewrap. Inside our
# pods that inner sandbox unshares a netns and configures loopback via a
# netlink RTM_NEWADDR call that gVisor doesn't emulate, so bwrap aborts
# ("loopback: Failed RTM_NEWADDR: No child processes") before Codex can
# even read a file. The pod already IS the boundary (gVisor kernel
# isolation + Cilium default-deny egress + filesystem masking), so the
# inner layer is redundant as well as broken. sandbox_mode =
# "danger-full-access" turns off ONLY that inner OS-sandbox: pod egress
# stays default-deny via Cilium regardless, and approval_policy (Codex's
# human-in-the-loop prompts) is a separate setting left untouched.
#
# top-level TOML keys must precede any [table] header, so we PREPEND rather
# than append (a staged config may open with [projects.*] / [tui.*]).
# Idempotent: if any sandbox_mode key is already present we leave the
# operator's choice alone and only note it.
ensure_codex_sandbox_mode() {
  local cfg="$1" dry_run="$2"
  local cfg_disp="${cfg/#${HOME}/\~}"

  if [[ -f "${cfg}" ]] && grep -qE '^[[:space:]]*sandbox_mode[[:space:]]*=' "${cfg}"; then
    echo "  codex: ${cfg_disp} already sets sandbox_mode — leaving it as-is."
    return 0
  fi

  if [[ "${dry_run}" == "true" ]]; then
    echo "  codex: would set sandbox_mode=\"danger-full-access\" in ${cfg_disp}"
    return 0
  fi

  local header
  header="$(cat <<'TOML'
# Added by 'sandbox onboard'. The pod already isolates this agent (gVisor +
# Cilium default-deny egress + filesystem masking), so Codex's own
# bubblewrap sandbox is redundant — and it cannot start under gVisor
# (bwrap loopback RTM_NEWADDR failure), which blocks apply_patch. This
# disables only that inner OS-sandbox; egress and approval prompts are
# unaffected. Remove this line to restore Codex's built-in sandboxing.
sandbox_mode = "danger-full-access"
TOML
)"

  mkdir -p "$(dirname "${cfg}")"
  if [[ -f "${cfg}" ]]; then
    printf '%s\n\n%s' "${header}" "$(cat "${cfg}")" > "${cfg}.tmp"
    mv "${cfg}.tmp" "${cfg}"
  else
    printf '%s\n' "${header}" > "${cfg}"
  fi
  chmod 0600 "${cfg}"
  echo "  codex: set sandbox_mode=\"danger-full-access\" in ${cfg_disp}"
}

_onboard_copilot() {
  local dry_run="$1" force="$2"
  local agent_home="${ONBOARD_AGENT_HOME_BASE}/copilot"
  mkdir -p "${agent_home}"

  # Only config.json (the plaintext-token store) is staged. When the host keeps
  # its token in the keychain instead, this is a no-op ("missing-src") and the
  # first in-pod 'copilot login' establishes the token durably in the mounted
  # agent-home — see the file-header note.
  local src dst result
  for pair in \
    "${HOME}/.copilot/config.json|${agent_home}/config.json"
  do
    src="${pair%|*}"
    dst="${pair##*|}"
    result="$(stage_file "${src}" "${dst}" "${dry_run}" "${force}")"
    print_stage_result copilot "${src}" "${dst}" "${result}"
  done
}

_onboard_grok() {
  local dry_run="$1" force="$2"
  local agent_home="${ONBOARD_AGENT_HOME_BASE}/grok"
  mkdir -p "${agent_home}"

  # Stage the OAuth token. Absent until the operator has run 'grok login' on the
  # host — in which case this is a no-op ("missing-src") and the first in-pod
  # 'grok login --device-auth' writes the token durably into the mounted
  # agent-home (same pattern as copilot).
  local result
  result="$(stage_file "${HOME}/.grok/auth.json" "${agent_home}/auth.json" "${dry_run}" "${force}")"
  print_stage_result grok "${HOME}/.grok/auth.json" "${agent_home}/auth.json" "${result}"

  # Stage config.toml ONLY when it pins no per-model credential. Grok resolves
  # credentials model.api_key > model.env_key > OAuth session token > XAI_API_KEY,
  # so a config that hard-codes a model api_key/env_key would silently outrank the
  # OAuth token — baking a long-lived key into agent state (PRINCIPLES.md rule 1).
  # Refuse that file and keep OAuth device flow the only path in.
  local src_cfg="${HOME}/.grok/config.toml"
  local dst_cfg="${agent_home}/config.toml"
  local src_cfg_disp="${src_cfg/#${HOME}/\~}"
  if [[ -f "${src_cfg}" ]] && grep -qE '^[[:space:]]*(api_key|env_key)[[:space:]]*=' "${src_cfg}"; then
    echo "  grok: ${src_cfg_disp} pins a per-model api_key/env_key — NOT staging it."
    echo "        That key would outrank the OAuth session token (PRINCIPLES.md"
    echo "        rule 1). Authenticate in-pod with 'grok login --device-auth'."
  else
    result="$(stage_file "${src_cfg}" "${dst_cfg}" "${dry_run}" "${force}")"
    print_stage_result grok "${src_cfg}" "${dst_cfg}" "${result}"
  fi
}

_onboard_opencode_refuse() {
  echo "  opencode: refused — opencode authenticates with an API key, not"
  echo "            OAuth. PRINCIPLES.md rule 1 forbids baking long-lived"
  echo "            API keys into agent state. Use 'sandbox secret set"
  echo "            opencode-api-key' (Phase 4) instead; the secret is"
  echo "            kept host-side and injected as a session-scoped K8s"
  echo "            Secret at launch, then deleted on teardown."
}

# write_starter_user_config <dry_run> <force> — write a commented
# starter ~/.sandbox/config.yaml so the operator can see the available
# keys (extra_allowed_domains, overlay) without digging through docs.
# Idempotent unless --force.
write_starter_user_config() {
  local dry_run="$1" force="$2"
  local dst="${HOME}/.sandbox/config.yaml"

  if [[ -f "${dst}" ]] && [[ "${force}" != "true" ]]; then
    echo "  config: ${dst/#${HOME}/\~} already exists — leaving it alone."
    return 0
  fi

  if [[ "${dry_run}" == "true" ]]; then
    echo "  config: would write starter ${dst/#${HOME}/\~}"
    return 0
  fi

  mkdir -p "$(dirname "${dst}")"
  cat > "${dst}" <<'YAML'
# ~/.sandbox/config.yaml
#
# Per-user defaults for sandbox sessions. See docs/how-to/persistent-domains.md
# and docs/how-to/profiles-and-overlays.md for the full schema.
# All keys below are optional.

# Extra allowed egress domains, merged with the tier defaults on every
# run. Subject to the org-level blocked-destinations check (and the
# overlay's, if one is configured).
# extra_allowed_domains:
#   - internal-registry.example.com
#   - artifactory.example.com

# Path to a team overlay directory (ships profiles/, GOVERNANCE.md, an
# additional blocked-destinations.yaml, and extra-ca-certs/). See
# examples/overlay-template/. Overlays can only ADD restrictions; they
# cannot weaken org-level controls or the tier model.
# overlay: ~/overlays/myteam
#
# If your team's overlay lives in a (private) git repo, don't set 'overlay:'
# by hand — run 'sandbox link <git-url>' and it will clone the repo, pin it
# to a ref, and manage the overlay/link_url/link_ref/link_commit keys here
# for you. See 'sandbox link --help'.
YAML
  chmod 0600 "${dst}"
  echo "  config: wrote starter ${dst/#${HOME}/\~}"
}
