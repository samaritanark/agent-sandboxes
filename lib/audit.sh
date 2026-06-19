#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/audit.sh — Audit log management
set -euo pipefail

# audit_write_session_json — write initial session.json metadata
audit_write_session_json() {
  local log_dir="$1"
  local session_id="$2"
  local agent="$3"
  local tier="$4"
  local user="$5"
  # 6th arg is either a single repo path (legacy single-repo callers / tests)
  # or a JSON array of repo paths (new multi-repo callers). We always emit
  # `.repos` as an array in session.json.
  local repo_or_repos="${6:-}"
  local name="${7:-}"
  local pod_name="${8:-}"
  local start_time="$9"
  shift 9
  local -a domains=("$@")

  local retention_days
  retention_days="$(get_tier_retention_days "${tier}")"

  local repos_json
  if [[ -z "${repo_or_repos}" ]]; then
    repos_json="[]"
  elif [[ "${repo_or_repos:0:1}" == "[" ]]; then
    repos_json="${repo_or_repos}"
  else
    repos_json="$(printf '%s' "${repo_or_repos}" | jq -R '[.]' -c)"
  fi

  # Build domains JSON array
  local domains_json="["
  local first=1
  for domain in "${domains[@]+"${domains[@]}"}"; do
    if [[ "${first}" -eq 0 ]]; then
      domains_json+=","
    fi
    domains_json+="\"${domain}\""
    first=0
  done
  domains_json+="]"

  local credential_type
  credential_type="$(get_agent_credential_type "${agent}")"

  # Several fields are read from the calling shell's env so adding them
  # didn't require changing this function's signature (which has many
  # call sites in tests/test-audit.sh):
  #   SESSION_PROFILE / SESSION_OVERLAY — Phase 2 audit hooks
  #   SESSION_KUBE_API_CIDR / SESSION_KUBE_API_PORT — Tier 3 + --infra-kubeconfig
  #     metadata that 'sandbox allow' needs to rebuild the policy without
  #     re-resolving the kube API server. Empty for Tier 1/2.
  jq -n \
    --arg id "${session_id}" \
    --arg agent "${agent}" \
    --argjson tier "${tier}" \
    --arg user "${user}" \
    --argjson repos "${repos_json}" \
    --arg name "${name}" \
    --arg pod_name "${pod_name}" \
    --arg start_time "${start_time}" \
    --arg credential_type "${credential_type}" \
    --argjson domains "${domains_json}" \
    --argjson retention_days "${retention_days}" \
    --arg profile "${SESSION_PROFILE:-}" \
    --arg overlay "${SESSION_OVERLAY:-}" \
    --arg kube_api_cidr "${SESSION_KUBE_API_CIDR:-}" \
    --arg kube_api_port "${SESSION_KUBE_API_PORT:-}" \
    '{
      id: $id,
      agent: $agent,
      tier: $tier,
      user: $user,
      repos: $repos,
      name: $name,
      pod_name: $pod_name,
      start_time: $start_time,
      end_time: null,
      agent_session_id: null,
      credential_type: $credential_type,
      profile: $profile,
      overlay: $overlay,
      kube_api_cidr: $kube_api_cidr,
      kube_api_port: $kube_api_port,
      allowed_domains: $domains,
      retention_days: $retention_days
    }' > "${log_dir}/session.json"

  echo "  Wrote session.json: ${log_dir}/session.json"
}

# audit_update_end_time — write end_time into session.json
audit_update_end_time() {
  local log_dir="$1"
  local end_time="$2"
  local session_json="${log_dir}/session.json"

  if [[ ! -f "${session_json}" ]]; then
    return 0
  fi

  local tmp
  tmp="$(mktemp)"
  jq --arg end_time "${end_time}" \
    '.end_time = $end_time' \
    "${session_json}" > "${tmp}"
  mv "${tmp}" "${session_json}"
}

# audit_record_agent_session_id — store the agent's pinned conversation ID
# into session.json so teardown can locate the exact transcript file.
audit_record_agent_session_id() {
  local log_dir="$1"
  local agent_session_id="$2"
  local session_json="${log_dir}/session.json"

  if [[ ! -f "${session_json}" ]]; then
    return 0
  fi

  local tmp
  tmp="$(mktemp)"
  jq --arg id "${agent_session_id}" \
    '.agent_session_id = $id' \
    "${session_json}" > "${tmp}"
  mv "${tmp}" "${session_json}"
}

# audit_record_dependencies — store the resolved per-session dependency records
# (Phase 5 §2.6) into session.json: which dependencies were brought up, their
# resolved catalogue versions, their resolved egress allowlists, and their
# up-timestamps. The down-timestamp is stamped at teardown
# (audit_record_dependencies_down). Be precise about what the egress record
# means for audit: Hubble sees DESTINATION granularity (FQDN/IP/port), not URL
# paths or POST bodies inside TLS (§1.7) — the allowlist narrows WHERE traffic
# can go, it is not a content-exfil record.
#
# <deps_json> is a JSON array built by session_dependencies_audit_json.
audit_record_dependencies() {
  local log_dir="$1"
  local deps_json="$2"
  local session_json="${log_dir}/session.json"

  [[ -f "${session_json}" ]] || return 0

  local tmp
  tmp="$(mktemp)"
  jq --argjson deps "${deps_json}" '.dependencies = $deps' \
    "${session_json}" > "${tmp}"
  mv "${tmp}" "${session_json}"
}

# audit_record_dependencies_down — stamp a down-timestamp on every recorded
# dependency at teardown. No-op when the session declared none.
audit_record_dependencies_down() {
  local log_dir="$1"
  local down_time="$2"
  local session_json="${log_dir}/session.json"

  [[ -f "${session_json}" ]] || return 0

  local tmp
  tmp="$(mktemp)"
  jq --arg dt "${down_time}" \
    'if (.dependencies | type) == "array"
       then .dependencies |= map(.down_time = $dt)
       else . end' \
    "${session_json}" > "${tmp}"
  mv "${tmp}" "${session_json}"
}

# audit_log_event — append a structured event line to session.json events array
audit_log_event() {
  local log_dir="$1"
  local event_type="$2"
  local message="$3"
  local session_json="${log_dir}/session.json"

  if [[ ! -f "${session_json}" ]]; then
    return 0
  fi

  local timestamp
  timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

  local tmp
  tmp="$(mktemp)"
  jq \
    --arg ts "${timestamp}" \
    --arg type "${event_type}" \
    --arg msg "${message}" \
    '.events += [{"time": $ts, "type": $type, "message": $msg}]' \
    "${session_json}" > "${tmp}"
  mv "${tmp}" "${session_json}"
}

# audit_capture_transcript — copy the agent's conversation transcript(s) for
# this session into the session log directory. The transcript is the only
# artifact that records what the agent actually did and how it responded,
# which is what a usable audit log needs (see PRINCIPLES.md "Audit logs").
#
# Correlation: when the caller pinned the agent's conversation ID at launch
# (agent_session_id, 4th arg — see get_agent_session_id_flag), the exact
# transcript file is known and copied directly. Otherwise the agent home is
# shared across sessions, so correlation falls back to modification time: any
# transcript file modified since the session started is taken to belong to
# this session, with session.json (written once at session start, before this
# runs) as the cross-platform '-newer' reference. The mtime fallback is
# ambiguous if two sessions of the same agent overlap; the pinned ID is not.
audit_capture_transcript() {
  local log_dir="$1"
  local agent="$2"
  local agent_home="$3"
  local agent_session_id="${4:-}"

  local session_json="${log_dir}/session.json"
  local dest="${log_dir}/transcript"

  if [[ ! -f "${session_json}" ]]; then
    return 0
  fi
  if [[ ! -d "${agent_home}" ]]; then
    warn "Agent home not found (${agent_home}); skipping transcript capture."
    return 0
  fi

  local -a srcs=()
  case "${agent}" in
    claude)
      # ~/.claude/projects/<project>/<uuid>.jsonl
      if [[ -n "${agent_session_id}" ]]; then
        read_into_array srcs < <(find "${agent_home}/projects" -type f \
          -name "${agent_session_id}.jsonl" 2>/dev/null || true)
      else
        read_into_array srcs < <(find "${agent_home}/projects" -type f -name '*.jsonl' \
          -newer "${session_json}" 2>/dev/null || true)
      fi
      ;;
    codex)
      # ~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl
      read_into_array srcs < <(find "${agent_home}/sessions" -type f -name '*.jsonl' \
        -newer "${session_json}" 2>/dev/null || true)
      ;;
    opencode)
      # No single transcript file — best-effort copy of the storage subtree
      # modified during the session (session metadata, messages, diffs).
      read_into_array srcs < <(find "${agent_home}/storage" -type f \
        -newer "${session_json}" 2>/dev/null || true)
      ;;
    *)
      warn "Transcript capture not supported for agent '${agent}'."
      return 0
      ;;
  esac

  if [[ ${#srcs[@]} -eq 0 ]]; then
    warn "No conversation transcript found for this ${agent} session."
    return 0
  fi

  mkdir -p "${dest}"
  for f in "${srcs[@]}"; do
    # Preserve the storage/ subtree layout for opencode; flat copy otherwise.
    if [[ "${agent}" == "opencode" ]]; then
      local rel="${f#"${agent_home}/storage/"}"
      mkdir -p "${dest}/$(dirname "${rel}")"
      cp -p "${f}" "${dest}/${rel}"
    else
      cp -p "${f}" "${dest}/"
    fi
  done
  echo "  Captured ${#srcs[@]} transcript file(s): ${dest}"
}

# audit_list_sessions — list sessions from log directory
audit_list_sessions() {
  local log_dir="$1"
  local -a sessions=()

  if [[ -d "${log_dir}" ]]; then
    for d in "${log_dir}"/ses-*/; do
      [[ -d "${d}" ]] && sessions+=("$(basename "${d}")")
    done
  fi

  printf '%s\n' "${sessions[@]+"${sessions[@]}"}"
}
