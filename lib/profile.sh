#!/usr/bin/env bash
# lib/profile.sh — Profile + overlay resolution
#
# Profiles are named bundles that declare a tier plus optional extra
# allowed domains, a default --repo, and (for later phases) lists of
# secrets and MCPs to inject. They're sugar over the existing tier model:
# `--profile 1|2|3` is a numeric alias for `--tier`, and a named profile
# (`--profile innkeeper-dev`) resolves to a YAML file whose `tier:` field
# is still subject to the same governance checks as a literal --tier flag.
#
# Profiles live in:
#   ~/.sandbox/profiles/<name>.yaml          — per-user
#   <overlay>/profiles/<name>.yaml           — per-team (overlay)
#
# Overlay path is resolved from $SANDBOX_OVERLAY first, then the
# `overlay:` key in ~/.sandbox/config.yaml. Overlays are additive-only on
# the safety side: their blocked-destinations.yaml is unioned with the
# repo's config/blocked-destinations.yaml; nothing in an overlay can
# remove an org-level block. See PRINCIPLES.md ("Default-deny egress").
#
# Profile YAML schema:
#   profile: innkeeper-dev          # informational; the filename is canonical
#   tier: 2                         # required (1|2|3)
#   default_repo: ~/repos/innkeeper # optional; used when --repo is absent
#   extra_allowed_domains:          # optional; merged with --allow-domain
#     - innkeeper-api.example.com
#   secrets: [jira-pat]             # Phase 4 — injected as session Secrets
#   mcps:    [innkeeper-mcp]        # Phase 5 — deployed alongside session
set -euo pipefail

# resolve_overlay_path — print the active overlay directory, if any.
# Source priority: SANDBOX_OVERLAY env, then `overlay:` in
# ~/.sandbox/config.yaml. Empty output when neither is set. The path is
# tilde-expanded; the caller can use it directly.
resolve_overlay_path() {
  local raw=""
  if [[ -n "${SANDBOX_OVERLAY:-}" ]]; then
    raw="${SANDBOX_OVERLAY}"
  elif [[ -f "${USER_SANDBOX_CONFIG}" ]]; then
    raw="$(extract_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" overlay)"
  fi
  [[ -z "${raw}" ]] && return 0
  echo "${raw/#\~/${HOME}}"
}

# is_numeric_profile <name> — true if name is "1", "2", or "3".
is_numeric_profile() {
  case "$1" in
    1|2|3) return 0 ;;
    *)     return 1 ;;
  esac
}

# find_profile_path <name> — locate a profile YAML by name. Search order:
# ~/.sandbox/profiles/<name>.yaml, then <overlay>/profiles/<name>.yaml.
# Prints absolute path on success; returns 1 on miss with no output.
find_profile_path() {
  local name="$1"
  local user_path="${HOME}/.sandbox/profiles/${name}.yaml"
  if [[ -f "${user_path}" ]]; then
    echo "${user_path}"
    return 0
  fi

  local overlay
  overlay="$(resolve_overlay_path)"
  if [[ -n "${overlay}" ]]; then
    local overlay_path="${overlay}/profiles/${name}.yaml"
    if [[ -f "${overlay_path}" ]]; then
      echo "${overlay_path}"
      return 0
    fi
  fi

  return 1
}

# overlay_blocked_destinations_file — print the overlay's blocked-destinations
# path (if it exists), empty otherwise. Used by lib/checks.sh to extend the
# org-level block list with overlay additions.
overlay_blocked_destinations_file() {
  local overlay
  overlay="$(resolve_overlay_path)"
  [[ -n "${overlay}" ]] || return 0
  local path="${overlay}/blocked-destinations.yaml"
  [[ -f "${path}" ]] && echo "${path}"
}
