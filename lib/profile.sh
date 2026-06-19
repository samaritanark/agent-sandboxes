#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/profile.sh — Profile + overlay resolution
#
# Profiles are named bundles that declare a tier plus optional extra
# allowed domains, a default --repo, and (for later phases) lists of
# secrets and MCPs to inject. They're sugar over the existing tier model:
# `--profile 1|2|3` is a numeric alias for `--tier`, and a named profile
# (`--profile example-dev`) resolves to a YAML file whose `tier:` field
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
#   profile: example-dev          # informational; the filename is canonical
#   tier: 2                         # required (1|2|3)
#   agent: codex                    # optional; used when --agent is absent
#                                   #   (run falls back to its own default,
#                                   #    claude, when neither is set)
#   default_repo: ~/repos/example # optional; used when --repo is absent
#   extra_allowed_domains:          # optional; merged with --allow-domain
#     - example-api.example.com
#   secrets: [jira-pat]             # Phase 4 — injected as session Secrets
#   mcps:    [example-mcp]        # Phase 5 — deployed alongside session
#
# Only `tier` is required; everything else (agent included) is optional, so a
# profile can be as minimal as a single tier or as complete as a full launch.
# Profiles are written by `sandbox profile save` (see cmd_profile in
# bin/sandbox) into the per-user dir below; the overlay copy is team-shipped.
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

# user_profiles_dir — print the per-user profiles directory. `sandbox profile
# save`/`delete` only ever write here; overlay profiles are team-shipped and
# managed outside this CLI.
user_profiles_dir() {
  echo "${HOME}/.sandbox/profiles"
}

# is_valid_profile_name <name> — true if name is safe to use both as a profile
# filename (<name>.yaml) and as a `--profile` reference. Rejects the empty
# string, path separators and traversal (so a name can't escape the profiles
# dir), leading dots, and the numeric tier aliases (1|2|3), which `--profile`
# already treats as `--tier` shortcuts. Allowed charset: [A-Za-z0-9._-].
is_valid_profile_name() {
  local name="$1"
  [[ -n "${name}" ]]                  || return 1
  is_numeric_profile "${name}"        && return 1
  [[ "${name}" == *"/"* ]]            && return 1
  [[ "${name}" == *".."* ]]           && return 1
  [[ "${name}" == .* ]]               && return 1
  [[ "${name}" =~ ^[A-Za-z0-9._-]+$ ]] || return 1
  return 0
}

# render_profile_yaml <name> <tier> <agent> <default_repo> — emit profile YAML
# to stdout. Extra allowed domains are read from stdin, one per line (blank
# lines ignored, so an empty stdin means "no domains"). `agent` and
# `default_repo` are OPTIONAL: pass an empty string to omit the line entirely
# — a profile is never forced to pin an agent. The emitted shape is exactly
# what extract_yaml_scalar_from_file / extract_yaml_list_from_file parse back.
render_profile_yaml() {
  local name="$1" tier="$2" agent="${3:-}" default_repo="${4:-}"

  printf '# %s — generated by `sandbox profile save`\n' "${name}"
  printf '# Edit by hand, or re-run save with --force to regenerate.\n'
  printf 'profile: %s\n' "${name}"
  printf 'tier: %s\n' "${tier}"
  [[ -n "${agent}" ]]        && printf 'agent: %s\n' "${agent}"
  [[ -n "${default_repo}" ]] && printf 'default_repo: %s\n' "${default_repo}"

  local -a domains=()
  local d
  while IFS= read -r d; do
    [[ -n "${d}" ]] && domains+=("${d}")
  done
  if [[ "${#domains[@]}" -gt 0 ]]; then
    printf 'extra_allowed_domains:\n'
    for d in "${domains[@]}"; do
      printf '  - %s\n' "${d}"
    done
  fi
}
