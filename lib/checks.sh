#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/checks.sh — Input validation and pre-flight checks
set -euo pipefail

# Allow an already-set value to win (e.g. tests pointing at a fixture), like
# USER_SANDBOX_CONFIG in lib/config.sh. A plain '=' here silently overrode a
# caller's override, which let a test's writes land on the real repo file.
BLOCKED_DESTINATIONS_CONFIG="${BLOCKED_DESTINATIONS_CONFIG:-${SANDBOX_ROOT}/config/blocked-destinations.yaml}"

# check_domain_not_blocked — die if domain matches the org-level blocked
# destinations list OR any overlay-supplied additions. Overlays are
# additive-only: they can extend the block list but cannot weaken it.
# See PRINCIPLES.md "Default-deny egress" and lib/profile.sh.
check_domain_not_blocked() {
  local domain="$1"

  if [[ ! -f "${BLOCKED_DESTINATIONS_CONFIG}" ]]; then
    echo "WARN: blocked-destinations.yaml not found; skipping block check." >&2
    return 0
  fi

  _check_domain_against_blocked_file "${domain}" "${BLOCKED_DESTINATIONS_CONFIG}" "org"

  # Overlay additions, if an overlay is configured. The function is a no-op
  # when no overlay is active or the overlay does not ship its own
  # blocked-destinations.yaml.
  local overlay_file
  overlay_file="$(overlay_blocked_destinations_file 2>/dev/null || true)"
  if [[ -n "${overlay_file}" ]]; then
    _check_domain_against_blocked_file "${domain}" "${overlay_file}" "overlay"
  fi
}

# _check_domain_against_blocked_file <domain> <file> <source-label>
# Internal helper: scan a single blocked-destinations YAML and die on match.
_check_domain_against_blocked_file() {
  local domain="$1"
  local file="$2"
  local source_label="$3"

  local line blocked_domain
  while IFS= read -r line; do
    blocked_domain="$(echo "${line}" | sed 's/^[[:space:]]*-[[:space:]]*//' | tr -d '"'"'")"
    [[ -z "${blocked_domain}" ]] && continue
    [[ "${blocked_domain}" == "#"* ]] && continue

    # Match the blocked pattern against the requested domain.
    #
    #   *.example.com  blocks the apex 'example.com' AND every subdomain.
    #                  Blocking a domain has to block the bare domain too —
    #                  otherwise '--allow-domain example.com' walks straight
    #                  past a '*.example.com' rule, which is a trivial (and
    #                  easy-to-hit-by-accident) way to defeat the block.
    #   prefix.*       blocks any host whose leading label is 'prefix'
    #                  (e.g. 'smtp.*' blocks 'smtp.example.com').
    #   *suffix        legacy bare-leading-'*' suffix match, kept as-is.
    #   example.com    exact match.
    local matched="false"
    case "${blocked_domain}" in
      "*."*)
        local apex="${blocked_domain#\*.}"
        [[ "${domain}" == "${apex}" || "${domain}" == *."${apex}" ]] && matched="true"
        ;;
      "*"*)
        local suffix="${blocked_domain#\*}"
        [[ "${domain}" == *"${suffix}" ]] && matched="true"
        ;;
      *".*")
        local prefix="${blocked_domain%.\*}"
        [[ "${domain}" == "${prefix}" || "${domain}" == "${prefix}".* ]] && matched="true"
        ;;
      *)
        [[ "${domain}" == "${blocked_domain}" ]] && matched="true"
        ;;
    esac

    if [[ "${matched}" == "true" ]]; then
      echo "ERROR: Domain '${domain}' matches the ${source_label} blocked-destinations rule '${blocked_domain}'." >&2
      echo "       (${file})" >&2
      exit 1
    fi
  done < <(grep -A1000 'blocked_domains:' "${file}" \
           | grep '^\s*-' || true)
}

# get_blocked_cidrs — print the union of blocked CIDRs from the org
# blocked-destinations file and any overlay addition, one per line, de-duped.
# Overlays are additive on the safety side (PRINCIPLES.md "Default-deny
# egress"): they may extend the deny list, never shrink it. Empty output when
# none are configured. These are enforced as a Cilium egressDeny rule (see
# lib/policy.sh) so a forbidden range stays unreachable even if an allow-listed
# FQDN resolves into it.
get_blocked_cidrs() {
  {
    if [[ -f "${BLOCKED_DESTINATIONS_CONFIG}" ]]; then
      extract_yaml_list_from_file "${BLOCKED_DESTINATIONS_CONFIG}" blocked_cidrs
    fi
    local overlay_file
    overlay_file="$(overlay_blocked_destinations_file 2>/dev/null || true)"
    if [[ -n "${overlay_file}" ]]; then
      extract_yaml_list_from_file "${overlay_file}" blocked_cidrs
    fi
  } | awk 'NF && !seen[$0]++'
}

# validate_cidr <cidr> — true if cidr is a syntactically plausible IPv4 or
# IPv6 CIDR (catches typos like a missing prefix length or a bare hostname).
# It is a shape check, not a full range validation — Cilium has the final say.
validate_cidr() {
  local cidr="$1"
  [[ "${cidr}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] && return 0
  [[ "${cidr}" == *:* ]] && [[ "${cidr}" =~ ^[0-9A-Fa-f:]+/[0-9]{1,3}$ ]] && return 0
  return 1
}

# check_blocked_cidrs_valid — die if any configured blocked CIDR is malformed.
# Run as a preflight (before any cluster resources are created) so a typo'd
# entry fails fast and loudly instead of silently producing a deny rule Cilium
# rejects — i.e. a block that doesn't block.
check_blocked_cidrs_valid() {
  local cidr
  while IFS= read -r cidr; do
    [[ -z "${cidr}" ]] && continue
    if ! validate_cidr "${cidr}"; then
      echo "ERROR: blocked_cidrs entry '${cidr}' is not a valid CIDR." >&2
      echo "       Fix it in ${BLOCKED_DESTINATIONS_CONFIG} (or the overlay's blocked-destinations.yaml)." >&2
      echo "       Expected forms: 10.0.0.0/8, 169.254.0.0/16, fd00::/8." >&2
      exit 1
    fi
  done < <(get_blocked_cidrs)
}

# check_no_privileged_flags — ensure no dangerous kubectl/container flags are present
check_no_privileged_flags() {
  local manifest="$1"

  if echo "${manifest}" | grep -q 'privileged: true'; then
    echo "ERROR: Pod manifest contains 'privileged: true'." >&2
    exit 1
  fi

  if echo "${manifest}" | grep -q 'automountServiceAccountToken: true'; then
    echo "ERROR: Pod manifest sets automountServiceAccountToken: true." >&2
    exit 1
  fi
}

# check_prerequisites — verify all required tools are installed
check_prerequisites() {
  local missing=0

  local required_tools=("kubectl" "jq" "git" "xxd" "sha256sum")
  for tool in "${required_tools[@]}"; do
    if ! command -v "${tool}" &>/dev/null; then
      echo "WARN: Required tool not found: ${tool}" >&2
      (( missing++ )) || true
    fi
  done

  local optional_tools=("gitleaks" "hubble" "helm")
  for tool in "${optional_tools[@]}"; do
    if ! command -v "${tool}" &>/dev/null; then
      echo "INFO: Optional tool not found: ${tool} (some features disabled)" >&2
    fi
  done

  if [[ "${missing}" -gt 0 ]]; then
    echo "ERROR: ${missing} required tool(s) missing. Run 'sandbox setup'." >&2
    exit 1
  fi
}
