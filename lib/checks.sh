#!/usr/bin/env bash
# lib/checks.sh — Input validation and pre-flight checks
set -euo pipefail

BLOCKED_DESTINATIONS_CONFIG="${SANDBOX_ROOT}/config/blocked-destinations.yaml"

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

    if [[ "${blocked_domain}" == \** ]]; then
      local suffix="${blocked_domain:1}"
      if [[ "${domain}" == *"${suffix}" ]]; then
        echo "ERROR: Domain '${domain}' matches ${source_label} blocked pattern '${blocked_domain}'." >&2
        echo "       (${file})" >&2
        exit 1
      fi
    else
      if [[ "${domain}" == "${blocked_domain}" ]]; then
        echo "ERROR: Domain '${domain}' is in the ${source_label} blocked destinations list." >&2
        echo "       (${file})" >&2
        exit 1
      fi
    fi
  done < <(grep -A1000 'blocked_domains:' "${file}" \
           | grep '^\s*-' || true)
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
