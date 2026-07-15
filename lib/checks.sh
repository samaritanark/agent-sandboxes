#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/checks.sh — Input validation and pre-flight checks
set -euo pipefail

# Allow an already-set value to win (e.g. tests pointing at a fixture), like
# USER_SANDBOX_CONFIG in lib/config.sh. A plain '=' here silently overrode a
# caller's override, which let a test's writes land on the real repo file.
BLOCKED_DESTINATIONS_CONFIG="${BLOCKED_DESTINATIONS_CONFIG:-${SANDBOX_ROOT}/config/blocked-destinations.yaml}"

# Per-user block layer lives in the same file as the rest of the user config
# (lib/config.sh owns this var). Default it here too so checks.sh stays usable
# under `set -u` even if it is sourced before config.sh (bin/sandbox does
# exactly that — the functions are only called later, once both are loaded).
USER_SANDBOX_CONFIG="${USER_SANDBOX_CONFIG:-${HOME}/.sandbox/config.yaml}"

# _normalize_domain <name> — canonicalize a DNS name for comparison the way the
# egress enforcement layer normalizes it. DNS names are case-insensitive, and a
# trailing "." (the FQDN root label) denotes the same host — so 'evil.com',
# 'EVIL.COM', and 'evil.com.' are one destination. Cilium lowercases and
# trailing-dot-normalizes the toFQDNs/matchName rules the allow-list becomes,
# so a case-sensitive block check let '--allow-domain EVIL.COM' (or a trailing
# dot) walk straight past a blocked 'evil.com' and land in the allow rule as
# the very host the org meant to block. Normalizing both the checked name and
# each block pattern closes that gap. bash 3.2-safe (no ${x,,} / no mapfile).
_normalize_domain() {
  local d="$1"
  d="$(printf '%s' "${d}" | tr '[:upper:]' '[:lower:]')"
  while [[ "${d}" == *. ]]; do d="${d%.}"; done   # strip trailing root dot(s)
  printf '%s\n' "${d}"
}

# check_domain_not_blocked — die if domain matches the org-level blocked
# destinations list OR any overlay-supplied additions. Overlays are
# additive-only: they can extend the block list but cannot weaken it.
# See PRINCIPLES.md "Default-deny egress" and lib/profile.sh.
check_domain_not_blocked() {
  local domain
  domain="$(_normalize_domain "$1")"

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

  # Per-user additions from ~/.sandbox/config.yaml (deny-only: unioned with the
  # org + overlay blocks, never weakens them). Lets an operator keep a personal
  # "never let a sandbox reach this" backstop. See lib/config.sh.
  _check_domain_against_blocked_file "${domain}" "${USER_SANDBOX_CONFIG}" "user"
}

# _domain_matches_block_pattern <domain> <pattern> — true if a blocked-list
# pattern matches the requested domain. Pattern grammar:
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
_domain_matches_block_pattern() {
  # The domain arrives already normalized (check_domain_not_blocked); normalize
  # the pattern too so a block entry written 'EVIL.COM' or 'evil.com.' still
  # matches. The '*' grammar markers are unaffected by lowercasing/dot-strip.
  local domain="$1" pattern
  pattern="$(_normalize_domain "$2")"
  case "${pattern}" in
    "*."*)
      local apex="${pattern#\*.}"
      [[ "${domain}" == "${apex}" || "${domain}" == *."${apex}" ]] && return 0
      ;;
    "*"*)
      local suffix="${pattern#\*}"
      [[ "${domain}" == *"${suffix}" ]] && return 0
      ;;
    *".*")
      local prefix="${pattern%.\*}"
      [[ "${domain}" == "${prefix}" || "${domain}" == "${prefix}".* ]] && return 0
      ;;
    *)
      [[ "${domain}" == "${pattern}" ]] && return 0
      ;;
  esac
  return 1
}

# _check_domain_against_blocked_file <domain> <file> <source-label>
# Internal helper: scan a single config's blocked_domains list and die on
# match. Reads via extract_yaml_list_from_file (lib/config.sh), which is
# key-bounded — so this is safe to point at ~/.sandbox/config.yaml, which mixes
# blocked_domains with other keys (extra_allowed_domains, etc.), not just the
# dedicated blocked-destinations.yaml.
_check_domain_against_blocked_file() {
  local domain="$1"
  local file="$2"
  local source_label="$3"

  [[ -f "${file}" ]] || return 0

  local pattern
  while IFS= read -r pattern; do
    [[ -z "${pattern}" ]] && continue
    if _domain_matches_block_pattern "${domain}" "${pattern}"; then
      echo "ERROR: Domain '${domain}' matches the ${source_label} blocked-destinations rule '${pattern}'." >&2
      echo "       (${file})" >&2
      exit 1
    fi
  done < <(extract_yaml_list_from_file "${file}" "blocked_domains")
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
    # Per-user additions (deny-only union; see lib/config.sh).
    if [[ -f "${USER_SANDBOX_CONFIG}" ]]; then
      extract_yaml_list_from_file "${USER_SANDBOX_CONFIG}" blocked_cidrs
    fi
  } | awk 'NF && !seen[$0]++'
}

# validate_cidr <cidr> — true if cidr is a syntactically plausible IPv4 or
# IPv6 CIDR (catches typos like a missing prefix length or a bare hostname).
# It is a shape check, not a full range validation — Cilium has the final say.
validate_cidr() {
  local cidr="$1"
  # Hold the regexes in variables: bash 3.2's [[ =~ ]] parser rejects an
  # inline regex containing '(' (macOS ships 3.2). Reference unquoted so the
  # RHS is treated as a regex, not a literal, on both 3.2 and 4+.
  local _ipv4_re='^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'
  local _ipv6_re='^[0-9A-Fa-f:]+/[0-9]{1,3}$'
  [[ "${cidr}" =~ $_ipv4_re ]] && return 0
  [[ "${cidr}" == *:* ]] && [[ "${cidr}" =~ $_ipv6_re ]] && return 0
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

# _is_ipv4_literal <s> — true if s is a dotted-quad IPv4 literal (shape only;
# does not range-check octets). Regex held in a var: bash 3.2's [[ =~ ]] parser
# chokes on an inline regex containing '(' (macOS ships 3.2).
_is_ipv4_literal() {
  local _re='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
  [[ "$1" =~ $_re ]]
}

# _ipv4_to_int <a.b.c.d> — print the 32-bit integer value of an IPv4 address,
# or return 1 if it is not four octets each in 0-255. Forces base-10 so a
# leading-zero octet ('010') is not misread as octal by $(( )).
_ipv4_to_int() {
  local ip="$1" _ifs="${IFS}"
  IFS='.'
  # shellcheck disable=SC2086  # deliberate word-split on '.' (no glob chars in an IP)
  set -- ${ip}
  IFS="${_ifs}"
  [[ $# -eq 4 ]] || return 1
  local o n=0
  for o in "$@"; do
    case "${o}" in ''|*[!0-9]*) return 1 ;; esac
    o=$(( 10#${o} ))
    (( o >= 0 && o <= 255 )) || return 1
    n=$(( (n << 8) + o ))
  done
  echo "${n}"
}

# ip_in_cidr <ip> <cidr> — true if an IPv4 address falls inside an IPv4 CIDR.
# IPv4 only: any IPv6 input (contains ':') returns false. bash 3.2-safe — pure
# $(( )) arithmetic, 64-bit intmax_t holds the 0xFFFFFFFF intermediates.
ip_in_cidr() {
  local ip="$1" cidr="$2"
  case "${ip}${cidr}" in *:*) return 1 ;; esac     # IPv6 not handled here
  [[ "${cidr}" == */* ]] || return 1
  _is_ipv4_literal "${ip}" || return 1

  local net="${cidr%/*}" prefix="${cidr#*/}"
  _is_ipv4_literal "${net}" || return 1
  case "${prefix}" in ''|*[!0-9]*) return 1 ;; esac
  (( prefix >= 0 && prefix <= 32 )) || return 1

  local ip_int net_int mask
  ip_int="$(_ipv4_to_int "${ip}")" || return 1
  net_int="$(_ipv4_to_int "${net}")" || return 1
  if (( prefix == 0 )); then
    mask=0                                          # 0.0.0.0/0 matches everything
  else
    mask=$(( (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
  fi
  (( (ip_int & mask) == (net_int & mask) ))
}

# check_ip_not_in_blocked_cidrs <ip> — die if an IP literal falls inside any
# blocked CIDR (org + overlay + user union). This is the create-time companion
# to Cilium's runtime egressDeny: a kube API server given as a literal IP (the
# common case) matches no blocked_domains pattern, so without this an
# accidentally-supplied production endpoint would be auto-allowlisted and only
# fail later inside the sandbox. IPv6 literals are left to Cilium at runtime
# (bash 3.2 can't cheaply do IPv6 math); warn so the gap is visible.
check_ip_not_in_blocked_cidrs() {
  local ip="$1"

  if [[ "${ip}" == *:* ]]; then
    echo "WARN: ${ip} is an IPv6 literal; create-time blocked-CIDR check skipped" >&2
    echo "      (Cilium still enforces egressDeny at runtime)." >&2
    return 0
  fi
  _is_ipv4_literal "${ip}" || return 0    # not an IP literal — nothing to check

  local cidr
  while IFS= read -r cidr; do
    [[ -z "${cidr}" ]] && continue
    [[ "${cidr}" == *:* ]] && continue    # IPv6 blocked CIDR — skip here
    if ip_in_cidr "${ip}" "${cidr}"; then
      echo "ERROR: ${ip} falls inside blocked CIDR '${cidr}'." >&2
      echo "       (${BLOCKED_DESTINATIONS_CONFIG}, the overlay's blocked-destinations.yaml, or ${USER_SANDBOX_CONFIG})" >&2
      exit 1
    fi
  done < <(get_blocked_cidrs)
}

# check_egress_target_not_blocked <host-or-ip> — the single entry point callers
# should use to validate any egress destination. Runs the domain block check
# and, when the target is an IPv4 literal, the blocked-CIDR membership check.
check_egress_target_not_blocked() {
  local target="$1"
  check_domain_not_blocked "${target}"
  if _is_ipv4_literal "${target}"; then
    check_ip_not_in_blocked_cidrs "${target}"
  fi
}

# inference_endpoint_is_trusted <host> — true if <host> exactly matches an entry
# in the team overlay's `trusted_inference_endpoints:` list. That list is an
# operator/overlay-owned GRANT naming the internal model endpoints trusted to
# receive secret-bearing prompts; its ONLY effect is to downgrade the workspace
# secret gate from a hard refusal to an interactive confirmation (see
# secret_gate_repos). Nothing else keys on it, and it never relaxes any other
# control — a trusted endpoint does not touch the vetting posture or the block
# list.
#
# Deliberately overlay-only: like the vetting posture (resolve_vetting_posture)
# the trust root is operator-side and cannot be asserted from a repo-local or
# per-user config — otherwise the party the gate protects against (whoever sets
# OPENCODE_BASE_URL) could also self-declare their endpoint trusted. An empty or
# absent list means no endpoint is ever trusted, so the gate keeps its hard-block
# default and this feature is simply off.
#
# Matching is on the bare host (no wildcards, no port), consistent with
# resolve_inference_endpoint and the egress allowlist. Wildcards are refused by
# construction here: a loose match on the destination the whole prompt flows to
# is exactly where a subdomain takeover or DNS rebind would masquerade as
# trusted. A listed host is trusted on any port.
inference_endpoint_is_trusted() {
  local host="$1"
  [[ -n "${host}" ]] || return 1
  local overlay
  overlay="$(resolve_overlay_path 2>/dev/null || true)"
  [[ -n "${overlay}" && -f "${overlay}/config.yaml" ]] || return 1
  local entry
  while IFS= read -r entry; do
    [[ "${entry}" == "${host}" ]] && return 0
  done < <(extract_yaml_list_from_file "${overlay}/config.yaml" trusted_inference_endpoints)
  return 1
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

# check_dependency_no_host_mounts — refuse any host mount on a dependency pod
# manifest. The dependency manifest builder (lib/dependency.sh) is
# additive-from-empty and so should never emit a hostPath, but this is the
# *checked* invariant behind that convention (§2.3) — the same move that made
# blocked-CIDR completeness a test rather than prose. A dependency that carried
# the agent's workspace or any host path would reopen the upload-exfil channel
# the no-mount shape closes structurally (§2.2). Mirrors
# check_no_privileged_flags: a grep over the rendered YAML, fail closed on hit.
check_dependency_no_host_mounts() {
  local manifest="$1"

  if echo "${manifest}" | grep -q 'hostPath:'; then
    echo "ERROR: dependency pod manifest contains a hostPath volume." >&2
    echo "       Dependencies mount no workspace and no host path (§2.2/§2.3)." >&2
    exit 1
  fi
}

# check_prerequisites — verify all required tools are installed
check_prerequisites() {
  local missing=0

  local required_tools=("kubectl" "jq" "git" "xxd")
  for tool in "${required_tools[@]}"; do
    if ! command -v "${tool}" &>/dev/null; then
      echo "WARN: Required tool not found: ${tool}" >&2
      (( missing++ )) || true
    fi
  done

  # sha-256 hashing (workspace drift) and checksum verification (setup) need a
  # hasher, but the binary name differs by platform: GNU sha256sum on Linux,
  # shasum on stock macOS. Either one satisfies the requirement.
  if ! command -v sha256sum &>/dev/null && ! command -v shasum &>/dev/null; then
    echo "WARN: Required tool not found: sha256sum (or shasum)" >&2
    (( missing++ )) || true
  fi

  # betterleaks gates Tier 2/3 launches (the secret scan in lib/filesystem.sh
  # fails closed without it), so flag it more loudly than the truly optional
  # tools — but don't make it a hard prerequisite for Tier 1, which has no
  # workspace to scan.
  if ! command -v betterleaks &>/dev/null; then
    echo "WARN: betterleaks not found — Tier 2/3 'sandbox run' will refuse to" >&2
    echo "      launch (fail closed). Run 'sandbox setup' to install it." >&2
  fi

  local optional_tools=("hubble" "helm")
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
