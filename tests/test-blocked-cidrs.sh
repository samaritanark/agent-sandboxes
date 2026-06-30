#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-blocked-cidrs.sh — Blocked-CIDR parsing, validation, and the
# Cilium egressDeny rendering in build_cilium_policy. Verifies that a forbidden
# IP range is turned into a deny rule (deny beats allow in Cilium), so an
# allow-listed FQDN that resolves into the range is still blocked. Cluster-free.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-blocked-cidrs"
TEST_DIR="$(mktemp -d /tmp/sandbox-cidr-test-XXXXXX)"
HOME="${TEST_DIR}/home"; mkdir -p "${HOME}"
SANDBOX_NAMESPACE="sandbox"

fail() { echo "FAIL: $*" >&2; exit 1; }
cleanup() { rm -rf "${TEST_DIR}"; }
trap cleanup EXIT

USER_SANDBOX_CONFIG="${HOME}/.sandbox/config.yaml"

source "${SANDBOX_ROOT}/lib/platform.sh"
source "${SANDBOX_ROOT}/lib/config.sh"
source "${SANDBOX_ROOT}/lib/profile.sh"
source "${SANDBOX_ROOT}/lib/checks.sh"
source "${SANDBOX_ROOT}/lib/agents.sh"
source "${SANDBOX_ROOT}/lib/tier.sh"
source "${SANDBOX_ROOT}/lib/policy.sh"

# Point the blocked-destinations file at a per-test fixture. Set this AFTER
# sourcing checks.sh — checks.sh now honours a pre-set value, but setting it
# here too means the override holds regardless of source order.
BLOCKED_DESTINATIONS_CONFIG="${TEST_DIR}/blocked.yaml"

eq() {
  local label="$1" expected="$2" actual="$3"
  [[ "${expected}" == "${actual}" ]] && pass "${label}" \
    || fail "${label}: expected '${expected}', got '${actual}'"
}

# Guard: never write outside the test dir. A misconfigured path here once
# clobbered the real config/blocked-destinations.yaml — fail loudly instead.
write_blocked() {
  case "${BLOCKED_DESTINATIONS_CONFIG}" in
    "${TEST_DIR}"/*) : ;;
    *) fail "refusing to write blocked-destinations fixture outside TEST_DIR: ${BLOCKED_DESTINATIONS_CONFIG}" ;;
  esac
  printf '%s\n' "$@" > "${BLOCKED_DESTINATIONS_CONFIG}"
}

###############################################################################
# validate_cidr
###############################################################################
test_validate_cidr() {
  info "Testing validate_cidr..."
  local c
  for c in 10.0.0.0/8 169.254.169.254/32 172.16.0.0/12 192.168.0.0/16 "fd00::/8" "fd00:ec2::254/128"; do
    validate_cidr "${c}" || fail "validate_cidr '${c}' should be valid"
  done
  pass "accepts valid IPv4/IPv6 CIDRs"

  for c in "" "10.0.0.0" "not-a-cidr" "example.com" "10.0.0.0/" "/8" "10.0.0.0-10.0.0.5"; do
    if validate_cidr "${c}"; then fail "validate_cidr '${c}' should be invalid"; fi
  done
  pass "rejects malformed entries"
}

###############################################################################
# get_blocked_cidrs — union of org + overlay, de-duplicated
###############################################################################
test_get_blocked_cidrs() {
  info "Testing get_blocked_cidrs..."
  unset SANDBOX_OVERLAY

  # None configured → empty.
  write_blocked "blocked_domains:" "  - pastebin.com" "blocked_cidrs:"
  eq "no cidrs → empty" "" "$(get_blocked_cidrs)"

  # Org cidrs only.
  write_blocked "blocked_cidrs:" "  - 169.254.169.254/32" "  - 10.0.0.0/8"
  eq "org cidrs" "169.254.169.254/32
10.0.0.0/8" "$(get_blocked_cidrs)"

  # Overlay extends the org list (additive on the safety side), de-duped.
  local overlay="${TEST_DIR}/overlay"; mkdir -p "${overlay}"
  printf '%s\n' "blocked_cidrs:" "  - 10.0.0.0/8" "  - 172.16.0.0/12" \
    > "${overlay}/blocked-destinations.yaml"
  eq "org ∪ overlay, deduped" "169.254.169.254/32
10.0.0.0/8
172.16.0.0/12" "$(SANDBOX_OVERLAY="${overlay}" get_blocked_cidrs)"
}

###############################################################################
# check_blocked_cidrs_valid — dies on a malformed entry
###############################################################################
test_check_blocked_cidrs_valid() {
  info "Testing check_blocked_cidrs_valid..."
  unset SANDBOX_OVERLAY

  write_blocked "blocked_cidrs:" "  - 10.0.0.0/8" "  - 169.254.169.254/32"
  ( check_blocked_cidrs_valid >/dev/null 2>&1 ) \
    && pass "valid cidrs pass" || fail "valid cidrs should pass"

  write_blocked "blocked_cidrs:" "  - 10.0.0.0/8" "  - not-a-cidr"
  ( check_blocked_cidrs_valid >/dev/null 2>&1 ) \
    && fail "malformed cidr should be rejected" || pass "malformed cidr rejected"
}

###############################################################################
# Completeness invariant — the SHIPPED default config (not a fixture) must
# enforce the link-local / IMDS block. Per the M8 review finding, SSRF safety
# reduces to blocked-CIDR completeness, so the load-bearing entries are a
# tested invariant rather than prose: a future edit that narrows
# 169.254.0.0/16 back to a single /32, or drops it, fails here. Broad RFC-1918
# denial is deliberately NOT an invariant — it breaks Tier 3 (deny beats the
# per-session kube-API allow); see config/blocked-destinations.yaml comments.
###############################################################################
test_blocked_cidrs_completeness() {
  info "Testing shipped blocked-destinations completeness invariant..."
  unset SANDBOX_OVERLAY

  local default_config="${SANDBOX_ROOT}/config/blocked-destinations.yaml"
  [[ -f "${default_config}" ]] || fail "default blocked-destinations.yaml missing at ${default_config}"

  local cidrs
  cidrs="$(BLOCKED_DESTINATIONS_CONFIG="${default_config}" get_blocked_cidrs)"

  grep -qx '169.254.0.0/16' <<<"${cidrs}" \
    || fail "link-local/IMDS invariant: default config must block 169.254.0.0/16 (got: ${cidrs//$'\n'/, })"
  pass "default config blocks the full IPv4 link-local range (IMDS + metadata)"

  # A typo'd block is a block that does not block: every shipped default entry
  # must be a CIDR Cilium will accept.
  local c
  while IFS= read -r c; do
    [[ -z "${c}" ]] && continue
    validate_cidr "${c}" || fail "default config entry '${c}' is not a valid CIDR"
  done <<<"${cidrs}"
  pass "every shipped default blocked CIDR is well-formed"
}

###############################################################################
# build_cilium_policy — egressDeny rendering
###############################################################################
test_policy_egress_deny() {
  info "Testing build_cilium_policy egressDeny rendering..."
  unset SANDBOX_OVERLAY

  # With blocked cidrs → egressDeny + toCIDR + each entry present.
  write_blocked "blocked_cidrs:" "  - 169.254.169.254/32" "  - 10.0.0.0/8"
  local out
  out="$(build_cilium_policy ses-test claude 1 "" "")"
  grep -q '^  egressDeny:'                <<<"${out}" || fail "missing egressDeny section"
  grep -q '169.254.169.254/32'            <<<"${out}" || fail "missing metadata CIDR"
  grep -q '10.0.0.0/8'                     <<<"${out}" || fail "missing RFC1918 CIDR"
  pass "egressDeny block lists the blocked CIDRs"

  # Sanity: the allow side (DNS + FQDN) is still present alongside the deny.
  grep -q 'toFQDNs'  <<<"${out}" || fail "FQDN allow rule disappeared"
  grep -q 'egress:'  <<<"${out}" || fail "egress allow section disappeared"
  pass "allow rules coexist with the deny rule"

  # With NO blocked cidrs → no egressDeny section at all.
  write_blocked "blocked_domains:" "  - pastebin.com"
  out="$(build_cilium_policy ses-test claude 1 "" "")"
  if grep -q 'egressDeny' <<<"${out}"; then fail "egressDeny should be absent when no cidrs"; fi
  pass "no egressDeny section when no cidrs configured"

  # The rendered policy is valid YAML — checked with whatever parser is on
  # hand (python3+yaml or a yaml linter). If none is available we note it and
  # move on rather than failing the suite on a missing dev dependency.
  write_blocked "blocked_cidrs:" "  - 169.254.169.254/32" "  - 10.0.0.0/8"
  local policy_out
  policy_out="$(build_cilium_policy ses-test claude 3 "10.1.2.3/32" "6443")"
  if python3 -c 'import yaml' >/dev/null 2>&1; then
    printf '%s' "${policy_out}" \
      | python3 -c 'import sys,yaml; list(yaml.safe_load_all(sys.stdin))' \
      && pass "rendered policy parses as YAML (with kube API + deny)" \
      || fail "rendered policy is not valid YAML"
  else
    info "no YAML parser available — skipping the parse check (not a failure)"
  fi
}

###############################################################################
# ip_in_cidr — IPv4 membership math (bash 3.2-safe)
###############################################################################
test_ip_in_cidr() {
  info "Testing ip_in_cidr..."
  local spec ip cidr want got
  # (ip, cidr, expected) — ranges, host route, match-all, leading-zero octet
  # (must not be read as octal), IPv6 (unhandled → false), and garbage.
  for spec in \
    "10.0.3.7 10.0.0.0/8 in" \
    "11.0.0.1 10.0.0.0/8 out" \
    "169.254.169.254 169.254.0.0/16 in" \
    "192.168.1.5 192.168.1.0/24 in" \
    "192.168.2.5 192.168.1.0/24 out" \
    "1.2.3.4 0.0.0.0/0 in" \
    "10.0.0.1 10.0.0.1/32 in" \
    "10.0.0.2 10.0.0.1/32 out" \
    "010.0.0.1 10.0.0.0/8 in" \
    "fd00::1 fd00::/8 out" \
    "notanip 10.0.0.0/8 out" \
    "10.0.0.1 10.0.0.0/33 out" \
    "10.0.0.1 10.0.0.0 out" \
  ; do
    # shellcheck disable=SC2086  # intentional word-split of the spec triple
    set -- ${spec}; ip="$1"; cidr="$2"; want="$3"
    if ip_in_cidr "${ip}" "${cidr}"; then got="in"; else got="out"; fi
    [[ "${got}" == "${want}" ]] \
      || fail "ip_in_cidr ${ip} ${cidr}: expected ${want}, got ${got}"
  done
  pass "membership: ranges, /32, /0, leading-zero octet, IPv6 skip, garbage"
}

###############################################################################
# check_ip_not_in_blocked_cidrs — dies on an IP inside a blocked range
###############################################################################
test_check_ip_not_in_blocked_cidrs() {
  info "Testing check_ip_not_in_blocked_cidrs..."
  unset SANDBOX_OVERLAY
  rm -f "${USER_SANDBOX_CONFIG}"
  write_blocked "blocked_cidrs:" "  - 10.0.0.0/8" "  - 169.254.0.0/16"

  ( check_ip_not_in_blocked_cidrs 10.0.3.7 >/dev/null 2>&1 ) \
    && fail "10.0.3.7 ∈ 10.0.0.0/8 should be rejected" \
    || pass "in-range IP rejected"

  ( check_ip_not_in_blocked_cidrs 8.8.8.8 >/dev/null 2>&1 ) \
    && pass "out-of-range IP allowed" \
    || fail "8.8.8.8 is in no blocked range and should pass"

  # IPv6 literal: skipped at create time (Cilium enforces at runtime) → no die.
  ( check_ip_not_in_blocked_cidrs "fd00::1" >/dev/null 2>&1 ) \
    && pass "IPv6 literal skipped, not rejected" \
    || fail "IPv6 literal should be skipped, not rejected"

  # Non-IP target is a no-op here (the domain check handles names).
  ( check_ip_not_in_blocked_cidrs "api.example.com" >/dev/null 2>&1 ) \
    && pass "non-IP target is a no-op" \
    || fail "non-IP target should be a no-op"
}

###############################################################################
# Per-user block layer — ~/.sandbox/config.yaml additions are unioned in, and
# bounded reads mean extra_allowed_domains in the SAME file is NOT misread as a
# block (the reason _check_domain_against_blocked_file reads via the key-bounded
# extractor rather than an unbounded grep).
###############################################################################
test_user_block_layer() {
  info "Testing per-user block layer (~/.sandbox/config.yaml)..."
  unset SANDBOX_OVERLAY
  mkdir -p "$(dirname "${USER_SANDBOX_CONFIG}")"

  # Org blocks nothing relevant; the user file adds domains + a CIDR, and also
  # carries an unrelated extra_allowed_domains list.
  write_blocked "blocked_domains:" "  - pastebin.com" "blocked_cidrs:"
  printf '%s\n' \
    "extra_allowed_domains:" \
    "  - allowed.example.com" \
    "blocked_domains:" \
    "  - secret.internal" \
    "  - '*.prod.example.com'" \
    "blocked_cidrs:" \
    "  - 172.16.0.0/12" \
    > "${USER_SANDBOX_CONFIG}"

  grep -qx '172.16.0.0/12' <<<"$(get_blocked_cidrs)" \
    || fail "user blocked_cidrs not unioned into get_blocked_cidrs"
  pass "user blocked_cidrs unioned into the deny set"

  ( check_domain_not_blocked "allowed.example.com" >/dev/null 2>&1 ) \
    || fail "user extra_allowed_domains bled into the block list (bounded-read regression)"
  pass "extra_allowed_domains in the same file is not misread as a block"

  ( check_domain_not_blocked "secret.internal" >/dev/null 2>&1 ) \
    && fail "user-blocked 'secret.internal' should be rejected" || true
  ( check_domain_not_blocked "api.prod.example.com" >/dev/null 2>&1 ) \
    && fail "user-blocked '*.prod.example.com' should reject subdomains" || true
  pass "user-level blocked_domains (exact + wildcard) rejected"

  ( check_egress_target_not_blocked "172.16.5.5" >/dev/null 2>&1 ) \
    && fail "user-blocked CIDR 172.16.0.0/12 should reject 172.16.5.5" || true
  pass "user-level blocked_cidrs rejects a matching IP via the combiner"

  rm -f "${USER_SANDBOX_CONFIG}"
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""
  echo "Test directory: ${TEST_DIR}"
  echo ""

  test_validate_cidr
  test_get_blocked_cidrs
  test_check_blocked_cidrs_valid
  test_blocked_cidrs_completeness
  test_policy_egress_deny
  test_ip_in_cidr
  test_check_ip_not_in_blocked_cidrs
  test_user_block_layer

  echo ""
  echo "All blocked-CIDR tests passed."
}

main "$@"
