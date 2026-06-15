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

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""
  echo "Test directory: ${TEST_DIR}"
  echo ""

  test_validate_cidr
  test_get_blocked_cidrs
  test_check_blocked_cidrs_valid
  test_policy_egress_deny

  echo ""
  echo "All blocked-CIDR tests passed."
}

main "$@"
