#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-grok.sh — xAI Grok Build CLI agent wiring (cluster-free).
# Verifies the parts of Grok support that need no live cluster:
#   - validate_agent / credential_type / domain list;
#   - GROK_DEPLOYMENT_KEY is on the host-env blocklist (it outranks the OAuth
#     token), while XAI_API_KEY is deliberately NOT (it ranks below OAuth);
#   - build_cilium_policy renders every Grok host as a Cilium matchName in BOTH
#     the L7 DNS rules and the toFQDNs allow, and NEVER as a matchPattern — Grok
#     uses no wildcard domains, the inverse of the copilot case.
# The live network + credential-isolation behaviour is in the manual cluster
# test test-grok-tier1.sh; the onboard model-key guard and audit token/index
# exclusions are covered in test-onboard.sh and test-audit.sh.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-grok"
TEST_DIR="$(mktemp -d /tmp/sandbox-grok-test-XXXXXX)"
HOME="${TEST_DIR}/home"; mkdir -p "${HOME}"
SANDBOX_NAMESPACE="sandbox"

cleanup() { rm -rf "${TEST_DIR}"; }
trap cleanup EXIT

USER_SANDBOX_CONFIG="${HOME}/.sandbox/config.yaml"
BLOCKED_DESTINATIONS_CONFIG="${TEST_DIR}/blocked.yaml"
cat > "${BLOCKED_DESTINATIONS_CONFIG}" <<'YAML'
blocked_domains: []
blocked_cidrs:
  - "169.254.0.0/16"
YAML

source "${SANDBOX_ROOT}/lib/platform.sh"
source "${SANDBOX_ROOT}/lib/config.sh"
source "${SANDBOX_ROOT}/lib/checks.sh"
source "${SANDBOX_ROOT}/lib/credentials.sh"
source "${SANDBOX_ROOT}/lib/agents.sh"
source "${SANDBOX_ROOT}/lib/tier.sh"
source "${SANDBOX_ROOT}/lib/policy.sh"

eq() {
  local label="$1" expected="$2" actual="$3"
  [[ "${expected}" == "${actual}" ]] && pass "${label}" \
    || fail "${label}: expected '${expected}', got '${actual}'"
}

contains_line() {
  # contains_line <label> <needle> <<< "$haystack"
  local label="$1" needle="$2" hay; hay="$(cat)"
  if grep -qxF "${needle}" <<< "${hay}"; then
    pass "${label}"
  else
    fail "${label}: '${needle}' not found"
  fi
}

###############################################################################
# Agent identity helpers
###############################################################################
test_validate_and_credtype() {
  info "Testing validate_agent + credential type for grok..."
  ( validate_agent grok ) && pass "validate_agent accepts grok" \
    || fail "validate_agent rejected grok"
  eq "credential_type is oauth" "oauth" "$(get_agent_credential_type grok)"
}

test_domains() {
  info "Testing get_agent_domains grok..."
  local domains; domains="$(get_agent_domains grok)"
  contains_line "model API api.x.ai listed"    "api.x.ai"      <<< "${domains}"
  contains_line "OAuth accounts.x.ai listed"    "accounts.x.ai" <<< "${domains}"
  contains_line "device-auth auth.x.ai listed"  "auth.x.ai"     <<< "${domains}"
  contains_line "grok.com listed"               "grok.com"      <<< "${domains}"
  # Grok uses no wildcard hosts — assert the list carries no '*' entry.
  local wildcards; wildcards="$(grep -c '\*' <<< "${domains}" || true)"
  eq "no wildcard domains" "0" "${wildcards}"
}

###############################################################################
# Credential isolation — GROK_DEPLOYMENT_KEY must be blocklisted (it outranks
# the stored OAuth token); XAI_API_KEY must NOT be (it ranks below OAuth and is
# a common var, so blocklisting it would spew cross-agent warnings).
###############################################################################
test_deployment_key_blocklisted() {
  info "Testing GROK_DEPLOYMENT_KEY is on HOST_ENV_BLOCKLIST (and XAI_API_KEY is not)..."
  if printf '%s\n' "${HOST_ENV_BLOCKLIST[@]}" | grep -qxF "GROK_DEPLOYMENT_KEY"; then
    pass "GROK_DEPLOYMENT_KEY is blocklisted"
  else
    fail "GROK_DEPLOYMENT_KEY missing from HOST_ENV_BLOCKLIST"
  fi
  if printf '%s\n' "${HOST_ENV_BLOCKLIST[@]}" | grep -qxF "XAI_API_KEY"; then
    fail "XAI_API_KEY should NOT be blocklisted (it ranks below OAuth)"
  else
    pass "XAI_API_KEY deliberately not blocklisted"
  fi
}

###############################################################################
# Policy rendering — every Grok host is a matchName in both blocks, never a
# matchPattern (no wildcards). This is the inverse of the copilot wildcard test.
###############################################################################
test_policy_all_matchname() {
  info "Testing build_cilium_policy renders Grok hosts as matchName (never matchPattern)..."
  local pol
  SESSION_DEP_ENDPOINTS=()
  pol="$(build_cilium_policy "ses-grok1" grok 1 "" "")"

  # Each exact host renders as a matchName exactly twice — once in the L7 DNS
  # rules, once in toFQDNs — proving the DNS filter stays coupled to the FQDN
  # allow. (grep -c exits 1 on zero, which trips set -e in $(...), so guard with
  # '|| true'.)
  local host count
  for host in api.x.ai accounts.x.ai auth.x.ai grok.com; do
    count="$(grep -c "matchName: \"${host}\"" <<< "${pol}" || true)"
    eq "${host} rendered as matchName twice (DNS + FQDN)" "2" "${count}"
  done

  # No Grok host should ever be emitted as a matchPattern (Grok has no wildcards).
  local patt
  patt="$(grep -c 'matchPattern: ".*\(x\.ai\|grok\.com\)"' <<< "${pol}" || true)"
  eq "no Grok host rendered as matchPattern" "0" "${patt}"
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""
  test_validate_and_credtype
  test_domains
  test_deployment_key_blocklisted
  test_policy_all_matchname
  echo ""
  echo "All ${TEST_NAME} tests passed."
}

main "$@"
