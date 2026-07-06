#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-copilot.sh — GitHub Copilot agent wiring (cluster-free).
# Verifies the parts of Copilot support that need no live cluster:
#   - validate_agent / credential_type / domain list;
#   - the GitHub tokens are on the host-env blocklist (OAuth-only posture);
#   - build_cilium_policy renders the *.githubcopilot.com wildcard as a Cilium
#     matchPattern in BOTH the L7 DNS rules and the toFQDNs allow, and an exact
#     host as matchName — i.e. the DNS filter stays coupled to the FQDN allow
#     even with a wildcard entry (lib/policy.sh's anti-exfil property).
# The live network + credential-isolation behaviour is in the manual
# cluster tests test-copilot-tier1.sh and test-credentials-copilot.sh.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-copilot"
TEST_DIR="$(mktemp -d /tmp/sandbox-copilot-test-XXXXXX)"
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
  info "Testing validate_agent + credential type for copilot..."
  ( validate_agent copilot ) && pass "validate_agent accepts copilot" \
    || fail "validate_agent rejected copilot"
  eq "credential_type is oauth" "oauth" "$(get_agent_credential_type copilot)"
}

test_domains() {
  info "Testing get_agent_domains copilot..."
  local domains; domains="$(get_agent_domains copilot)"
  contains_line "control plane github.com listed"     "github.com"          <<< "${domains}"
  contains_line "api.github.com listed"               "api.github.com"      <<< "${domains}"
  contains_line "model API wildcard listed"           "*.githubcopilot.com" <<< "${domains}"
  contains_line "completions proxy listed" "copilot-proxy.githubusercontent.com" <<< "${domains}"
}

###############################################################################
# Credential isolation — GitHub tokens must be on the host-env blocklist so an
# env token can never substitute for OAuth (PRINCIPLES.md, lib/credentials.sh).
###############################################################################
test_tokens_blocklisted() {
  info "Testing GitHub tokens are on HOST_ENV_BLOCKLIST..."
  local var
  for var in COPILOT_GITHUB_TOKEN GH_TOKEN GITHUB_TOKEN; do
    if printf '%s\n' "${HOST_ENV_BLOCKLIST[@]}" | grep -qxF "${var}"; then
      pass "${var} is blocklisted"
    else
      fail "${var} missing from HOST_ENV_BLOCKLIST"
    fi
  done
}

###############################################################################
# Policy rendering — the wildcard-coupling property.
###############################################################################
test_policy_wildcard_coupling() {
  info "Testing build_cilium_policy renders the copilot wildcard correctly..."
  local pol
  SESSION_DEP_ENDPOINTS=()
  pol="$(build_cilium_policy "ses-cop1" copilot 1 "" "")"

  # The wildcard appears exactly twice as a matchPattern — once in the L7 DNS
  # rules, once in toFQDNs — proving the DNS filter is coupled to the FQDN allow.
  # (grep -c exits 1 on a zero count, which would trip set -e in the command
  # substitution, so guard every count with '|| true'.)
  local wild_pattern
  wild_pattern="$(grep -c 'matchPattern: "\*.githubcopilot.com"' <<< "${pol}" || true)"
  eq "wildcard rendered as matchPattern twice (DNS + FQDN)" "2" "${wild_pattern}"

  # It must NEVER be emitted as a literal matchName (that would not match subdomains).
  local wild_name
  wild_name="$(grep -c 'matchName: "\*.githubcopilot.com"' <<< "${pol}" || true)"
  eq "wildcard never rendered as matchName" "0" "${wild_name}"

  # An exact host is a matchName, also in both blocks.
  local exact
  exact="$(grep -c 'matchName: "api.github.com"' <<< "${pol}" || true)"
  eq "exact host rendered as matchName twice (DNS + FQDN)" "2" "${exact}"
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""
  test_validate_and_credtype
  test_domains
  test_tokens_blocklisted
  test_policy_wildcard_coupling
  echo ""
  echo "All ${TEST_NAME} tests passed."
}

main "$@"
