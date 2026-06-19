#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-policy-deps.sh — Phase 5 network-policy shape. Verifies that:
#   - the session policy gains a toEndpoints rule + a cluster-local DNS allow per
#     dependency, and NO toFQDNs entry for the cluster-local name (it is reached
#     by endpoint identity, not by dialing a world IP);
#   - the session policy is unchanged when no dependencies are declared;
#   - a dependency policy is a clone-or-subset of the session egress, with
#     ingress accepted ONLY from the owning session pod;
#   - a dependency with no egress gets an explicit `dns: []` (deny-all names),
#     never a bare `dns:` (which would mean unfiltered DNS).
# Cluster-free. Requires yq.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$(mktemp -d /tmp/sandbox-policydeps-test-XXXXXX)"
HOME="${TEST_DIR}/home"; mkdir -p "${HOME}"
SANDBOX_NAMESPACE="sandbox"

cleanup() { rm -rf "${TEST_DIR}"; }
trap cleanup EXIT

command -v yq >/dev/null 2>&1 || skip "yq not installed — policy shape test needs it"

USER_SANDBOX_CONFIG="${HOME}/.sandbox/config.yaml"
BLOCKED_DESTINATIONS_CONFIG="${TEST_DIR}/blocked.yaml"
cat > "${BLOCKED_DESTINATIONS_CONFIG}" <<'YAML'
blocked_domains: []
blocked_cidrs:
  - "169.254.0.0/16"
YAML

source "${SANDBOX_ROOT}/lib/platform.sh"
source "${SANDBOX_ROOT}/lib/config.sh"
source "${SANDBOX_ROOT}/lib/profile.sh"
source "${SANDBOX_ROOT}/lib/checks.sh"
source "${SANDBOX_ROOT}/lib/agents.sh"
source "${SANDBOX_ROOT}/lib/tier.sh"
source "${SANDBOX_ROOT}/lib/policy.sh"
source "${SANDBOX_ROOT}/lib/dependency.sh"

eq() {
  local label="$1" expected="$2" actual="$3"
  [[ "${expected}" == "${actual}" ]] && pass "${label}" \
    || fail "${label}: expected '${expected}', got '${actual}'"
}

SID="ses-ab12"
RNAME="dep-innkeeper-mcp-${SID}"
FQDN="${RNAME}.sandbox.svc.cluster.local"

test_session_policy_with_dep() {
  info "Testing session policy gains dep toEndpoints + cluster.local DNS..."
  local pol
  SESSION_DEP_ENDPOINTS=("${RNAME} 8080")
  pol="$(build_cilium_policy "${SID}" claude 2 "" "")"
  SESSION_DEP_ENDPOINTS=()

  echo "${pol}" | yq e '.' >/dev/null || fail "session policy is not valid YAML"

  # A toEndpoints rule scoped to the dependency identity + port.
  eq "dep toEndpoints label" "${RNAME}" \
    "$(echo "${pol}" | yq e '.spec.egress[] | select(.toEndpoints[].matchLabels."sandbox-dependency" == "'"${RNAME}"'") | .toEndpoints[0].matchLabels."sandbox-dependency"' - | head -1)"
  eq "dep toEndpoints port" "8080" \
    "$(echo "${pol}" | yq e '.spec.egress[] | select(.toEndpoints[].matchLabels."sandbox-dependency" == "'"${RNAME}"'") | .toPorts[0].ports[0].port' - | head -1)"

  # The cluster-local name is in the L7 DNS allow...
  echo "${pol}" | yq e '.spec.egress[].toPorts[].rules.dns[].matchName' - 2>/dev/null \
    | grep -qx "${FQDN}" || fail "cluster-local FQDN missing from L7 DNS allow"
  pass "cluster-local FQDN in DNS allow"

  # ...but NOT in toFQDNs (reached by endpoint identity, not a world IP).
  if echo "${pol}" | yq e '.spec.egress[] | select(.toFQDNs) | .toFQDNs[].matchName' - 2>/dev/null \
       | grep -qx "${FQDN}"; then
    fail "cluster-local FQDN must NOT appear in toFQDNs"
  fi
  pass "cluster-local FQDN absent from toFQDNs"
}

test_session_policy_without_dep_unchanged() {
  info "Testing session policy without deps has no dep toEndpoints..."
  local pol
  pol="$(build_cilium_policy "${SID}" claude 1 "" "")"
  echo "${pol}" | yq e '.' >/dev/null || fail "session policy is not valid YAML"
  # Only the kube-dns toEndpoints should exist — no sandbox-dependency selector.
  if echo "${pol}" | yq e '.spec.egress[].toEndpoints[].matchLabels."sandbox-dependency"' - 2>/dev/null \
       | grep -qv '^null$'; then
    fail "no-dep session policy should not reference any dependency"
  fi
  pass "no-dep session policy is clean"
}

test_dep_policy_with_egress() {
  info "Testing dependency policy with egress (clone-or-subset)..."
  local pol
  pol="$(build_dependency_policy "${SID}" "${RNAME}" 8080 api.internal.example.com)"
  echo "${pol}" | yq e '.' >/dev/null || fail "dep policy is not valid YAML"

  eq "endpoint selector" "${RNAME}" \
    "$(echo "${pol}" | yq e '.spec.endpointSelector.matchLabels."sandbox-dependency"' -)"

  # Egress 443 limited to the declared allowlist.
  eq "toFQDNs allow" "api.internal.example.com" \
    "$(echo "${pol}" | yq e '.spec.egress[] | select(.toFQDNs) | .toFQDNs[0].matchName' -)"
  # egressDeny carries the blocked CIDR backstop.
  echo "${pol}" | yq e '.spec.egressDeny[].toCIDR[]' - 2>/dev/null \
    | grep -qx "169.254.0.0/16" || fail "dep policy missing blocked-CIDR backstop"
  pass "dep egress allowlist + CIDR backstop present"

  # Ingress accepted ONLY from the owning session pod.
  eq "ingress session label" "${SID}" \
    "$(echo "${pol}" | yq e '.spec.ingress[0].fromEndpoints[0].matchLabels."sandbox-session"' -)"
  eq "ingress role label" "session" \
    "$(echo "${pol}" | yq e '.spec.ingress[0].fromEndpoints[0].matchLabels."sandbox-role"' -)"
  eq "ingress port" "8080" \
    "$(echo "${pol}" | yq e '.spec.ingress[0].toPorts[0].ports[0].port' -)"
}

test_dep_policy_no_egress() {
  info "Testing dependency policy with no egress gets dns: [] and no toFQDNs..."
  local pol
  pol="$(build_dependency_policy "${SID}" "dep-pg-${SID}" 5432)"
  echo "${pol}" | yq e '.' >/dev/null || fail "dep policy is not valid YAML"

  # dns must be an explicit empty list (deny all names), not null.
  local dns_type
  dns_type="$(echo "${pol}" | yq e '.spec.egress[0].toPorts[0].rules.dns | tag' -)"
  eq "dns is a (empty) sequence" "!!seq" "${dns_type}"
  eq "dns length 0" "0" "$(echo "${pol}" | yq e '.spec.egress[0].toPorts[0].rules.dns | length' -)"

  # No toFQDNs egress at all.
  eq "no toFQDNs block" "0" \
    "$(echo "${pol}" | yq e '[.spec.egress[] | select(.toFQDNs)] | length' -)"
}

main() {
  test_session_policy_with_dep
  test_session_policy_without_dep_unchanged
  test_dep_policy_with_egress
  test_dep_policy_no_egress
  echo "All policy-deps tests passed."
}
main "$@"
