#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-tier3-host-entity.sh — Tier 3 kube API egress shape. Verifies
# that a session policy grants the API port via toEntities: host (Cilium's
# reserved:host identity — needed when the infra cluster's API server is
# actually running on the sandbox's own node, e.g. a local k3d/podman
# cluster; a toCIDR-only rule there gets masqueraded out the primary
# interface and needs the network to hairpin the packet back to the same
# host, which isn't universal — confirmed failing identically over Wi-Fi and
# Ethernet, and confirmed fixed by toEntities: host, on real hardware before
# this test was written) ONLY when the caller sets SESSION_KUBE_HOST_ENTITY=
# true — bin/sandbox's signal that kube_api_cidr's IP resolved to this same
# host. toCIDR alone is always granted whenever kube_api_cidr is set,
# regardless of that flag: it's the only thing that matters for a genuinely
# remote cluster.
#
# This gating matters because toEntities: host matches on *this node*, not
# on kube_api_cidr's IP — an unconditional grant would open pod → this host
# on kube_api_port for every Tier 3 session, including remote ones, reaching
# the sandbox's own confining k3s control plane if a remote API happens to
# share its port (6443 default for both). See lib/policy.sh.
# Cluster-free. Requires yq.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$(mktemp -d /tmp/sandbox-tier3hostentity-test-XXXXXX)"
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

eq() {
  local label="$1" expected="$2" actual="$3"
  [[ "${expected}" == "${actual}" ]] && pass "${label}" \
    || fail "${label}: expected '${expected}', got '${actual}'"
}

SID="ses-cd34"

test_same_node_grants_both_cidr_and_host_entity() {
  info "Testing SESSION_KUBE_HOST_ENTITY=true grants toCIDR AND toEntities:host..."
  local pol
  SESSION_KUBE_HOST_ENTITY="true" \
    pol="$(build_cilium_policy "${SID}" claude 3 "192.168.1.38/32" "6550")"
  echo "${pol}" | yq e '.' >/dev/null || fail "policy is not valid YAML"

  eq "toCIDR entry" "192.168.1.38/32" \
    "$(echo "${pol}" | yq e '.spec.egress[] | select(.toCIDR) | .toCIDR[0]' -)"
  eq "toCIDR port" "6550" \
    "$(echo "${pol}" | yq e '.spec.egress[] | select(.toCIDR) | .toPorts[0].ports[0].port' -)"

  eq "toEntities entry" "host" \
    "$(echo "${pol}" | yq e '.spec.egress[] | select(.toEntities) | .toEntities[0]' -)"
  eq "toEntities port" "6550" \
    "$(echo "${pol}" | yq e '.spec.egress[] | select(.toEntities) | .toPorts[0].ports[0].port' -)"
}

test_remote_cluster_grants_cidr_only() {
  info "Testing a remote cluster (kube_api_cidr set, SESSION_KUBE_HOST_ENTITY unset) grants toCIDR but NOT toEntities:host..."
  local pol
  unset SESSION_KUBE_HOST_ENTITY || true
  pol="$(build_cilium_policy "${SID}" claude 3 "203.0.113.9/32" "6443")"
  echo "${pol}" | yq e '.' >/dev/null || fail "policy is not valid YAML"

  eq "toCIDR entry" "203.0.113.9/32" \
    "$(echo "${pol}" | yq e '.spec.egress[] | select(.toCIDR) | .toCIDR[0]' -)"
  eq "no toEntities block" "0" \
    "$(echo "${pol}" | yq e '[.spec.egress[] | select(.toEntities)] | length' -)"
}

test_no_kube_api_cidr_grants_neither() {
  info "Testing no kube_api_cidr (tiers 1/2) has no toCIDR/toEntities block, even with the flag set..."
  local pol
  SESSION_KUBE_HOST_ENTITY="true" \
    pol="$(build_cilium_policy "${SID}" claude 2 "" "")"
  echo "${pol}" | yq e '.' >/dev/null || fail "policy is not valid YAML"

  eq "no toCIDR block" "0" \
    "$(echo "${pol}" | yq e '[.spec.egress[] | select(.toCIDR)] | length' -)"
  eq "no toEntities block" "0" \
    "$(echo "${pol}" | yq e '[.spec.egress[] | select(.toEntities)] | length' -)"
}

main() {
  test_same_node_grants_both_cidr_and_host_entity
  test_remote_cluster_grants_cidr_only
  test_no_kube_api_cidr_grants_neither
  echo "All tier3-host-entity tests passed."
}
main "$@"
