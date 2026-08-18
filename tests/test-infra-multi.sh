#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-infra-multi.sh — Multiple Tier 3 kubeconfigs and infra tokens.
#
# A session can now be handed more than one --infra-kubeconfig and more than one
# --infra-token. This exercises the four render/merge paths that made that work,
# all cluster-free except merge_kubeconfigs (which needs the kubectl client and
# is skipped with a note when it is absent):
#   1. build_cilium_policy emits one toCIDR rule per cluster, ports index-aligned
#      (and stays byte-identical for the single-cluster case).
#   2. build_pod_manifest emits one hostAliases entry per cluster.
#   3. merge_kubeconfigs folds several minified kubeconfigs into one file with
#      collision-free context names and every credential preserved.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$(mktemp -d /tmp/sandbox-infra-multi-XXXXXX)"
HOME="${TEST_DIR}/home"; mkdir -p "${HOME}"
SANDBOX_NAMESPACE="sandbox"
SANDBOX_SERVICE_ACCOUNT="sandbox-runner"

cleanup() { rm -rf "${TEST_DIR}"; }
trap cleanup EXIT

# Stub the domain helpers build_cilium_policy pulls in, so these tests exercise
# only the kube-API toCIDR rendering and not the per-agent/per-tier allowlists.
source "${SANDBOX_ROOT}/lib/platform.sh"
source "${SANDBOX_ROOT}/lib/resources.sh"
source "${SANDBOX_ROOT}/lib/filesystem.sh"
source "${SANDBOX_ROOT}/lib/policy.sh"
source "${SANDBOX_ROOT}/lib/manifest.sh"
source "${SANDBOX_ROOT}/lib/cluster.sh"
get_agent_domains() { :; }
get_tier_domains() { :; }
get_blocked_cidrs() { :; }
_normalize_domain() { echo "$1"; }
_apex_is_registrable_domain() { return 1; }
domain_is_blocked() { return 1; }

###############################################################################
# build_cilium_policy — one toCIDR rule per cluster
###############################################################################
test_policy_multi_cidr() {
  info "Testing build_cilium_policy renders one toCIDR rule per cluster..."

  local pol
  pol="$(build_cilium_policy ses-x claude 3 "10.1.2.3/32,10.9.8.7/32" "6443,443")"

  [[ "$(printf '%s\n' "${pol}" | grep -c 'toCIDR')" -eq 2 ]] \
    && pass "two clusters -> two toCIDR rules" \
    || fail "expected 2 toCIDR rules, got $(printf '%s\n' "${pol}" | grep -c 'toCIDR')"

  printf '%s\n' "${pol}" | grep -q '10.1.2.3/32' \
    && printf '%s\n' "${pol}" | grep -q '10.9.8.7/32' \
    && pass "both cluster CIDRs present" \
    || fail "a cluster CIDR is missing from the policy"

  # Ports are index-aligned with their CIDRs, not collapsed to one value.
  printf '%s\n' "${pol}" | grep -q 'port: "6443"' \
    && printf '%s\n' "${pol}" | grep -q 'port: "443"' \
    && pass "per-cluster ports (6443 and 443) both present" \
    || fail "per-cluster ports not both rendered"

  # Single-cluster case stays exactly as before: one rule, its own port.
  local one
  one="$(build_cilium_policy ses-y claude 3 "10.1.2.3/32" "6443")"
  [[ "$(printf '%s\n' "${one}" | grep -c 'toCIDR')" -eq 1 ]] \
    && pass "single cluster -> one toCIDR rule (back-compat)" \
    || fail "single-cluster rendering changed"

  # A short/missing port entry falls back to 443 rather than mis-aligning: the
  # toCIDR block for the second cluster must be followed by port 443.
  local dflt
  dflt="$(build_cilium_policy ses-w claude 3 "10.1.2.3/32,10.9.8.7/32" "6443")"
  printf '%s\n' "${dflt}" | grep -A5 '10.9.8.7/32' | grep -q 'port: "443"' \
    && pass "missing port entry defaults to 443" \
    || fail "second cluster did not default to port 443"

  # No clusters -> no toCIDR block at all.
  [[ "$(build_cilium_policy ses-z claude 1 "" "" | grep -c 'toCIDR')" -eq 0 ]] \
    && pass "no clusters -> no toCIDR block" \
    || fail "toCIDR block rendered with no clusters"
}

###############################################################################
# build_pod_manifest — one hostAliases entry per cluster
###############################################################################
test_manifest_multi_hostalias() {
  info "Testing build_pod_manifest renders one hostAliases entry per cluster..."

  local man
  man="$(HOME="${HOME}" build_pod_manifest ses1 claude 3 img "" probe "" \
    sandbox-ses1 1 "10.0.0.1,10.0.0.2" "dev.example.com,prod.example.com")"

  [[ "$(printf '%s\n' "${man}" | grep -c '      hostnames:')" -eq 2 ]] \
    && pass "two clusters -> two hostAliases entries" \
    || fail "expected 2 hostAliases entries"
  printf '%s\n' "${man}" | grep -q 'ip: "10.0.0.1"' \
    && printf '%s\n' "${man}" | grep -q 'ip: "10.0.0.2"' \
    && printf '%s\n' "${man}" | grep -q 'dev.example.com' \
    && printf '%s\n' "${man}" | grep -q 'prod.example.com' \
    && pass "both ip/host pairs present" \
    || fail "a hostAlias ip/host pair is missing"

  # Single cluster: one entry (back-compat).
  local one
  one="$(HOME="${HOME}" build_pod_manifest ses2 claude 3 img "" probe "" \
    sandbox-ses2 1 "10.0.0.1" "dev.example.com")"
  [[ "$(printf '%s\n' "${one}" | grep -c '      hostnames:')" -eq 1 ]] \
    && pass "single cluster -> one hostAliases entry (back-compat)" \
    || fail "single-cluster hostAliases changed"

  # No clusters: no hostAliases block.
  local none
  none="$(HOME="${HOME}" build_pod_manifest ses3 claude 1 img "" probe "" \
    sandbox-ses3 "" "" "")"
  [[ "$(printf '%s\n' "${none}" | grep -c 'hostAliases')" -eq 0 ]] \
    && pass "no clusters -> no hostAliases block" \
    || fail "hostAliases block rendered with no clusters"
}

###############################################################################
# merge_kubeconfigs — fold several minified kubeconfigs into one (needs kubectl)
###############################################################################
test_merge_kubeconfigs() {
  if ! command -v kubectl >/dev/null 2>&1; then
    info "no kubectl client available — skipping merge_kubeconfigs check (not a failure)"
    return 0
  fi
  info "Testing merge_kubeconfigs folds kubeconfigs into one, collisions and all..."

  # Two kubeconfigs that DELIBERATELY collide on every internal name ("default")
  # and use different static auth (token vs client cert/key), so the merge has
  # to both rename and carry credentials verbatim.
  cat > "${TEST_DIR}/dev.yaml" <<'EOF'
apiVersion: v1
kind: Config
clusters:
- name: default
  cluster:
    server: https://dev.example.com:6443
    certificate-authority-data: ZGV2LWNh
users:
- name: default
  user:
    token: dev-token-123
contexts:
- name: default
  context:
    cluster: default
    user: default
current-context: default
EOF
  cat > "${TEST_DIR}/prod.yaml" <<'EOF'
apiVersion: v1
kind: Config
clusters:
- name: default
  cluster:
    server: https://prod.example.com:443
    certificate-authority-data: cHJvZC1jYQ==
users:
- name: default
  user:
    client-certificate-data: cHJvZC1jZXJ0
    client-key-data: cHJvZC1rZXk=
contexts:
- name: default
  context:
    cluster: default
    user: default
current-context: default
EOF

  minify_kubeconfig "${TEST_DIR}/dev.yaml" "" > "${TEST_DIR}/part-0"
  minify_kubeconfig "${TEST_DIR}/prod.yaml" "" > "${TEST_DIR}/part-1"
  merge_kubeconfigs "${TEST_DIR}/merged" "${TEST_DIR}/part-0" "${TEST_DIR}/part-1"

  local ctxs
  ctxs="$(kubectl --kubeconfig="${TEST_DIR}/merged" config get-contexts -o name | sort | tr '\n' ' ')"
  [[ "${ctxs}" == "default default-2 " ]] \
    && pass "colliding context names -> default, default-2" \
    || fail "expected 'default default-2', got '${ctxs}'"

  [[ "$(kubectl --kubeconfig="${TEST_DIR}/merged" config current-context)" == "default" ]] \
    && pass "current-context is the first source" \
    || fail "current-context is not the first source"

  local tok
  tok="$(kubectl --kubeconfig="${TEST_DIR}/merged" config view --raw \
    -o jsonpath='{.users[?(@.name=="sandbox-user-0")].user.token}')"
  [[ "${tok}" == "dev-token-123" ]] \
    && pass "token credential preserved" \
    || fail "token credential lost (got '${tok}')"

  # Base64 blobs must survive the --set-raw-bytes=false round-trip byte-for-byte.
  local ca key
  ca="$(kubectl --kubeconfig="${TEST_DIR}/merged" config view --raw \
    -o jsonpath='{.clusters[?(@.name=="sandbox-cluster-1")].cluster.certificate-authority-data}')"
  key="$(kubectl --kubeconfig="${TEST_DIR}/merged" config view --raw \
    -o jsonpath='{.users[?(@.name=="sandbox-user-1")].user.client-key-data}')"
  [[ "${ca}" == "cHJvZC1jYQ==" ]] \
    && pass "CA data round-trips byte-for-byte" \
    || fail "CA data corrupted (got '${ca}')"
  [[ "${key}" == "cHJvZC1rZXk=" ]] \
    && pass "client-key data round-trips byte-for-byte" \
    || fail "client-key data corrupted (got '${key}')"

  local servers
  servers="$(kubectl --kubeconfig="${TEST_DIR}/merged" config view --raw \
    -o jsonpath='{range .clusters[*]}{.cluster.server}{"\n"}{end}' | sort | tr '\n' ' ')"
  [[ "${servers}" == "https://dev.example.com:6443 https://prod.example.com:443 " ]] \
    && pass "both cluster servers survive the merge" \
    || fail "a cluster server was dropped (got '${servers}')"
}

info "Running test-infra-multi tests..."
test_policy_multi_cidr
test_manifest_multi_hostalias
test_merge_kubeconfigs
echo "All test-infra-multi tests passed."
