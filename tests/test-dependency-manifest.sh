#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-dependency-manifest.sh — Additive-from-empty dependency pod +
# Service manifests, and the check_dependency_no_host_mounts invariant
# (Phase 5). Verifies a dependency pod carries the gVisor + securityContext
# floor, NO host mounts / volumes / secret-env by default, an ownerReference
# when an owner is given, and that the no-host-mounts check fails closed on an
# injected hostPath. Cluster-free.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$(mktemp -d /tmp/sandbox-depmanifest-test-XXXXXX)"
HOME="${TEST_DIR}/home"; mkdir -p "${HOME}"
SANDBOX_NAMESPACE="sandbox"

cleanup() { rm -rf "${TEST_DIR}"; }
trap cleanup EXIT

USER_SANDBOX_CONFIG="${HOME}/.sandbox/config.yaml"

source "${SANDBOX_ROOT}/lib/config.sh"
source "${SANDBOX_ROOT}/lib/profile.sh"
source "${SANDBOX_ROOT}/lib/checks.sh"
source "${SANDBOX_ROOT}/lib/catalogue.sh"
source "${SANDBOX_ROOT}/lib/agents.sh"
source "${SANDBOX_ROOT}/lib/resources.sh"
source "${SANDBOX_ROOT}/lib/secrets.sh"
source "${SANDBOX_ROOT}/lib/dependency.sh"

# resolve_session_dependencies reads the catalogue from SANDBOX_ROOT/config and
# the blocked list from BLOCKED_DESTINATIONS_CONFIG; point both at fixtures.
RESOLVE_ROOT="${TEST_DIR}/resolve-root"
mkdir -p "${RESOLVE_ROOT}/config/catalogue"
BLOCKED_DESTINATIONS_CONFIG="${RESOLVE_ROOT}/blocked.yaml"
printf 'blocked_domains:\nblocked_cidrs:\n  - "169.254.0.0/16"\n' > "${BLOCKED_DESTINATIONS_CONFIG}"

DIGEST="sha256:0000000000000000000000000000000000000000000000000000000000000000"

eq() {
  local label="$1" expected="$2" actual="$3"
  [[ "${expected}" == "${actual}" ]] && pass "${label}" \
    || fail "${label}: expected '${expected}', got '${actual}'"
}

have_yq() { command -v yq >/dev/null 2>&1; }

# A minimal MCP catalogue entry fixture.
CAT="${TEST_DIR}/innkeeper-mcp.yaml"
cat > "${CAT}" <<YAML
name: innkeeper-mcp
kind: mcp
image: ghcr.io/x/innkeeper@${DIGEST}
port: 8080
YAML

SID="ses-ab12"
RNAME="$(dependency_resource_name innkeeper-mcp "${SID}")"

test_resource_naming() {
  info "Testing dependency resource naming + FQDN..."
  eq "resource name" "dep-innkeeper-mcp-ses-ab12" "${RNAME}"
  eq "service FQDN" "dep-innkeeper-mcp-ses-ab12.sandbox.svc.cluster.local" \
    "$(dependency_service_fqdn "${RNAME}")"
  # Catalogue name with caps/dots is sanitized to a DNS-1123 label.
  eq "sanitized name" "dep-my-dep-ses-ab12" \
    "$(dependency_resource_name "My.Dep" "${SID}")"
}

test_additive_from_empty() {
  info "Testing dependency pod is additive-from-empty (no mounts/volumes/secrets)..."
  local pod
  pod="$(build_dependency_pod_manifest "${SID}" 2 innkeeper-mcp "${RNAME}" "${CAT}" "owner-pod" "uid-123" "")"

  # No host mounts, ever.
  echo "${pod}" | grep -q 'hostPath' && fail "dependency pod must not contain hostPath"
  pass "no hostPath"
  # No volumes block at all (additive-from-empty).
  echo "${pod}" | grep -qE '^\s*volumes:' && fail "dependency pod must not declare volumes"
  pass "no volumes"
  # No secret env when no bundle was passed.
  echo "${pod}" | grep -q 'envFrom' && fail "dependency pod must not have envFrom without a secret bundle"
  pass "no secret env by default"

  if have_yq; then
    echo "${pod}" | yq e '.' >/dev/null || fail "dependency pod is not valid YAML"
    eq "gVisor runtime" "gvisor" "$(echo "${pod}" | yq e '.spec.runtimeClassName' -)"
    eq "no SA token" "false" "$(echo "${pod}" | yq e '.spec.automountServiceAccountToken' -)"
    eq "runAsNonRoot" "true" "$(echo "${pod}" | yq e '.spec.securityContext.runAsNonRoot' -)"
    eq "drop ALL caps" "ALL" "$(echo "${pod}" | yq e '.spec.containers[0].securityContext.capabilities.drop[0]' -)"
    eq "no privesc" "false" "$(echo "${pod}" | yq e '.spec.containers[0].securityContext.allowPrivilegeEscalation' -)"
    eq "ndots 1" "1" "$(echo "${pod}" | yq e '.spec.dnsConfig.options[0].value' -)"
    eq "session label" "${SID}" "$(echo "${pod}" | yq e '.metadata.labels.sandbox-session' -)"
    eq "dependency role" "dependency" "$(echo "${pod}" | yq e '.metadata.labels.sandbox-role' -)"
    eq "ownerRef uid" "uid-123" "$(echo "${pod}" | yq e '.metadata.ownerReferences[0].uid' -)"
    eq "container port" "8080" "$(echo "${pod}" | yq e '.spec.containers[0].ports[0].containerPort' -)"
  else
    warn "yq not found — skipping structural assertions"
  fi
}

test_no_owner_dry_run() {
  info "Testing dry-run (no owner) omits ownerReferences..."
  local pod
  pod="$(build_dependency_pod_manifest "${SID}" 1 innkeeper-mcp "${RNAME}" "${CAT}" "" "" "")"
  echo "${pod}" | grep -q 'ownerReferences' && fail "no owner should omit ownerReferences"
  pass "ownerReferences omitted without an owner"
}

test_secret_bundle() {
  info "Testing secret bundle adds envFrom..."
  local pod
  pod="$(build_dependency_pod_manifest "${SID}" 2 innkeeper-mcp "${RNAME}" "${CAT}" "owner-pod" "uid-123" "dep-secrets-x")"
  echo "${pod}" | grep -q 'dep-secrets-x' || fail "secret bundle name should appear in envFrom"
  pass "secret bundle wired into envFrom"
}

test_service_manifest() {
  info "Testing Service manifest..."
  local svc
  svc="$(build_dependency_service "${SID}" innkeeper-mcp "${RNAME}" 8080 "owner-pod" "uid-123")"
  if have_yq; then
    echo "${svc}" | yq e '.' >/dev/null || fail "service is not valid YAML"
    eq "ClusterIP" "ClusterIP" "$(echo "${svc}" | yq e '.spec.type' -)"
    eq "selector" "${RNAME}" "$(echo "${svc}" | yq e '.spec.selector.sandbox-dependency' -)"
    eq "port" "8080" "$(echo "${svc}" | yq e '.spec.ports[0].port' -)"
  else
    warn "yq not found — skipping Service structural assertions"
  fi
}

test_no_host_mounts_check() {
  info "Testing check_dependency_no_host_mounts fails closed on a hostPath..."
  # A clean manifest passes.
  local pod
  pod="$(build_dependency_pod_manifest "${SID}" 1 innkeeper-mcp "${RNAME}" "${CAT}" "" "" "")"
  ( check_dependency_no_host_mounts "${pod}" ) || fail "clean manifest should pass the check"
  pass "clean manifest passes"

  # An injected hostPath is rejected (run in a subshell — the check exits 1).
  local tampered="${pod}
  volumes:
    - name: evil
      hostPath:
        path: /etc
        type: Directory"
  if ( check_dependency_no_host_mounts "${tampered}" ) 2>/dev/null; then
    fail "manifest with hostPath should be rejected"
  fi
  pass "injected hostPath rejected"
}

# Phase 3 — browser pod: command/args pinned, RAM-backed /dev/shm, still no host
# mounts (the emptyDir is not a host mount), caps still dropped.
test_browser_pod_shape() {
  info "Testing browser pod shape (command/args + /dev/shm, no host mounts)..."
  local cat="${TEST_DIR}/playwright.yaml"
  cat > "${cat}" <<YAML
name: playwright
kind: mcp
image: mcr/playwright@${DIGEST}
port: 8931
args:
  - "--no-sandbox"
  - "--block-service-workers"
shm_size: "512Mi"
egress:
  - example.com
YAML
  local pod
  pod="$(build_dependency_pod_manifest "${SID}" 1 playwright "dep-playwright-${SID}" "${cat}" owner uid-1 "")"

  echo "${pod}" | grep -q 'hostPath' && fail "browser pod must not contain hostPath"
  pass "browser pod has no hostPath"
  ( check_dependency_no_host_mounts "${pod}" ) || fail "browser pod should pass no-host-mounts check"
  pass "browser pod passes no-host-mounts check"

  if have_yq; then
    echo "${pod}" | yq e '.' >/dev/null || fail "browser pod is not valid YAML"
    eq "args pinned" "--no-sandbox" "$(echo "${pod}" | yq e '.spec.containers[0].args[0]' -)"
    eq "shm medium" "Memory" "$(echo "${pod}" | yq e '.spec.volumes[] | select(.name=="dshm") | .emptyDir.medium' -)"
    eq "shm size" "512Mi" "$(echo "${pod}" | yq e '.spec.volumes[] | select(.name=="dshm") | .emptyDir.sizeLimit' -)"
    eq "shm mount path" "/dev/shm" "$(echo "${pod}" | yq e '.spec.containers[0].volumeMounts[] | select(.name=="dshm") | .mountPath' -)"
    eq "caps still dropped" "ALL" "$(echo "${pod}" | yq e '.spec.containers[0].securityContext.capabilities.drop[0]' -)"
  else
    warn "yq not found — skipping browser structural assertions"
  fi
}

# resolve_session_dependencies — the orchestration brain: catalogue resolution,
# kind/list agreement, MCP-agent support, and the per-session ceiling (§2.7 #5).
_write_resolve_entry() {
  local name="$1" kind="$2" extra="${3:-}"
  {
    printf 'name: %s\nkind: %s\nimage: ghcr.io/x/%s@%s\nport: 8080\n' \
      "${name}" "${kind}" "${name}" "${DIGEST}"
    if [[ -n "${extra}" ]]; then printf '%s\n' "${extra}"; fi
  } > "${RESOLVE_ROOT}/config/catalogue/${name}.yaml"
}

test_resolve_and_ceiling() {
  info "Testing resolve_session_dependencies (kinds, mismatch, ceiling)..."
  _write_resolve_entry innkeeper-mcp mcp "mcp_transport: http"
  _write_resolve_entry dev-postgres service ""

  # Happy path: one mcp + one service resolves, sets globals.
  SANDBOX_ROOT="${RESOLVE_ROOT}" SESSION_PROFILE_MCPS="innkeeper-mcp" \
    SESSION_PROFILE_SERVICES="dev-postgres" \
    resolve_session_dependencies "ses-r1" claude \
    || fail "valid mcp+service should resolve"
  [[ "${SESSION_HAS_DEPS}" == "true" ]] && pass "HAS_DEPS set" || fail "HAS_DEPS not set"
  [[ "${SESSION_HAS_MCPS}" == "true" ]] && pass "HAS_MCPS set" || fail "HAS_MCPS not set"
  [[ "${#SESSION_DEP_NAMES[@]}" -eq 2 ]] && pass "two deps resolved" || fail "expected 2 deps"
  [[ "${SESSION_MCP_SERVER_RECORDS[0]}" == innkeeper-mcp\|http\|http://* ]] \
    && pass "mcp server record built" || fail "mcp record wrong: ${SESSION_MCP_SERVER_RECORDS[0]:-}"

  # Kind mismatch: a service requested under mcps: is rejected.
  if SANDBOX_ROOT="${RESOLVE_ROOT}" SESSION_PROFILE_MCPS="dev-postgres" \
       SESSION_PROFILE_SERVICES="" \
       resolve_session_dependencies "ses-r2" claude 2>/dev/null; then
    fail "service under mcps: should be rejected"
  fi
  pass "kind mismatch rejected"

  # MCP on an unsupported agent fails closed.
  if SANDBOX_ROOT="${RESOLVE_ROOT}" SESSION_PROFILE_MCPS="innkeeper-mcp" \
       SESSION_PROFILE_SERVICES="" \
       resolve_session_dependencies "ses-r3" codex 2>/dev/null; then
    fail "MCP on codex should be rejected"
  fi
  pass "MCP on unsupported agent rejected"

  # Per-session ceiling.
  local i list=""
  for i in 1 2 3 4 5 6 7; do
    _write_resolve_entry "svc${i}" service ""
    list="${list}svc${i},"
  done
  if SANDBOX_ROOT="${RESOLVE_ROOT}" SESSION_MAX_DEPS_PER_SESSION=6 \
       SESSION_PROFILE_MCPS="" SESSION_PROFILE_SERVICES="${list%,}" \
       resolve_session_dependencies "ses-r4" claude 2>/dev/null; then
    fail "7 deps over a ceiling of 6 should be rejected"
  fi
  pass "per-session dependency ceiling enforced"
}

main() {
  test_resource_naming
  test_additive_from_empty
  test_no_owner_dry_run
  test_secret_bundle
  test_service_manifest
  test_no_host_mounts_check
  test_browser_pod_shape
  test_resolve_and_ceiling
  echo "All dependency-manifest tests passed."
}
main "$@"
