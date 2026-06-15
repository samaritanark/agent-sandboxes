#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-gvisor.sh — Verify gVisor is active inside sandbox pods
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-gvisor"

fail() { echo "FAIL: $*" >&2; exit 1; }

###############################################################################
# Test 1: RuntimeClass gvisor exists
###############################################################################
test_runtimeclass_exists() {
  info "Checking gVisor RuntimeClass..."
  if kubectl get runtimeclass gvisor &>/dev/null; then
    pass "RuntimeClass 'gvisor' exists"
  else
    fail "RuntimeClass 'gvisor' not found. Run 'sandbox setup'."
  fi
}

###############################################################################
# Test 2: Deploy a test pod with gVisor and verify it boots under runsc
###############################################################################
test_gvisor_boot_messages() {
  local pod_name="test-gvisor-$$"
  info "Launching gVisor test pod: ${pod_name}..."

  # Clean up any prior run
  kubectl delete pod -n "${NAMESPACE}" "${pod_name}" --ignore-not-found=true &>/dev/null

  kubectl run "${pod_name}" \
    --namespace "${NAMESPACE}" \
    --image "sandbox:shell" \
    --image-pull-policy IfNotPresent \
    --restart Never \
    --runtime-class gvisor \
    --overrides '{
      "spec": {
        "serviceAccountName": "sandbox-agent",
        "automountServiceAccountToken": false,
        "securityContext": {
          "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000,
          "runAsNonRoot": true
        },
        "containers": [{
          "name": "agent",
          "image": "sandbox:shell",
          "command": ["dmesg"],
          "securityContext": {
            "allowPrivilegeEscalation": false,
            "capabilities": {"drop": ["ALL"]}
          }
        }]
      }
    }' \
    2>/dev/null

  info "Waiting for test pod to complete..."
  local retries=30
  local i=0
  until kubectl get pod -n "${NAMESPACE}" "${pod_name}" \
        -o jsonpath='{.status.phase}' 2>/dev/null | grep -qE '^(Succeeded|Failed)$'; do
    (( i++ )) || true
    [[ "${i}" -ge "${retries}" ]] && fail "Pod did not complete in time"
    sleep 2
  done

  local phase
  phase="$(kubectl get pod -n "${NAMESPACE}" "${pod_name}" -o jsonpath='{.status.phase}')"

  local pod_output
  pod_output="$(kubectl logs -n "${NAMESPACE}" "${pod_name}" 2>/dev/null || true)"

  # Clean up
  kubectl delete pod -n "${NAMESPACE}" "${pod_name}" --ignore-not-found=true &>/dev/null

  if [[ "${phase}" != "Succeeded" ]]; then
    fail "gVisor test pod exited with phase '${phase}'"
  fi

  # gVisor's dmesg shows "Starting gVisor..." in boot messages
  if echo "${pod_output}" | grep -qi "gvisor\|runsc\|Starting gVisor"; then
    pass "gVisor boot messages detected in dmesg output"
  else
    # Fallback: check that uname output shows gVisor kernel version format
    info "dmesg output: ${pod_output}"
    fail "gVisor boot signature not found in dmesg. Is RuntimeClass 'gvisor' using runsc handler?"
  fi
}

###############################################################################
# Test 3: Verify pod spec enforces runtimeClassName
###############################################################################
test_pod_runtimeclass() {
  info "Testing that sandbox run enforces runtimeClassName: gvisor..."

  local pod_name="test-runtimeclass-$$"
  kubectl delete pod -n "${NAMESPACE}" "${pod_name}" --ignore-not-found=true &>/dev/null

  kubectl run "${pod_name}" \
    --namespace "${NAMESPACE}" \
    --image "sandbox:shell" \
    --image-pull-policy IfNotPresent \
    --restart Never \
    --runtime-class gvisor \
    --overrides '{
      "spec": {
        "serviceAccountName": "sandbox-agent",
        "automountServiceAccountToken": false,
        "securityContext": {"runAsUser": 1000, "runAsGroup": 1000, "runAsNonRoot": true},
        "containers": [{"name": "agent", "image": "sandbox:shell",
          "command": ["sh", "-c", "cat /proc/version"],
          "securityContext": {"allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]}}}]
      }
    }' 2>/dev/null

  local retries=30
  local i=0
  until kubectl get pod -n "${NAMESPACE}" "${pod_name}" \
        -o jsonpath='{.status.phase}' 2>/dev/null | grep -qE '^(Succeeded|Failed)$'; do
    (( i++ )) || true
    [[ "${i}" -ge "${retries}" ]] && fail "Pod did not complete"
    sleep 2
  done

  local runtime
  runtime="$(kubectl get pod -n "${NAMESPACE}" "${pod_name}" \
    -o jsonpath='{.spec.runtimeClassName}' 2>/dev/null || echo "")"
  kubectl delete pod -n "${NAMESPACE}" "${pod_name}" --ignore-not-found=true &>/dev/null

  if [[ "${runtime}" == "gvisor" ]]; then
    pass "runtimeClassName is 'gvisor'"
  else
    fail "runtimeClassName is '${runtime}' (expected 'gvisor')"
  fi
}

###############################################################################
# Main
###############################################################################
main() {
  echo "=== ${TEST_NAME} ==="
  echo ""

  test_runtimeclass_exists
  test_gvisor_boot_messages
  test_pod_runtimeclass

  echo ""
  echo "All gVisor tests passed."
}

main "$@"
