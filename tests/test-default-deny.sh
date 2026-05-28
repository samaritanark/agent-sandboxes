#!/usr/bin/env bash
# tests/test-default-deny.sh — Verify default deny for unlabeled pods
# An unlabeled pod (no sandbox-session label) should have zero network access
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

TEST_NAME="test-default-deny"

fail() { echo "FAIL: $*" >&2; exit 1; }

###############################################################################
# Test: Unlabeled pod has no network access
###############################################################################
test_unlabeled_pod_denied() {
  local pod_name="test-default-deny-$$"
  info "Launching unlabeled pod (no sandbox-session label)..."

  kubectl delete pod -n "${NAMESPACE}" "${pod_name}" --ignore-not-found=true &>/dev/null

  # No sandbox-session label, no network policy — should be default-deny
  kubectl run "${pod_name}" \
    --namespace "${NAMESPACE}" \
    --image "sandbox:base" \
    --image-pull-policy IfNotPresent \
    --restart Never \
    --overrides "{
      \"spec\": {
        \"runtimeClassName\": \"gvisor\",
        \"serviceAccountName\": \"sandbox-agent\",
        \"automountServiceAccountToken\": false,
        \"securityContext\": {\"runAsUser\": 1000, \"runAsGroup\": 1000, \"runAsNonRoot\": true},
        \"containers\": [{
          \"name\": \"agent\",
          \"image\": \"sandbox:base\",
          \"command\": [\"sh\", \"-c\",
            \"curl -sf --max-time 8 --connect-timeout 5 https://example.com/ > /dev/null 2>&1; echo \$?\"],
          \"securityContext\": {\"allowPrivilegeEscalation\": false, \"capabilities\": {\"drop\": [\"ALL\"]}}
        }]
      }
    }" 2>/dev/null

  local retries=30
  local i=0
  until kubectl get pod -n "${NAMESPACE}" "${pod_name}" \
        -o jsonpath='{.status.phase}' 2>/dev/null | grep -qE '^(Succeeded|Failed)$'; do
    (( i++ )) || true
    [[ "${i}" -ge "${retries}" ]] && {
      kubectl delete pod -n "${NAMESPACE}" "${pod_name}" --ignore-not-found=true &>/dev/null
      fail "Unlabeled pod did not complete in time"
    }
    sleep 2
  done

  local exit_code
  exit_code="$(kubectl logs -n "${NAMESPACE}" "${pod_name}" 2>/dev/null | tail -1 | tr -d '[:space:]')"

  kubectl delete pod -n "${NAMESPACE}" "${pod_name}" --ignore-not-found=true &>/dev/null

  # curl should fail (non-zero) because no egress is allowed
  if [[ "${exit_code}" != "0" ]]; then
    pass "Unlabeled pod: example.com blocked by default-deny (exit: ${exit_code})"
  else
    fail "Unlabeled pod could reach example.com! Default-deny is NOT working. Check Cilium policyEnforcementMode=always."
  fi
}

###############################################################################
# Test: Verify Cilium is in 'always' enforcement mode
###############################################################################
test_cilium_enforcement_mode() {
  info "Checking Cilium policy enforcement mode..."

  local mode
  mode="$(kubectl get configmap -n kube-system cilium-config \
    -o jsonpath='{.data.policy-enforcement-mode}' 2>/dev/null || echo "unknown")"

  if [[ "${mode}" == "always" ]]; then
    pass "Cilium enforcement mode: always"
  else
    fail "Cilium enforcement mode is '${mode}' (expected 'always'). See run 'sandbox setup'."
  fi
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""

  test_cilium_enforcement_mode
  test_unlabeled_pod_denied

  echo ""
  echo "Default-deny tests passed."
}

main "$@"
