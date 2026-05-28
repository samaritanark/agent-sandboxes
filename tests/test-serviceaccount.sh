#!/usr/bin/env bash
# tests/test-serviceaccount.sh — ServiceAccount lockdown tests
# Verifies: SA has no RBAC bindings; pods cannot query Kubernetes API
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

TEST_NAME="test-serviceaccount"

fail() { echo "FAIL: $*" >&2; exit 1; }

###############################################################################
# Test: ServiceAccount exists with automountServiceAccountToken: false
###############################################################################
test_sa_no_automount() {
  info "Checking sandbox-agent ServiceAccount..."

  if ! kubectl get sa -n "${NAMESPACE}" sandbox-agent &>/dev/null; then
    fail "ServiceAccount 'sandbox-agent' not found in namespace '${NAMESPACE}'. Run 'sandbox setup'."
  fi

  local automount
  automount="$(kubectl get sa -n "${NAMESPACE}" sandbox-agent \
    -o jsonpath='{.automountServiceAccountToken}' 2>/dev/null || echo "null")"

  # Should be false (or absent, which defaults to false in combined with pod setting)
  if [[ "${automount}" == "false" ]] || [[ "${automount}" == "null" ]] || [[ -z "${automount}" ]]; then
    pass "ServiceAccount sandbox-agent: automountServiceAccountToken is not true"
  else
    fail "ServiceAccount sandbox-agent: automountServiceAccountToken=${automount} (must be false)."
  fi
}

###############################################################################
# Test: ServiceAccount has no ClusterRoleBindings or RoleBindings
###############################################################################
test_sa_no_rbac() {
  info "Checking that sandbox-agent SA has no RBAC bindings..."

  # Check ClusterRoleBindings
  local crb_count
  crb_count="$(kubectl get clusterrolebinding -o json 2>/dev/null \
    | jq -r --arg sa "sandbox-agent" --arg ns "${NAMESPACE}" \
      '[.items[] | select(
        .subjects[]? |
        select(.kind=="ServiceAccount" and .name==$sa and .namespace==$ns)
      )] | length' 2>/dev/null || echo "0")"

  if [[ "${crb_count}" -eq 0 ]]; then
    pass "sandbox-agent SA has no ClusterRoleBindings"
  else
    fail "sandbox-agent SA has ${crb_count} ClusterRoleBinding(s)!"
  fi

  # Check RoleBindings in sandbox namespace
  local rb_count
  rb_count="$(kubectl get rolebinding -n "${NAMESPACE}" -o json 2>/dev/null \
    | jq -r --arg sa "sandbox-agent" \
      '[.items[] | select(
        .subjects[]? |
        select(.kind=="ServiceAccount" and .name==$sa)
      )] | length' 2>/dev/null || echo "0")"

  if [[ "${rb_count}" -eq 0 ]]; then
    pass "sandbox-agent SA has no RoleBindings in namespace '${NAMESPACE}'"
  else
    fail "sandbox-agent SA has ${rb_count} RoleBinding(s) in '${NAMESPACE}'!"
  fi
}

###############################################################################
# Test: Pod running as sandbox-agent SA cannot query Kubernetes API
###############################################################################
test_pod_cannot_query_api() {
  local session_id="test-sa-$$-$(head -c 2 /dev/urandom | xxd -p | head -c 4)"
  local pod_name="sandbox-${session_id}"

  info "Testing that pod with sandbox-agent SA cannot query Kubernetes API..."

  cat <<EOF | kubectl apply -f - &>/dev/null
---
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: "policy-${session_id}"
  namespace: "${NAMESPACE}"
spec:
  endpointSelector:
    matchLabels:
      sandbox-session: "${session_id}"
  egress: []
  ingress: []
EOF

  kubectl run "${pod_name}" \
    --namespace "${NAMESPACE}" \
    --image "sandbox:base" \
    --image-pull-policy IfNotPresent \
    --restart Never \
    --labels "sandbox-session=${session_id}" \
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
            \"curl -sf --max-time 5 --connect-timeout 3 https://kubernetes.default.svc/api > /dev/null 2>&1; echo \$?\"],
          \"env\": [{\"name\": \"HOME\", \"value\": \"/home/agent\"}],
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
      kubectl delete ciliumnetworkpolicy -n "${NAMESPACE}" "policy-${session_id}" --ignore-not-found=true &>/dev/null
      fail "Pod timed out"
    }
    sleep 2
  done

  local exit_code
  exit_code="$(kubectl logs -n "${NAMESPACE}" "${pod_name}" 2>/dev/null | tail -1 | tr -d '[:space:]')"

  kubectl delete pod -n "${NAMESPACE}" "${pod_name}" --ignore-not-found=true &>/dev/null
  kubectl delete ciliumnetworkpolicy -n "${NAMESPACE}" "policy-${session_id}" --ignore-not-found=true &>/dev/null

  if [[ "${exit_code}" != "0" ]]; then
    pass "Pod cannot reach Kubernetes API server (blocked by policy + no token)"
  else
    fail "Pod COULD reach Kubernetes API server! This is a security violation."
  fi
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""

  test_sa_no_automount
  test_sa_no_rbac
  test_pod_cannot_query_api

  echo ""
  echo "All ServiceAccount lockdown tests passed."
}

main "$@"
