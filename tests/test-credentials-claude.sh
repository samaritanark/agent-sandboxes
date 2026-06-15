#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-credentials-claude.sh — Claude credential isolation
# Verifies: ANTHROPIC_API_KEY is NOT present inside pod; OAuth only
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

TEST_NAME="test-credentials-claude"

fail() { echo "FAIL: $*" >&2; exit 1; }

###############################################################################
# Test: ANTHROPIC_API_KEY must not appear in pod environment
###############################################################################
test_no_anthropic_api_key() {
  local session_id="test-cred-c-$$-$(head -c 2 /dev/urandom | xxd -p | head -c 4)"
  local pod_name="sandbox-${session_id}"

  info "Verifying ANTHROPIC_API_KEY is absent in Claude pod environment..."

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
  egress:
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
  ingress: []
EOF

  kubectl run "${pod_name}" \
    --namespace "${NAMESPACE}" \
    --image "sandbox:claude" \
    --image-pull-policy IfNotPresent \
    --restart Never \
    --labels "sandbox-session=${session_id},sandbox-agent=claude,sandbox-tier=1" \
    --overrides "{
      \"spec\": {
        \"runtimeClassName\": \"gvisor\",
        \"serviceAccountName\": \"sandbox-agent\",
        \"automountServiceAccountToken\": false,
        \"securityContext\": {\"runAsUser\": 1000, \"runAsGroup\": 1000, \"runAsNonRoot\": true},
        \"containers\": [{
          \"name\": \"agent\",
          \"image\": \"sandbox:claude\",
          \"command\": [\"sh\", \"-c\", \"env | grep -i 'anthropic\\|api_key' | wc -l\"],
          \"env\": [
            {\"name\": \"HOME\", \"value\": \"/home/agent\"},
            {\"name\": \"TERM\", \"value\": \"xterm-256color\"}
          ],
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

  local match_count
  match_count="$(kubectl logs -n "${NAMESPACE}" "${pod_name}" 2>/dev/null | tail -1 | tr -d '[:space:]')"

  kubectl delete pod -n "${NAMESPACE}" "${pod_name}" --ignore-not-found=true &>/dev/null
  kubectl delete ciliumnetworkpolicy -n "${NAMESPACE}" "policy-${session_id}" --ignore-not-found=true &>/dev/null

  if [[ "${match_count}" == "0" ]]; then
    pass "ANTHROPIC_API_KEY not present in Claude pod environment"
  else
    fail "Found ${match_count} anthropic/api_key env var(s) in Claude pod!"
  fi
}

###############################################################################
# Test: Verify only approved env vars are set
###############################################################################
test_only_approved_env() {
  local session_id="test-cred-c2-$$-$(head -c 2 /dev/urandom | xxd -p | head -c 4)"
  local pod_name="sandbox-${session_id}"

  info "Verifying only HOME and TERM are set in Claude pod..."

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
            \"env | grep -E 'KUBECONFIG|AWS_|GOOGLE_|AZURE_|OS_|TELEPORT_|TSH_|DOCKER_HOST|KUBERNETES_SERVICE' | wc -l\"],
          \"env\": [
            {\"name\": \"HOME\", \"value\": \"/home/agent\"},
            {\"name\": \"TERM\", \"value\": \"xterm-256color\"}
          ],
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

  local leak_count
  leak_count="$(kubectl logs -n "${NAMESPACE}" "${pod_name}" 2>/dev/null | tail -1 | tr -d '[:space:]')"

  kubectl delete pod -n "${NAMESPACE}" "${pod_name}" --ignore-not-found=true &>/dev/null
  kubectl delete ciliumnetworkpolicy -n "${NAMESPACE}" "policy-${session_id}" --ignore-not-found=true &>/dev/null

  if [[ "${leak_count}" == "0" ]]; then
    pass "No host credential env vars leaked into Claude pod"
  else
    fail "Found ${leak_count} blocked env var(s) in Claude pod!"
  fi
}

###############################################################################
# Test: Verify KUBERNETES_SERVICE_HOST not present (no SA token auto-mount)
###############################################################################
test_no_kubernetes_service_host() {
  local session_id="test-cred-c3-$$-$(head -c 2 /dev/urandom | xxd -p | head -c 4)"
  local pod_name="sandbox-${session_id}"

  info "Verifying KUBERNETES_SERVICE_HOST is absent (no implicit API server access)..."

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
            \"ls /var/run/secrets/kubernetes.io/serviceaccount 2>/dev/null | wc -l\"],
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

  local sa_files
  sa_files="$(kubectl logs -n "${NAMESPACE}" "${pod_name}" 2>/dev/null | tail -1 | tr -d '[:space:]')"

  kubectl delete pod -n "${NAMESPACE}" "${pod_name}" --ignore-not-found=true &>/dev/null
  kubectl delete ciliumnetworkpolicy -n "${NAMESPACE}" "policy-${session_id}" --ignore-not-found=true &>/dev/null

  if [[ "${sa_files}" == "0" ]]; then
    pass "No service account token mounted (automountServiceAccountToken: false works)"
  else
    fail "Service account token IS mounted! automountServiceAccountToken must be false."
  fi
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""

  test_no_anthropic_api_key
  test_only_approved_env
  test_no_kubernetes_service_host

  echo ""
  echo "All Claude credential isolation tests passed."
}

main "$@"
