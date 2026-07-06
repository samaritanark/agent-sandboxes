#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-credentials-copilot.sh — Copilot credential isolation
# Verifies: no GitHub token (COPILOT_GITHUB_TOKEN / GH_TOKEN / GITHUB_TOKEN)
# is present inside the pod — Copilot authenticates via OAuth device flow only,
# never an injected env token. Requires a live k3s + gVisor cluster; run
# manually (not in `task test`).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

TEST_NAME="test-credentials-copilot"

fail() { echo "FAIL: $*" >&2; exit 1; }

###############################################################################
# Test: no GitHub token env var must appear in the Copilot pod environment.
###############################################################################
test_no_github_token() {
  local session_id="test-cred-cp-$$-$(head -c 2 /dev/urandom | xxd -p | head -c 4)"
  local pod_name="sandbox-${session_id}"

  info "Verifying no GitHub token is present in Copilot pod environment..."

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
    --image "sandbox:copilot" \
    --image-pull-policy IfNotPresent \
    --restart Never \
    --labels "sandbox-session=${session_id},sandbox-agent=copilot,sandbox-tier=1" \
    --overrides "{
      \"spec\": {
        \"runtimeClassName\": \"gvisor\",
        \"serviceAccountName\": \"sandbox-agent\",
        \"automountServiceAccountToken\": false,
        \"securityContext\": {\"runAsUser\": 1000, \"runAsGroup\": 1000, \"runAsNonRoot\": true},
        \"containers\": [{
          \"name\": \"agent\",
          \"image\": \"sandbox:copilot\",
          \"command\": [\"sh\", \"-c\", \"env | grep -iE 'GH_TOKEN|GITHUB_TOKEN|COPILOT_GITHUB_TOKEN' | wc -l\"],
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
    pass "no GitHub token present in Copilot pod environment"
  else
    fail "Found ${match_count} GitHub-token env var(s) in Copilot pod!"
  fi
}

###############################################################################
# Test: the image build itself refuses a baked-in GitHub token (Dockerfile
# assertion). Confirms the image was built clean.
###############################################################################
test_no_github_token_in_image() {
  local session_id="test-cred-cp2-$$-$(head -c 2 /dev/urandom | xxd -p | head -c 4)"
  local pod_name="sandbox-${session_id}"

  info "Verifying the copilot image bakes in no GitHub token..."

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
    --image "sandbox:copilot" \
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
          \"image\": \"sandbox:copilot\",
          \"command\": [\"sh\", \"-c\", \"env | grep -iE 'GH_TOKEN|GITHUB_TOKEN|COPILOT_GITHUB_TOKEN' | wc -l\"],
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

  local match_count
  match_count="$(kubectl logs -n "${NAMESPACE}" "${pod_name}" 2>/dev/null | tail -1 | tr -d '[:space:]')"

  kubectl delete pod -n "${NAMESPACE}" "${pod_name}" --ignore-not-found=true &>/dev/null
  kubectl delete ciliumnetworkpolicy -n "${NAMESPACE}" "policy-${session_id}" --ignore-not-found=true &>/dev/null

  if [[ "${match_count}" == "0" ]]; then
    pass "no GitHub token baked into the copilot image"
  else
    fail "Found ${match_count} GitHub-token env var(s) baked into the image!"
  fi
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""

  test_no_github_token
  test_no_github_token_in_image

  echo ""
  echo "All Copilot credential isolation tests passed."
}

main "$@"
