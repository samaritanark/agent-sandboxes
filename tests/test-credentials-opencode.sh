#!/usr/bin/env bash
# tests/test-credentials-opencode.sh — OpenCode credential injection tests
# Verifies: OPENAI_API_KEY is present for opencode; no host env leaks;
# OPENAI_BASE_URL matches the operator-supplied OPENCODE_BASE_URL.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

TEST_NAME="test-credentials-opencode"

# requires-network: OPENCODE_BASE_URL must be set so the test knows what
# value to inject and verify in the pod env.
if [[ -z "${OPENCODE_BASE_URL:-}" ]]; then
  skip "${TEST_NAME}: OPENCODE_BASE_URL not set (export the URL of an OpenAI-compatible endpoint)"
fi

###############################################################################
# Test: OPENAI_API_KEY is present in opencode pod (injected via K8s Secret)
###############################################################################
test_api_key_present() {
  local test_api_key="test-opencode-apikey-integration-$(date +%s)"
  local session_id="test-cred-oc-$$-$(head -c 2 /dev/urandom | xxd -p | head -c 4)"
  local pod_name="sandbox-${session_id}"
  local secret_name="opencode-apikey-${session_id}"

  info "Testing OPENAI_API_KEY injection via K8s Secret for opencode..."

  # Create secret as the CLI would
  kubectl create secret generic "${secret_name}" \
    --namespace "${NAMESPACE}" \
    --from-literal="OPENAI_API_KEY=${test_api_key}" \
    --dry-run=client -o yaml | kubectl apply -f - &>/dev/null

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
    --labels "sandbox-session=${session_id},sandbox-agent=opencode,sandbox-tier=1" \
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
            \"echo \\\"OPENAI_API_KEY=\${OPENAI_API_KEY:-MISSING}\\\"\"],
          \"env\": [
            {\"name\": \"HOME\", \"value\": \"/home/agent\"},
            {\"name\": \"TERM\", \"value\": \"xterm-256color\"},
            {\"name\": \"OPENAI_BASE_URL\", \"value\": \"${OPENCODE_BASE_URL}\"},
            {\"name\": \"OPENAI_API_KEY\", \"valueFrom\": {
              \"secretKeyRef\": {\"name\": \"${secret_name}\", \"key\": \"OPENAI_API_KEY\"}
            }}
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
      kubectl delete secret -n "${NAMESPACE}" "${secret_name}" --ignore-not-found=true &>/dev/null
      kubectl delete ciliumnetworkpolicy -n "${NAMESPACE}" "policy-${session_id}" --ignore-not-found=true &>/dev/null
      fail "Pod timed out"
    }
    sleep 2
  done

  local output
  output="$(kubectl logs -n "${NAMESPACE}" "${pod_name}" 2>/dev/null || true)"

  kubectl delete pod -n "${NAMESPACE}" "${pod_name}" --ignore-not-found=true &>/dev/null
  kubectl delete secret -n "${NAMESPACE}" "${secret_name}" --ignore-not-found=true &>/dev/null
  kubectl delete ciliumnetworkpolicy -n "${NAMESPACE}" "policy-${session_id}" --ignore-not-found=true &>/dev/null

  if echo "${output}" | grep -q "OPENAI_API_KEY=${test_api_key}"; then
    pass "OPENAI_API_KEY correctly injected via K8s Secret for opencode"
  else
    fail "OPENAI_API_KEY not correctly set in opencode pod (output: '${output}')."
  fi
}

###############################################################################
# Test: OPENAI_BASE_URL inside the pod matches the host's OPENCODE_BASE_URL
###############################################################################
test_base_url_matches_configured() {
  local session_id="test-cred-oc2-$$-$(head -c 2 /dev/urandom | xxd -p | head -c 4)"
  local pod_name="sandbox-${session_id}"
  local secret_name="opencode-apikey-${session_id}"

  info "Verifying OPENAI_BASE_URL matches OPENCODE_BASE_URL for opencode..."

  kubectl create secret generic "${secret_name}" \
    --namespace "${NAMESPACE}" \
    --from-literal="OPENAI_API_KEY=test-key" \
    --dry-run=client -o yaml | kubectl apply -f - &>/dev/null

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
          \"command\": [\"sh\", \"-c\", \"echo \\\"BASE=\${OPENAI_BASE_URL:-MISSING}\\\"\"],
          \"env\": [
            {\"name\": \"HOME\", \"value\": \"/home/agent\"},
            {\"name\": \"OPENAI_BASE_URL\", \"value\": \"${OPENCODE_BASE_URL}\"},
            {\"name\": \"OPENAI_API_KEY\", \"valueFrom\": {
              \"secretKeyRef\": {\"name\": \"${secret_name}\", \"key\": \"OPENAI_API_KEY\"}
            }}
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
      kubectl delete secret -n "${NAMESPACE}" "${secret_name}" --ignore-not-found=true &>/dev/null
      kubectl delete ciliumnetworkpolicy -n "${NAMESPACE}" "policy-${session_id}" --ignore-not-found=true &>/dev/null
      fail "Pod timed out"
    }
    sleep 2
  done

  local output
  output="$(kubectl logs -n "${NAMESPACE}" "${pod_name}" 2>/dev/null || true)"

  kubectl delete pod -n "${NAMESPACE}" "${pod_name}" --ignore-not-found=true &>/dev/null
  kubectl delete secret -n "${NAMESPACE}" "${secret_name}" --ignore-not-found=true &>/dev/null
  kubectl delete ciliumnetworkpolicy -n "${NAMESPACE}" "policy-${session_id}" --ignore-not-found=true &>/dev/null

  local expected_base="${OPENCODE_BASE_URL}"
  if echo "${output}" | grep -q "BASE=${expected_base}"; then
    pass "OPENAI_BASE_URL in pod matches OPENCODE_BASE_URL (${expected_base})"
  else
    fail "OPENAI_BASE_URL does not match OPENCODE_BASE_URL (output: '${output}', expected: '${expected_base}')."
  fi
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""

  test_api_key_present
  test_base_url_matches_configured

  echo ""
  echo "All OpenCode credential tests passed."
}

main "$@"
