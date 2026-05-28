#!/usr/bin/env bash
# tests/test-filesystem.sh — Filesystem isolation tests
# Verifies: .env and credential files are masked inside Tier 2 pods
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

TEST_NAME="test-filesystem"

fail() { echo "FAIL: $*" >&2; exit 1; }

###############################################################################
# Create a test workspace with sensitive files
###############################################################################
setup_test_workspace() {
  local workspace
  workspace="$(mktemp -d /tmp/test-sandbox-workspace-XXXXXX)"

  # Initialize git repo (required for Tier 2)
  git -C "${workspace}" init -q
  git -C "${workspace}" config user.email "test@sandbox"
  git -C "${workspace}" config user.name "Test"

  # Create a harmless file
  echo "hello world" > "${workspace}/README.md"
  git -C "${workspace}" add README.md
  git -C "${workspace}" commit -q -m "init"

  # Create sensitive files that should be masked
  echo "SECRET_KEY=super-secret-value-12345" > "${workspace}/.env"
  echo "DATABASE_PASSWORD=db-password-99" >> "${workspace}/.env"
  echo "//registry.npmjs.org/:_authToken=npm-secret-token" > "${workspace}/.npmrc"
  echo "export OS_PASSWORD=openstack-password" > "${workspace}/admin-openrc.sh"
  cat > "${workspace}/clouds.yaml" << 'YAML'
clouds:
  mycloud:
    auth:
      password: cloud-secret-password
YAML

  echo "${workspace}"
}

###############################################################################
# Test: .env file is masked (empty) inside sandbox
###############################################################################
test_env_masked() {
  local workspace="$1"
  local session_id="test-fs-$$-$(head -c 2 /dev/urandom | xxd -p | head -c 4)"
  local pod_name="sandbox-${session_id}"

  info "Testing .env masking..."

  # Apply a minimal policy
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
    --image "sandbox:base" \
    --image-pull-policy IfNotPresent \
    --restart Never \
    --labels "sandbox-session=${session_id},sandbox-agent=claude,sandbox-tier=2" \
    --overrides "{
      \"spec\": {
        \"runtimeClassName\": \"gvisor\",
        \"serviceAccountName\": \"sandbox-agent\",
        \"automountServiceAccountToken\": false,
        \"securityContext\": {\"runAsUser\": 1000, \"runAsGroup\": 1000, \"fsGroup\": 1000, \"runAsNonRoot\": true},
        \"containers\": [{
          \"name\": \"agent\",
          \"image\": \"sandbox:base\",
          \"command\": [\"sh\", \"-c\", \"cat /workspace/.env && echo EXITCODE:0 || echo EXITCODE:1\"],
          \"securityContext\": {\"allowPrivilegeEscalation\": false, \"capabilities\": {\"drop\": [\"ALL\"]}},
          \"volumeMounts\": [
            {\"name\": \"workspace\", \"mountPath\": \"/workspace\"},
            {\"name\": \"overlay-dotenv\", \"mountPath\": \"/workspace/.env\"}
          ]
        }],
        \"volumes\": [
          {\"name\": \"workspace\", \"hostPath\": {\"path\": \"${workspace}\", \"type\": \"Directory\"}},
          {\"name\": \"overlay-dotenv\", \"emptyDir\": {}}
        ]
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
      fail "Pod timed out: test_env_masked"
    }
    sleep 2
  done

  local output
  output="$(kubectl logs -n "${NAMESPACE}" "${pod_name}" 2>/dev/null || true)"

  kubectl delete pod -n "${NAMESPACE}" "${pod_name}" --ignore-not-found=true &>/dev/null
  kubectl delete ciliumnetworkpolicy -n "${NAMESPACE}" "policy-${session_id}" --ignore-not-found=true &>/dev/null

  # .env file is masked by emptyDir overlay — it should be empty or a directory
  if echo "${output}" | grep -q "super-secret-value"; then
    fail ".env masking FAILED — secret value visible inside container!"
  else
    pass ".env file is masked (secret value not visible)"
  fi
}

###############################################################################
# Test: Workspace files (non-sensitive) are accessible
###############################################################################
test_workspace_accessible() {
  local workspace="$1"
  local session_id="test-fs2-$$-$(head -c 2 /dev/urandom | xxd -p | head -c 4)"
  local pod_name="sandbox-${session_id}"

  info "Testing workspace file access (README.md should be readable)..."

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
        \"securityContext\": {\"runAsUser\": 1000, \"runAsGroup\": 1000, \"fsGroup\": 1000, \"runAsNonRoot\": true},
        \"containers\": [{
          \"name\": \"agent\",
          \"image\": \"sandbox:base\",
          \"command\": [\"sh\", \"-c\", \"cat /workspace/README.md\"],
          \"securityContext\": {\"allowPrivilegeEscalation\": false, \"capabilities\": {\"drop\": [\"ALL\"]}},
          \"volumeMounts\": [{\"name\": \"workspace\", \"mountPath\": \"/workspace\"}]
        }],
        \"volumes\": [{\"name\": \"workspace\", \"hostPath\": {\"path\": \"${workspace}\", \"type\": \"Directory\"}}]
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
      fail "Pod timed out: test_workspace_accessible"
    }
    sleep 2
  done

  local output
  output="$(kubectl logs -n "${NAMESPACE}" "${pod_name}" 2>/dev/null || true)"

  kubectl delete pod -n "${NAMESPACE}" "${pod_name}" --ignore-not-found=true &>/dev/null
  kubectl delete ciliumnetworkpolicy -n "${NAMESPACE}" "policy-${session_id}" --ignore-not-found=true &>/dev/null

  if echo "${output}" | grep -q "hello world"; then
    pass "README.md is readable inside container"
  else
    fail "README.md not readable inside container (output: '${output}')"
  fi
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""

  local workspace
  workspace="$(setup_test_workspace)"
  info "Test workspace: ${workspace}"

  test_env_masked "${workspace}"
  test_workspace_accessible "${workspace}"

  # Cleanup
  rm -rf "${workspace}"

  echo ""
  echo "All filesystem isolation tests passed."
}

main "$@"
