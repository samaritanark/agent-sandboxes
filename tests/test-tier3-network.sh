#!/usr/bin/env bash
# tests/test-tier3-network.sh — Tier 3 dynamic endpoint network tests
# Verifies: dynamic --infra-endpoint is reachable, other endpoints blocked
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

TEST_NAME="test-tier3-network"

# Dynamic infra endpoint for testing (should be your actual infra endpoint)
TEST_INFRA_ENDPOINT="${TEST_INFRA_ENDPOINT:-infra.example.internal}"

fail() { echo "FAIL: $*" >&2; exit 1; }

run_network_test() {
  local test_label="$1"
  local domain="$2"
  local expected_reachable="$3"

  local session_id="test-t3n-$$-$(head -c 2 /dev/urandom | xxd -p | head -c 4)"
  local pod_name="sandbox-${session_id}"

  info "Testing: ${test_label} — ${domain}"

  # Tier 3 policy: Tier 2 domains + dynamic infra endpoint
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
            - port: "53"
              protocol: TCP
          rules:
            dns:
              - matchPattern: "*"
    - toFQDNs:
        - matchName: "claude.ai"
        - matchName: "api.anthropic.com"
        - matchName: "console.anthropic.com"
        - matchName: "statsig.anthropic.com"
        - matchName: "sentry.io"
        - matchName: "github.com"
        - matchName: "api.github.com"
        - matchName: "pypi.org"
        - matchName: "files.pythonhosted.org"
        - matchName: "registry.npmjs.org"
        - matchName: "registry.terraform.io"
        # Dynamic Tier 3 endpoint
        - matchName: "${TEST_INFRA_ENDPOINT}"
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
  ingress: []
EOF

  kubectl run "${pod_name}" \
    --namespace "${NAMESPACE}" \
    --image "sandbox:base" \
    --image-pull-policy IfNotPresent \
    --restart Never \
    --labels "sandbox-session=${session_id},sandbox-agent=claude,sandbox-tier=3" \
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
            \"curl -sf --max-time 10 --connect-timeout 5 https://${domain}/ > /dev/null 2>&1; echo \$?\"],
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
      fail "Pod timed out: ${test_label}"
    }
    sleep 2
  done

  local exit_code
  exit_code="$(kubectl logs -n "${NAMESPACE}" "${pod_name}" 2>/dev/null | tail -1 | tr -d '[:space:]')"

  kubectl delete pod -n "${NAMESPACE}" "${pod_name}" --ignore-not-found=true &>/dev/null
  kubectl delete ciliumnetworkpolicy -n "${NAMESPACE}" "policy-${session_id}" --ignore-not-found=true &>/dev/null

  if [[ "${expected_reachable}" == "yes" ]]; then
    [[ "${exit_code}" == "0" ]] && pass "${test_label}: ${domain} reachable" \
      || fail "${test_label}: ${domain} should be reachable (exit: ${exit_code})"
  else
    [[ "${exit_code}" != "0" ]] && pass "${test_label}: ${domain} blocked" \
      || fail "${test_label}: ${domain} should be BLOCKED (exit: ${exit_code})"
  fi
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""
  echo "Dynamic infra endpoint: ${TEST_INFRA_ENDPOINT}"
  echo "(Override with: TEST_INFRA_ENDPOINT=<your-endpoint> $0)"
  echo ""

  # Tier 2 domains still work
  run_network_test "tier3-github-ok"     "github.com"              "yes"
  run_network_test "tier3-anthropic-ok"  "api.anthropic.com"       "yes"
  # Dynamic infra endpoint
  run_network_test "tier3-infra-ok"      "${TEST_INFRA_ENDPOINT}"  "yes"
  # Blocked
  run_network_test "tier3-blocked"       "example.com"             "no"

  echo ""
  echo "All Tier 3 network tests passed."
}

main "$@"
