#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-codex-tier1.sh — Codex Tier 1 network access tests
# Verifies: api.openai.com reachable, github.com blocked
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

TEST_NAME="test-codex-tier1"

fail() { echo "FAIL: $*" >&2; exit 1; }

run_network_test() {
  local test_label="$1"
  local domain="$2"
  local expected_reachable="$3"

  local session_id="test-cdx1-$$-$(head -c 2 /dev/urandom | xxd -p | head -c 4)"
  local pod_name="sandbox-${session_id}"

  info "Testing: ${test_label} — ${domain}"

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
            # DNS filter mirrors the toFQDNs allowlist (no wildcard) — see
            # lib/policy.sh: a wildcard DNS rule is a tunnelling exfil channel.
            dns:
              - matchName: "api.openai.com"
              - matchName: "auth.openai.com"
              - matchName: "auth0.openai.com"
              - matchName: "chatgpt.com"
              - matchName: "cdn.openai.com"
    - toFQDNs:
        - matchName: "api.openai.com"
        - matchName: "auth.openai.com"
        - matchName: "auth0.openai.com"
        - matchName: "chatgpt.com"
        - matchName: "cdn.openai.com"
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
    --labels "sandbox-session=${session_id},sandbox-agent=codex,sandbox-tier=1" \
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
      || fail "${test_label}: ${domain} should be BLOCKED but was reachable!"
  fi
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""

  run_network_test "codex-tier1-allowed"  "api.openai.com"     "yes"
  run_network_test "codex-tier1-allowed2" "auth.openai.com"    "yes"
  run_network_test "codex-tier1-blocked"  "github.com"         "no"
  run_network_test "codex-tier1-blocked2" "api.anthropic.com"  "no"
  run_network_test "codex-tier1-blocked3" "example.com"        "no"

  echo ""
  echo "All Codex Tier 1 network tests passed."
}

main "$@"
