#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-opencode-tier1.sh — OpenCode Tier 1 network access tests
# Verifies: the configured OpenCode endpoint is reachable, api.openai.com /
# api.anthropic.com / github.com / example.com are blocked.
# OpenAI-compatible host (taken from OPENCODE_BASE_URL).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

TEST_NAME="test-opencode-tier1"

# requires-network: depends on a reachable OPENCODE_BASE_URL host.
if [[ -z "${OPENCODE_BASE_URL:-}" ]]; then
  skip "${TEST_NAME}: OPENCODE_BASE_URL not set (export the URL of an OpenAI-compatible endpoint)"
fi

# Extract hostname from OPENCODE_BASE_URL for both the Cilium matchName and
# the curl target. Strips scheme, path, and port.
OPENCODE_HOST="${OPENCODE_BASE_URL#*://}"
OPENCODE_HOST="${OPENCODE_HOST%%/*}"
OPENCODE_HOST="${OPENCODE_HOST%%:*}"

run_network_test() {
  local test_label="$1"
  local domain="$2"
  local expected_reachable="$3"

  local session_id="test-oc1-$$-$(head -c 2 /dev/urandom | xxd -p | head -c 4)"
  local pod_name="sandbox-${session_id}"

  info "Testing: ${test_label} — ${domain}"

  # OpenCode Tier 1 policy — egress restricted to OPENCODE_HOST only.
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
              - matchName: "${OPENCODE_HOST}"
    - toFQDNs:
        - matchName: "${OPENCODE_HOST}"
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

  run_network_test "opencode-tier1-endpoint"          "${OPENCODE_HOST}"                  "yes"
  # Skip a domain if it happens to be the endpoint itself (e.g. operator set
  # OPENCODE_BASE_URL=https://api.openai.com/v1).
  for d in api.openai.com api.anthropic.com github.com example.com; do
    if [[ "${d}" == "${OPENCODE_HOST}" ]]; then
      info "skipping blocked-domain check for ${d} (it is the configured endpoint)"
      continue
    fi
    run_network_test "opencode-tier1-${d}-blocked"    "${d}"                              "no"
  done

  echo ""
  echo "All OpenCode Tier 1 network tests passed."
}

main "$@"
