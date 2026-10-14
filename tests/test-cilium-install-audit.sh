#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-cilium-install-audit.sh — the Cilium install must not weaken the
# egress-audit path. Cluster-free.
#
# The egress audit reads the Cilium AGENT's Hubble directly
# (`kubectl exec ds/cilium -- hubble observe`, lib/cluster.sh) — hubble-relay is
# not on the path. Two properties keep that channel alive and must hold on BOTH
# install paths (setup/common.sh for Linux, lima/sandbox-vm.yaml.tmpl for macOS):
#
#   1. Agent-side Hubble stays on: `hubble.enabled=true` (and relay off, which
#      is the point of PR #103 — relay carries no audit traffic here).
#   2. The Cilium agent installs BestEffort (`resources: {}`), so what protects
#      it from an agent-triggered memory/disk squeeze is the chart's
#      `system-node-critical` priority class (kubelet won't evict a critical pod;
#      oom_score_adj -997). A `--set priorityClassName=…` override or
#      `enableCriticalPriorityClass=false` would silently demote it to an
#      ordinary BestEffort pod — the first eviction/OOM victim. Neither install
#      path may set those. (See SKILL.md invariant 3.)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-cilium-install-audit"

# Extract the Cilium helm invocation from a file: the lines from the one that
# installs `cilium/cilium` through the end of its backslash-continued command.
_cilium_helm_block() {
  awk '
    /helm .*cilium\/cilium/ { inblk=1 }
    inblk { print }
    inblk && !/\\[[:space:]]*$/ { inblk=0 }
  ' "$1"
}

assert_audit_install() {
  local label="$1" file="$2" block
  block="$(_cilium_helm_block "${SANDBOX_ROOT}/${file}")"
  [[ -n "${block}" ]] || fail "${label}: no cilium/cilium helm invocation found in ${file}"

  case "${block}" in
    *"hubble.enabled=true"*) pass "${label}: agent-side Hubble stays enabled" ;;
    *) fail "${label}: ${file} does not set hubble.enabled=true (audit source)" ;;
  esac
  case "${block}" in
    *"hubble.relay.enabled=false"*) pass "${label}: relay disabled (not on audit path)" ;;
    *) fail "${label}: ${file} does not set hubble.relay.enabled=false" ;;
  esac
  # The agent's protection is its critical priority class — must not be demoted.
  case "${block}" in
    *priorityClassName*) fail "${label}: ${file} overrides priorityClassName on the Cilium install — demotes the agent below system-node-critical" ;;
    *) pass "${label}: no priorityClassName override" ;;
  esac
  case "${block}" in
    *enableCriticalPriorityClass=false*) fail "${label}: ${file} sets enableCriticalPriorityClass=false — strips the agent's eviction/OOM protection" ;;
    *) pass "${label}: critical priority class not disabled" ;;
  esac
}

main() {
  info "Running ${TEST_NAME} tests..."
  assert_audit_install "linux install"  setup/common.sh
  assert_audit_install "macos install"  lima/sandbox-vm.yaml.tmpl
  echo "All ${TEST_NAME} tests passed."
}

main "$@"
