#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-agent-home.sh — lib/platform.sh agent-home path resolution.
#
# The pod's agent-home hostPath must differ by platform: on macOS it is a
# VM-local ext4 path (NOT the 9p-shared Mac home, where the gVisor gofer
# presents container-created files as root-owned and breaks credential
# persistence — login reports "Not logged in"); on Linux/WSL the operator-home
# path is mounted directly. This locks that split in. Cluster-free.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-agent-home"

fail() { echo "FAIL: $*" >&2; exit 1; }

source "${SANDBOX_ROOT}/lib/platform.sh"

eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    pass "${label}"
  else
    fail "${label}: expected '${expected}', got '${actual}'"
  fi
}

# Override detect_platform so the resolver can be exercised for both platforms
# on any test host. is_macos/is_linux read through detect_platform.
_set_platform() { eval "detect_platform() { echo '$1'; }"; }

test_macos_uses_vm_local() {
  info "Testing macOS resolves agent-home to the VM-local path..."
  _set_platform macos
  eq "claude → VM-local" "/var/lib/sandbox/agent-home/claude" "$(resolve_agent_home claude)"
  eq "codex  → VM-local" "/var/lib/sandbox/agent-home/codex"  "$(resolve_agent_home codex)"
}

test_linux_uses_host_home() {
  info "Testing Linux resolves agent-home to the operator-home path..."
  _set_platform linux
  eq "claude → host home" "${HOME}/.sandbox/agent-home/claude" "$(resolve_agent_home claude)"
}

test_host_agent_home_is_platform_independent() {
  info "Testing host_agent_home is always the operator home (staging/backup)..."
  _set_platform macos
  eq "macOS staging stays on host" "${HOME}/.sandbox/agent-home/claude" "$(host_agent_home claude)"
  _set_platform linux
  eq "linux staging stays on host" "${HOME}/.sandbox/agent-home/claude" "$(host_agent_home claude)"
}

test_vm_base_is_overridable() {
  info "Testing SANDBOX_VM_AGENT_HOME_BASE override is honored..."
  _set_platform macos
  ( SANDBOX_VM_AGENT_HOME_BASE="/data/agent-home"
    source "${SANDBOX_ROOT}/lib/platform.sh"
    _set_platform macos
    eq "override applies" "/data/agent-home/claude" "$(resolve_agent_home claude)" )
}

main() {
  info "Running ${TEST_NAME} tests..."
  test_macos_uses_vm_local
  test_linux_uses_host_home
  test_host_agent_home_is_platform_independent
  test_vm_base_is_overridable
  echo "All ${TEST_NAME} tests passed."
}

main "$@"
