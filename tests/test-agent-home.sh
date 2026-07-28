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

test_home_dir_is_overridable() {
  info "Testing SANDBOX_AGENT_HOME_BASE / _OVERRIDE relocate host_agent_home (issue #68)..."
  _set_platform linux
  ( SANDBOX_AGENT_HOME_BASE="/srv/ah"
    eq "BASE relocates per-agent subdir" "/srv/ah/claude" "$(host_agent_home claude)" )
  ( SANDBOX_AGENT_HOME_OVERRIDE="/x/y"
    eq "OVERRIDE is used verbatim (agent-agnostic)" "/x/y" "$(host_agent_home claude)" )
  ( SANDBOX_AGENT_HOME_BASE="/srv/ah"; SANDBOX_AGENT_HOME_OVERRIDE="/x/y"
    eq "OVERRIDE wins over BASE" "/x/y" "$(host_agent_home codex)" )
}

test_pod_uid_tracks_operator() {
  info "Testing resolve_pod_uid tracks the operator on Linux, stays 1000 on macOS (issue #71)..."
  _set_platform linux
  ( SANDBOX_POD_UID="1003"; eq "linux honors operator uid"        "1003" "$(resolve_pod_uid)" )
  ( SANDBOX_POD_UID="0";    eq "root clamps to 1000 (nonRoot)"    "1000" "$(resolve_pod_uid)" )
  ( SANDBOX_POD_UID="nope"; eq "non-numeric clamps to 1000"       "1000" "$(resolve_pod_uid)" )
  _set_platform macos
  ( SANDBOX_POD_UID="1003"; eq "macOS ignores operator uid (VM)"  "1000" "$(resolve_pod_uid)" )
}

test_prepare_home_fallback_is_symlink_safe() {
  info "Testing prepare_agent_home's chown fallback skips symlinks and never sets the world bit..."
  command -v stat >/dev/null 2>&1 || skip "stat(1) unavailable"
  (
    source "${SANDBOX_ROOT}/lib/lima.sh"
    _set_platform linux

    ah_tmp="$(mktemp -d)"
    trap 'rm -rf "${ah_tmp}"' EXIT
    ah_staging="${ah_tmp}/ah_staging"; ah_secret="${ah_tmp}/ah_secret-token"
    mkdir -p "${ah_staging}"
    printf 'TOKEN\n' > "${ah_secret}"; chmod 600 "${ah_secret}"
    printf 'x\n' > "${ah_staging}/regular"; chmod 600 "${ah_staging}/regular"
    # An agent could plant this across sessions to redirect chmod onto a
    # sensitive target outside the tree (~/.claude/.credentials.json etc).
    ln -s "${ah_secret}" "${ah_staging}/link"

    # Force the chown to fail so the fallback fires: a uid we cannot chown to
    # as a non-root operator (the --homedir-owned-by-someone-else case).
    host_agent_home() { echo "${ah_staging}"; }
    resolve_agent_home() { echo "${ah_staging}"; }
    resolve_pod_uid() { echo 4294967294; }

    prepare_agent_home claude

    ah_mode="$(stat -c %A "${ah_secret}")"
    [[ "${ah_mode}" == "-rw-------" ]] || fail "symlink target was modified via fallback: ${ah_mode}"
    ah_mode="$(stat -c %A "${ah_staging}/regular")"
    [[ "${ah_mode}" == *"rw-"*"rw-"*"---" ]] || fail "regular file not group-writable / leaked world bit: ${ah_mode}"
    pass "fallback left the symlink target untouched and set no world bit"
  )
}

main() {
  info "Running ${TEST_NAME} tests..."
  test_macos_uses_vm_local
  test_linux_uses_host_home
  test_host_agent_home_is_platform_independent
  test_vm_base_is_overridable
  test_home_dir_is_overridable
  test_pod_uid_tracks_operator
  test_prepare_home_fallback_is_symlink_safe
  echo "All ${TEST_NAME} tests passed."
}

main "$@"
