#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-workspace-mount.sh — lib/platform.sh tier 2/3 workspace path
# resolution.
#
# The pod's tier 2/3 workspace hostPath must differ by platform: on macOS it is
# a per-session VM-local ext4 copy (NOT the repo mounted directly off the 9p Mac
# home, where the gVisor gofer presents container-created files as root-owned so
# the uid-1000 agent cannot write the workspace — including .git/ during a
# commit); the copy is kept in two-way sync with the host repo by an in-VM
# Mutagen daemon. On Linux/WSL the host repo is mounted directly, so the
# resolver is the identity function and nothing changes. This locks that split
# in. Cluster-free.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-workspace-mount"

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

test_macos_uses_vm_local_per_session() {
  info "Testing macOS resolves the workspace to a per-session VM-local copy..."
  _set_platform macos
  eq "single repo → VM-local/<session>/<basename>" \
    "/var/lib/sandbox/workspaces/ses-1/myproj" \
    "$(resolve_workspace_mount ses-1 /Users/dev/repos/myproj)"
  # The basename is what lands under /workspace[/<basename>] in the pod, so the
  # VM-local copy is keyed by basename, and sessions are isolated by session id.
  eq "different session → isolated copy" \
    "/var/lib/sandbox/workspaces/ses-2/myproj" \
    "$(resolve_workspace_mount ses-2 /Users/dev/repos/myproj)"
  eq "trailing slash tolerated" \
    "/var/lib/sandbox/workspaces/ses-1/myproj" \
    "$(resolve_workspace_mount ses-1 /Users/dev/repos/myproj/)"
}

test_linux_mounts_repo_directly() {
  info "Testing Linux resolves the workspace to the repo path itself (identity)..."
  _set_platform linux
  eq "repo mounted directly" \
    "/home/dev/repos/myproj" \
    "$(resolve_workspace_mount ses-1 /home/dev/repos/myproj)"
}

test_vm_base_is_overridable() {
  info "Testing SANDBOX_VM_WORKSPACE_BASE override is honored..."
  ( SANDBOX_VM_WORKSPACE_BASE="/data/ws"
    source "${SANDBOX_ROOT}/lib/platform.sh"
    _set_platform macos
    eq "override applies" \
      "/data/ws/ses-1/myproj" \
      "$(resolve_workspace_mount ses-1 /Users/dev/repos/myproj)" )
}

main() {
  info "Running ${TEST_NAME} tests..."
  test_macos_uses_vm_local_per_session
  test_linux_mounts_repo_directly
  test_vm_base_is_overridable
  echo "All ${TEST_NAME} tests passed."
}

main "$@"
