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
source "${SANDBOX_ROOT}/lib/filesystem.sh"

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

# A throwaway git work tree, so validate_repo_path clears its "must be a git
# repo" gate and reaches the path checks we care about here.
_mk_git_repo() {
  local d; d="$(mktemp -d /tmp/test-vrp-XXXXXX)"
  git -C "${d}" init -q
  echo "${d}"
}

# Run validate_repo_path in a subshell (it exits on refusal) with SANDBOX_ROOT
# pinned to ${1}; capture stderr in _VRP_OUT and the exit code in _VRP_RC
# without tripping the script's own errexit.
_run_vrp() {
  local root="$1" repo="$2"
  _VRP_RC=0
  _VRP_OUT="$( ( export SANDBOX_ROOT="${root}"; validate_repo_path "${repo}" ) 2>&1 )" \
    || _VRP_RC=$?
}

test_vrp_accepts_plain_repo() {
  info "Testing validate_repo_path accepts an ordinary git repo..."
  local root repo; root="$(_mk_git_repo)"; repo="$(_mk_git_repo)"
  _run_vrp "${root}" "${repo}"
  if [[ "${_VRP_RC}" -eq 0 ]]; then
    pass "ordinary repo accepted"
  else
    fail "ordinary repo rejected (rc=${_VRP_RC}): ${_VRP_OUT}"
  fi
  rm -rf "${root}" "${repo}"
}

test_vrp_refuses_sandbox_checkout() {
  info "Testing validate_repo_path refuses the sandbox checkout itself..."
  local root; root="$(_mk_git_repo)"
  _run_vrp "${root}" "${root}"
  if [[ "${_VRP_RC}" -ne 0 ]] && [[ "${_VRP_OUT}" == *"agent-sandboxes checkout"* ]]; then
    pass "checkout root refused with the right message"
  else
    fail "checkout root not refused (rc=${_VRP_RC}): ${_VRP_OUT}"
  fi
  rm -rf "${root}"
}

test_vrp_refuses_path_under_checkout() {
  info "Testing validate_repo_path refuses a path UNDER the checkout..."
  local root; root="$(_mk_git_repo)"
  mkdir -p "${root}/subdir"   # inside the work tree, so the git-repo gate passes
  _run_vrp "${root}" "${root}/subdir"
  if [[ "${_VRP_RC}" -ne 0 ]] && [[ "${_VRP_OUT}" == *"agent-sandboxes checkout"* ]]; then
    pass "subdir of checkout refused"
  else
    fail "subdir of checkout not refused (rc=${_VRP_RC}): ${_VRP_OUT}"
  fi
  rm -rf "${root}"
}

test_vrp_refuses_home() {
  info "Testing validate_repo_path still refuses \$HOME exactly..."
  local root home; root="$(_mk_git_repo)"; home="$(_mk_git_repo)"
  # Override HOME so the exact-HOME branch is exercised deterministically.
  _VRP_RC=0
  _VRP_OUT="$( ( export SANDBOX_ROOT="${root}" HOME="${home}"
                 validate_repo_path "${home}" ) 2>&1 )" || _VRP_RC=$?
  if [[ "${_VRP_RC}" -ne 0 ]] && [[ "${_VRP_OUT}" == *"\$HOME"* ]]; then
    pass "\$HOME refused"
  else
    fail "\$HOME not refused (rc=${_VRP_RC}): ${_VRP_OUT}"
  fi
  rm -rf "${root}" "${home}"
}

main() {
  info "Running ${TEST_NAME} tests..."
  test_macos_uses_vm_local_per_session
  test_linux_mounts_repo_directly
  test_vm_base_is_overridable
  test_vrp_accepts_plain_repo
  test_vrp_refuses_sandbox_checkout
  test_vrp_refuses_path_under_checkout
  test_vrp_refuses_home
  echo "All ${TEST_NAME} tests passed."
}

main "$@"
