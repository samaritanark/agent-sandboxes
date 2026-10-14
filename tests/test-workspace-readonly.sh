#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-workspace-readonly.sh — Tier 2/3 host-exec hardening. Cluster-free.
#
# Covers two defenses that keep a Tier 2/3 agent (which writes the hostPath
# workspace as the operator's uid) from gaining host code execution:
#
#   1. READONLY_WORKSPACE_PATHS are mounted read-only over the workspace, so the
#      agent cannot plant git hooks / core.fsmonitor (.git/config, .git/hooks),
#      submodule config (.gitmodules), or IDE/devcontainer autorun config
#      (.vscode, .idea, .devcontainer) that the operator's host git/editor would
#      later execute. The rendered manifest must carry a read-only mount for
#      each such path that EXISTS in the repo and none for those that don't, and
#      the volumes/mounts blocks must name the same volumes. A `.git` that is a
#      regular file (linked worktree / submodule pointer) is itself made
#      read-only so it can't be repointed.
#   2. validate_repo_path refuses the agent-sandboxes checkout (or a parent of
#      it) as a --repo workspace, so the agent can't rewrite the tooling that
#      then runs on the host via PATH / sudo.
#
# Also guards the single-source-of-truth: READONLY_WORKSPACE_PATHS (the enforcer)
# must not drift from config/tiers/tier2.yaml readonly_paths (the declaration).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-workspace-readonly"
TEST_DIR="$(mktemp -d /tmp/sandbox-wsro-test-XXXXXX)"
HOME="${TEST_DIR}/home"; mkdir -p "${HOME}"
cleanup() { rm -rf "${TEST_DIR}"; }
trap cleanup EXIT

source "${SANDBOX_ROOT}/lib/platform.sh"
source "${SANDBOX_ROOT}/lib/config.sh"
source "${SANDBOX_ROOT}/lib/profile.sh"
source "${SANDBOX_ROOT}/lib/filesystem.sh"
source "${SANDBOX_ROOT}/lib/agents.sh"
source "${SANDBOX_ROOT}/lib/manifest.sh"

# Force the Linux workspace resolver (identity) so the volume hostPath equals
# the repo path regardless of the test host.
eval "detect_platform() { echo linux; }"

eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then pass "${label}"
  else fail "${label}: expected '${expected}', got '${actual}'"; fi
}
has() {
  local label="$1" haystack="$2" needle="$3"
  case "${haystack}" in
    *"${needle}"*) pass "${label}" ;;
    *) fail "${label}: '${needle}' not found" ;;
  esac
}
lacks() {
  local label="$1" haystack="$2" needle="$3"
  case "${haystack}" in
    *"${needle}"*) fail "${label}: '${needle}' should be absent" ;;
    *) pass "${label}" ;;
  esac
}

###############################################################################
# F7: read-only overlays for present paths, absent for missing ones
###############################################################################
test_readonly_overlays_present_and_absent() {
  info "Testing read-only workspace overlays (present vs absent paths)..."
  local repo="${TEST_DIR}/repo"
  mkdir -p "${repo}/.git/hooks" "${repo}/.vscode"
  : > "${repo}/.git/config"
  : > "${repo}/.gitmodules"
  : > "${repo}/.vscode/tasks.json"
  # .idea and .devcontainer deliberately absent.

  local vols mounts
  vols="$(build_volumes_block 2 "" ses-1 "" "${repo}")"
  mounts="$(build_volume_mounts_block 2 "" /home/agent/.config "" "${repo}")"

  # Volumes: one hostPath per existing path, correct type, pointing at the repo.
  has "volume ro-ws-0-0 for .git/config"   "${vols}" "- name: ro-ws-0-0"
  has ".git/config volume path"            "${vols}" "path: \"${repo}/.git/config\""
  has ".git/config volume type File"       "${vols}" $'path: "'"${repo}"$'/.git/config"\n        type: File'
  has "volume ro-ws-0-1 for .git/hooks"    "${vols}" "- name: ro-ws-0-1"
  has ".git/hooks volume type Directory"   "${vols}" $'path: "'"${repo}"$'/.git/hooks"\n        type: Directory'
  has "volume ro-ws-0-2 for .gitmodules"   "${vols}" "- name: ro-ws-0-2"
  has "volume ro-ws-0-3 for .vscode"       "${vols}" "- name: ro-ws-0-3"
  lacks "no volume ro-ws-0-4 (.idea absent)"        "${vols}" "- name: ro-ws-0-4"
  lacks "no volume ro-ws-0-5 (.devcontainer absent)" "${vols}" "- name: ro-ws-0-5"

  # Mounts: each present path mounted read-only under /workspace.
  has "mount .git/config read-only" "${mounts}" \
    $'- name: ro-ws-0-0\n          mountPath: /workspace/.git/config\n          readOnly: true'
  has "mount .git/hooks read-only" "${mounts}" \
    $'- name: ro-ws-0-1\n          mountPath: /workspace/.git/hooks\n          readOnly: true'
  has "mount .gitmodules read-only" "${mounts}" \
    $'- name: ro-ws-0-2\n          mountPath: /workspace/.gitmodules\n          readOnly: true'
  has "mount .vscode read-only" "${mounts}" \
    $'- name: ro-ws-0-3\n          mountPath: /workspace/.vscode\n          readOnly: true'
  lacks "no .idea mount"        "${mounts}" "/workspace/.idea"
  lacks "no .devcontainer mount" "${mounts}" "/workspace/.devcontainer"

  # Pairing: every ro-ws volume declared must be mounted, and vice versa.
  local v m
  v="$(printf '%s\n' "${vols}"   | grep -oE 'ro-ws-[0-9]+-[0-9]+' | sort -u)"
  m="$(printf '%s\n' "${mounts}" | grep -oE 'ro-ws-[0-9]+-[0-9]+' | sort -u)"
  eq "ro-ws volumes and mounts pair up exactly" "${v}" "${m}"
}

###############################################################################
# F7: a .git that is a FILE (worktree/submodule) is made read-only itself
###############################################################################
test_readonly_git_pointer_file() {
  info "Testing a .git pointer file (worktree/submodule) is mounted read-only..."
  local repo="${TEST_DIR}/worktree"
  mkdir -p "${repo}"
  printf 'gitdir: /somewhere/.git/worktrees/wt\n' > "${repo}/.git"

  local vols mounts idx
  vols="$(build_volumes_block 2 "" ses-1 "" "${repo}")"
  mounts="$(build_volume_mounts_block 2 "" /home/agent/.config "" "${repo}")"

  # Index is len(READONLY_WORKSPACE_PATHS) so it never collides with a positional
  # entry; compute it rather than hard-coding the list length.
  idx="${#READONLY_WORKSPACE_PATHS[@]}"
  has ".git pointer volume type File" "${vols}" \
    $'path: "'"${repo}"$'/.git"\n        type: File'
  has ".git pointer mounted read-only" "${mounts}" \
    $'- name: ro-ws-0-'"${idx}"$'\n          mountPath: /workspace/.git\n          readOnly: true'
  # Its config/hooks live outside the workspace, so no such mounts are emitted.
  lacks "no .git/config mount for pointer repo" "${mounts}" "/workspace/.git/config"
  lacks "no .git/hooks mount for pointer repo"  "${mounts}" "/workspace/.git/hooks"
}

###############################################################################
# F8: the agent-sandboxes checkout can't be used as a --repo workspace
###############################################################################
test_rejects_tool_checkout() {
  info "Testing validate_repo_path refuses the agent-sandboxes checkout..."
  local rc
  # The real checkout (this repo) is a git repo and equals SANDBOX_ROOT, which
  # the subshell inherits.
  ( validate_repo_path "${SANDBOX_ROOT}" ) >/dev/null 2>&1 && rc=0 || rc=$?
  if [[ "${rc}" -ne 0 ]]; then pass "refuses the checkout itself"
  else fail "accepted the agent-sandboxes checkout as a workspace"; fi

  # A subdirectory of the checkout (e.g. bin/, which shares the parent .git and
  # would let the agent rewrite bin/sandbox) is also refused.
  if git -C "${SANDBOX_ROOT}/bin" rev-parse --git-dir >/dev/null 2>&1; then
    ( validate_repo_path "${SANDBOX_ROOT}/bin" ) >/dev/null 2>&1 && rc=0 || rc=$?
    if [[ "${rc}" -ne 0 ]]; then pass "refuses a subdirectory of the checkout"
    else fail "accepted a subdirectory of the checkout as a workspace"; fi
  fi

  # A parent directory that CONTAINS the checkout is also refused.
  local parent
  parent="$(dirname "${SANDBOX_ROOT}")"
  if git -C "${parent}" rev-parse --git-dir >/dev/null 2>&1; then
    ( validate_repo_path "${parent}" ) >/dev/null 2>&1 && rc=0 || rc=$?
    if [[ "${rc}" -ne 0 ]]; then pass "refuses a parent that contains the checkout"
    else fail "accepted a parent of the checkout as a workspace"; fi
  else
    info "  (parent of checkout is not a git repo; parent-containment case not exercised)"
  fi

  # A normal unrelated git repo is still accepted.
  local ok="${TEST_DIR}/okrepo"
  mkdir -p "${ok}"; git -C "${ok}" init -q
  ( validate_repo_path "${ok}" ) >/dev/null 2>&1 && rc=0 || rc=$?
  eq "accepts an unrelated git repo" "0" "${rc}"
}

###############################################################################
# Drift: READONLY_WORKSPACE_PATHS (enforcer) == tier2.yaml readonly_paths (doc)
###############################################################################
test_readonly_list_no_drift() {
  info "Testing READONLY_WORKSPACE_PATHS matches tier2.yaml readonly_paths..."
  local code yaml
  code="$(for e in "${READONLY_WORKSPACE_PATHS[@]}"; do echo "${e%:*}"; done | sort)"
  yaml="$(awk '
    /^  readonly_paths:/ { f=1; next }
    f {
      if ($0 ~ /^    - /) {
        line=$0; sub(/^    - "?/,"",line); sub(/"?$/,"",line); sub(/\/$/,"",line); print line
      } else if ($0 ~ /^ *$/ || $0 ~ /^ *#/) { next }
      else { f=0 }
    }
  ' "${SANDBOX_ROOT}/config/tiers/tier2.yaml" | sort)"
  eq "enforced list == tier2.yaml readonly_paths" "${code}" "${yaml}"
}

main() {
  info "Running ${TEST_NAME} tests..."
  test_readonly_overlays_present_and_absent
  test_readonly_git_pointer_file
  test_rejects_tool_checkout
  test_readonly_list_no_drift
  echo "All ${TEST_NAME} tests passed."
}

main "$@"
