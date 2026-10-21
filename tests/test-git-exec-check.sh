#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-git-exec-check.sh — host-side git host-exec vector detection.
# Cluster-free.
#
# The read-only .git/config + .git/hooks mounts block edits to those two paths
# only. git reads config and hooks from several OTHER writable locations the
# mounts do not cover, and each fires on the operator's next host `git status`
# as the operator, outside gVisor and default-deny egress (PR #113 follow-up,
# F7). workspace_git_exec_check is the host-side backstop that detects them:
#
#   1. .git/commondir            — redirects $GIT_COMMON_DIR to an agent dir.
#   2. .git/modules/<n>/config   — submodule repo config, flagged on hash drift
#                                   (even when the baseline had no submodules).
#   3. a nested repository       — any repo-shaped dir, or a .git pointer that
#                                   resolves outside .git/modules.
#   4. a replaced/repointed .git — inode, kind, or gitdir_hash differs.
#
# This test plants each route's structure (no payloads) and asserts the
# detector's status: 0 clean, 1 redirect, 2 unverified. It also checks that
# legitimate layouts pass, that the status never wraps to 0 on many findings,
# and that workspace_git_fingerprint round-trips through session.json.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-git-exec-check"
TEST_DIR="$(mktemp -d /tmp/sandbox-gitexec-test-XXXXXX)"
HOME="${TEST_DIR}/home"; mkdir -p "${HOME}"
cleanup() { rm -rf "${TEST_DIR}"; }
trap cleanup EXIT

source "${SANDBOX_ROOT}/lib/platform.sh"
source "${SANDBOX_ROOT}/lib/config.sh"
source "${SANDBOX_ROOT}/lib/tier.sh"
source "${SANDBOX_ROOT}/lib/agents.sh"
source "${SANDBOX_ROOT}/lib/filesystem.sh"
source "${SANDBOX_ROOT}/lib/audit.sh"

export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
_gi() { git -C "$1" init -q && git -C "$1" config user.email t@t && git -C "$1" config user.name t; }

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

# run_check <repo> [<fingerprint_json>] -> sets CHECK_OUT, CHECK_RC (status)
run_check() {
  local repo="$1"; shift
  set +e
  CHECK_OUT="$(workspace_git_exec_check "${repo}" "$@")"
  CHECK_RC=$?
  set -e
}

# _mkrepo <dir> — a fresh repo with one commit.
_mkrepo() {
  mkdir -p "$1"; _gi "$1"; echo a > "$1/a"
  git -C "$1" add . && git -C "$1" commit -qm a
}

# _shape <dir> — make <dir> repo-shaped (what git's is_git_directory accepts).
_shape() {
  mkdir -p "$1/objects" "$1/refs"
  printf 'ref: refs/heads/main\n' > "$1/HEAD"
}

###############################################################################
# A clean repo and a legitimate submodule repo pass (no false positives)
###############################################################################
test_clean_and_legit_pass() {
  info "Testing clean repo + legitimate submodule pass..."
  local clean="${TEST_DIR}/clean" fp
  _mkrepo "${clean}"
  eq "clean repo has no .git/modules" "none" "$(_git_modules_hash "${clean}")"
  fp="$(workspace_git_fingerprint "${clean}")"
  run_check "${clean}" "${fp}"
  eq "clean repo passes" "0" "${CHECK_RC}"
  echo b > "${clean}/b"; git -C "${clean}" add b && git -C "${clean}" commit -qm b
  run_check "${clean}" "${fp}"
  eq "an ordinary commit during the session stays clean" "0" "${CHECK_RC}"

  # A real submodule: baseline captured, then checked against itself -> clean.
  local sub="${TEST_DIR}/sub" super="${TEST_DIR}/super"
  _mkrepo "${sub}"; _mkrepo "${super}"
  git -C "${super}" -c protocol.file.allow=always submodule add -q "${sub}" s1 2>/dev/null
  git -C "${super}" commit -qm addsub
  [[ -f "${super}/.git/modules/s1/config" ]] || fail "submodule config not created; cannot test route 2"
  SUPER="${super}"; SUPER_FP="$(workspace_git_fingerprint "${super}")"  # reused below
  run_check "${super}" "${SUPER_FP}"
  eq "legit submodule with matching baseline passes" "0" "${CHECK_RC}"
  git -C "${super}" status >/dev/null
  run_check "${super}" "${SUPER_FP}"
  eq "legit submodule still passes after git status" "0" "${CHECK_RC}"
  lacks "submodule pointer not flagged" "${CHECK_OUT}" "pointer outside"
}

###############################################################################
# Legitimate nested layouts that existed at launch pass
###############################################################################
test_legit_nested_layouts_pass() {
  info "Testing a vendored repo and a linked worktree present at launch pass..."
  local v="${TEST_DIR}/vend"
  _mkrepo "${v}"; _mkrepo "${v}/vendor/x"
  run_check "${v}" "$(workspace_git_fingerprint "${v}")"
  eq "nested repo present at launch passes" "0" "${CHECK_RC}"

  local main="${TEST_DIR}/wtmain" wt="${TEST_DIR}/wt"
  _mkrepo "${main}"; git -C "${main}" worktree add -q "${wt}" 2>/dev/null
  [[ -f "${wt}/.git" ]] || fail "linked worktree .git is not a pointer file"
  WT="${wt}"; WT_FP="$(workspace_git_fingerprint "${wt}")"
  eq "worktree gitdir_kind" "file" "$(jq -r .gitdir_kind <<<"${WT_FP}")"
  run_check "${wt}" "${WT_FP}"
  eq "linked worktree workspace passes" "0" "${CHECK_RC}"
}

###############################################################################
# Route 1: .git/commondir redirect (no baseline needed)
###############################################################################
test_route1_commondir() {
  info "Testing route 1 (.git/commondir)..."
  local repo="${TEST_DIR}/r1" fp
  _mkrepo "${repo}"; fp="$(workspace_git_fingerprint "${repo}")"
  printf 'evil' > "${repo}/.git/commondir"
  run_check "${repo}" "${fp}"
  eq "commondir is a redirect" "1" "${CHECK_RC}"
  has "names commondir" "${CHECK_OUT}" "commondir"
  run_check "${repo}"
  eq "commondir is a redirect even without a baseline" "1" "${CHECK_RC}"
}

###############################################################################
# Route 2: submodule config drift, and gitdirs planted where there were none
###############################################################################
test_route2_submodule_drift() {
  info "Testing route 2 (.git/modules/*/config drift)..."
  [[ -n "${SUPER:-}" ]] || fail "SUPER not set (run test_clean_and_legit_pass first)"
  printf '\n[core]\n\tfsmonitor = /tmp/x\n' >> "${SUPER}/.git/modules/s1/config"
  run_check "${SUPER}" "${SUPER_FP}"
  eq "submodule config drift is a redirect" "1" "${CHECK_RC}"
  has "names modules" "${CHECK_OUT}" ".git/modules"
}

test_route2_planted_in_submodule_free_repo() {
  info "Testing route 2 when the launch baseline had no submodules..."
  local repo="${TEST_DIR}/r2none" fp
  _mkrepo "${repo}"; fp="$(workspace_git_fingerprint "${repo}")"
  eq "baseline modules_hash is none" "none" "$(jq -r .modules_hash <<<"${fp}")"
  mkdir -p "${repo}/.git/modules/m"; _shape "${repo}/.git/modules/m"
  printf '[core]\n\tbare = false\n' > "${repo}/.git/modules/m/config"
  run_check "${repo}" "${fp}"
  eq "submodule gitdir planted after a 'none' baseline is a redirect" "1" "${CHECK_RC}"
  has "names modules" "${CHECK_OUT}" ".git/modules"
}

test_route2_submodule_commondir() {
  info "Testing submodule commondir redirect is caught by the hash..."
  local sub="${TEST_DIR}/csub" super="${TEST_DIR}/csuper" fp
  _mkrepo "${sub}"; _mkrepo "${super}"
  git -C "${super}" -c protocol.file.allow=always submodule add -q "${sub}" s1 2>/dev/null
  git -C "${super}" commit -qm addsub
  fp="$(workspace_git_fingerprint "${super}")"
  mkdir -p "${super}/.git/evil"
  printf '[core]\n\tfsmonitor = /tmp/x\n' > "${super}/.git/evil/config"
  printf '../../evil' > "${super}/.git/modules/s1/commondir"
  grep -q fsmonitor "${super}/.git/modules/s1/config" && fail "setup leaked into module config"
  run_check "${super}" "${fp}"
  eq "submodule commondir redirect is a redirect" "1" "${CHECK_RC}"
  has "names modules drift" "${CHECK_OUT}" ".git/modules"
}

###############################################################################
# Route 3: nested repositories, found by shape and compared to the baseline
###############################################################################
test_route3_nested_git() {
  info "Testing route 3 (nested .git)..."
  local repo="${TEST_DIR}/r3" fp
  mkdir -p "${repo}/src"; _gi "${repo}"
  echo c > "${repo}/src/c"; git -C "${repo}" add . && git -C "${repo}" commit -qm c
  fp="$(workspace_git_fingerprint "${repo}")"
  _gi "${repo}/src"    # src/ becomes its own repo
  run_check "${repo}" "${fp}"
  eq "new nested .git is a redirect" "1" "${CHECK_RC}"
  has "names src" "${CHECK_OUT}" "dir: src/.git"
}

test_route3_shape_rule_any_name() {
  info "Testing route 3 finds a repo-shaped dir by shape, not name..."
  local repo="${TEST_DIR}/r3shape" fp
  _mkrepo "${repo}"; fp="$(workspace_git_fingerprint "${repo}")"
  mkdir -p "${repo}/half"; printf 'ref: refs/heads/main\n' > "${repo}/half/HEAD"
  run_check "${repo}" "${fp}"
  eq "HEAD alone is not repo-shaped (git ignores it)" "0" "${CHECK_RC}"
  _shape "${repo}/vendor/lib"
  run_check "${repo}" "${fp}"
  eq "a repo-shaped dir with no .git name is a redirect" "1" "${CHECK_RC}"
  has "names vendor/lib" "${CHECK_OUT}" "dir: vendor/lib"
}

test_route3_nested_config_drift() {
  info "Testing route 3 flags a config change in a nested repo present at launch..."
  local repo="${TEST_DIR}/r3drift" fp
  _mkrepo "${repo}"; _mkrepo "${repo}/vendor/x"
  fp="$(workspace_git_fingerprint "${repo}")"
  printf '\n[core]\n\tfsmonitor = /tmp/x\n' >> "${repo}/vendor/x/.git/config"
  run_check "${repo}" "${fp}"
  eq "nested repo config drift is a redirect" "1" "${CHECK_RC}"
}

test_route3_pointer_resolved_by_path() {
  info "Testing route 3 resolves nested pointers by path, not by pattern..."
  local repo="${TEST_DIR}/r3ptr" fp
  _mkrepo "${repo}"; mkdir -p "${repo}/.git/modules" "${repo}/src"
  fp="$(workspace_git_fingerprint "${repo}")"
  _shape "${repo}/elsewhere"
  printf 'gitdir: ../.git/modules/../../elsewhere\n' > "${repo}/src/.git"
  run_check "${repo}" "${fp}"
  eq "pointer that traverses out of .git/modules is a redirect" "1" "${CHECK_RC}"
  has "names the pointer" "${CHECK_OUT}" "pointer outside .git/modules: src/.git"
  run_check "${repo}"
  eq "it is a redirect even without a baseline" "1" "${CHECK_RC}"
}

test_route3_no_baseline_unverified() {
  info "Testing nested repos with no baseline are unverified, not clean..."
  local repo="${TEST_DIR}/r3nobase"
  _mkrepo "${repo}"; _mkrepo "${repo}/vendor/x"
  run_check "${repo}" "$(jq -c '{inode, modules_hash}' <<<"$(workspace_git_fingerprint "${repo}")")"
  eq "pre-upgrade baseline + nested repo is unverified" "2" "${CHECK_RC}"
  has "says no launch baseline" "${CHECK_OUT}" "no launch baseline"
}

###############################################################################
# Route 4: a replaced, converted, or repointed .git
###############################################################################
test_route4_replaced_git() {
  info "Testing route 4 (replaced .git)..."
  local repo="${TEST_DIR}/r4" fp
  _mkrepo "${repo}"; fp="$(workspace_git_fingerprint "${repo}")"
  mv "${repo}/.git" "${TEST_DIR}/r4-old.git"; _gi "${repo}"
  run_check "${repo}" "${fp}"
  eq "replaced .git is a redirect" "1" "${CHECK_RC}"
  has "names inode change" "${CHECK_OUT}" "inode"
}

test_route4_git_becomes_pointer() {
  info "Testing route 4 (.git directory turned into a pointer file)..."
  local repo="${TEST_DIR}/r4ptr" fp
  _mkrepo "${repo}"; fp="$(workspace_git_fingerprint "${repo}")"
  mv "${repo}/.git" "${repo}/.git-moved"; printf 'gitdir: .git-moved\n' > "${repo}/.git"
  run_check "${repo}" "${fp}"
  eq ".git converted to a pointer is a redirect" "1" "${CHECK_RC}"
  has "names the kind change" "${CHECK_OUT}" "from a dir to a file"
}

test_route4_pointer_rewritten_in_place() {
  info "Testing route 4 (worktree pointer rewritten in place, same inode)..."
  [[ -n "${WT:-}" ]] || fail "WT not set (run test_legit_nested_layouts_pass first)"
  local ino; ino="$(_git_stat_inode "${WT}/.git")"
  _shape "${TEST_DIR}/wt-other"
  printf 'gitdir: %s\n' "${TEST_DIR}/wt-other" > "${WT}/.git"
  eq "pointer rewrite keeps the inode" "${ino}" "$(_git_stat_inode "${WT}/.git")"
  run_check "${WT}" "${WT_FP}"
  eq "in-place pointer rewrite is a redirect" "1" "${CHECK_RC}"
  has "names the rewrite" "${CHECK_OUT}" "pointer was rewritten"
  # A pre-upgrade baseline (inode only) cannot see this: unverified, not clean.
  run_check "${WT}" "$(jq -c '{inode, modules_hash}' <<<"${WT_FP}")"
  eq "pointer with an inode-only baseline is unverified" "2" "${CHECK_RC}"
}

###############################################################################
# Status values: no baseline is 2, and many findings never wrap to 0
###############################################################################
test_no_baseline_unverified() {
  info "Testing missing baseline is unverified (2), not clean..."
  local repo="${TEST_DIR}/nobase"
  _mkrepo "${repo}"
  run_check "${repo}"
  eq "no-baseline repo is unverified" "2" "${CHECK_RC}"
  has "names missing baseline" "${CHECK_OUT}" "baseline missing"
  [[ -n "${SUPER:-}" ]] || fail "SUPER not set"
  run_check "${SUPER}"
  eq "submodules with no baseline are unverified" "2" "${CHECK_RC}"
  has "names no launch baseline" "${CHECK_OUT}" "no launch baseline"
  # An old-format baseline on a clean repo is still verifiable.
  run_check "${repo}" "$(jq -c '{inode, modules_hash}' <<<"$(workspace_git_fingerprint "${repo}")")"
  eq "inode-only baseline on a clean repo passes" "0" "${CHECK_RC}"
}

test_status_never_wraps() {
  info "Testing 256 findings still return 1 (a hit count would wrap to 0)..."
  local repo="${TEST_DIR}/wrap" fp i
  _mkrepo "${repo}"; mkdir -p "${repo}/.git/modules"
  fp="$(workspace_git_fingerprint "${repo}")"
  _shape "${repo}/target"
  for i in $(seq 1 256); do
    mkdir -p "${repo}/p${i}"
    printf 'gitdir: ../target\n' > "${repo}/p${i}/.git"
  done
  run_check "${repo}" "${fp}"
  eq "256 findings return 1" "1" "${CHECK_RC}"
  has "output is capped" "${CHECK_OUT}" "and more"
}

###############################################################################
# Fingerprint round-trips through session.json (launch -> resume/stop/status)
###############################################################################
test_fingerprint_session_json_roundtrip() {
  info "Testing workspace_git_fingerprint survives session.json..."
  local repo="${TEST_DIR}/fp"
  _mkrepo "${repo}"
  local log_dir="${TEST_DIR}/log/ses-fp"; mkdir -p "${log_dir}"
  # Build the env var cmd_run builds, then write and read back.
  local fp; fp="$(workspace_git_fingerprint "${repo}")"
  export SESSION_REPO_GIT_FINGERPRINTS
  SESSION_REPO_GIT_FINGERPRINTS="$(jq -c --arg p "${repo}" --argjson fp "${fp}" '{($p): $fp}' <<<"{}")"
  local repos_json; repos_json="$(jq -R '[.]' -c <<<"${repo}")"
  audit_write_session_json "${log_dir}" "ses-fp" claude 2 tester \
    "${repos_json}" "" pod-fp "2026-10-15T00:00:00Z" example.com >/dev/null
  local got
  got="$(jq -c --arg p "${repo}" '.repo_git_fingerprints[$p]' "${log_dir}/session.json")"
  eq "fingerprint round-trips" "${fp}" "${got}"
  local k
  for k in inode modules_hash gitdir_kind gitdir_hash nested_hash; do
    [[ -n "$(jq -r --arg k "${k}" '.[$k] // ""' <<<"${got}")" ]] \
      && pass "fingerprint has ${k}" || fail "fingerprint missing ${k}"
  done
  run_check "${repo}" "${got}"
  eq "session.json baseline passes untampered repo" "0" "${CHECK_RC}"
}

###############################################################################
# A Tier 1 / no-repo session records an empty fingerprint map (no crash)
###############################################################################
test_empty_fingerprints_tier1() {
  info "Testing Tier 1 session.json has empty fingerprint map..."
  local log_dir="${TEST_DIR}/log/ses-t1"; mkdir -p "${log_dir}"
  unset SESSION_REPO_GIT_FINGERPRINTS
  audit_write_session_json "${log_dir}" "ses-t1" claude 1 tester \
    "" "" pod-t1 "2026-10-15T00:00:00Z" >/dev/null
  local v; v="$(jq -c '.repo_git_fingerprints' "${log_dir}/session.json")"
  eq "empty fingerprint map" "{}" "${v}"
}

main() {
  info "Running ${TEST_NAME} tests..."
  test_clean_and_legit_pass
  test_legit_nested_layouts_pass
  test_route1_commondir
  test_route2_planted_in_submodule_free_repo
  test_route2_submodule_commondir
  test_route3_nested_git
  test_route3_shape_rule_any_name
  test_route3_nested_config_drift
  test_route3_pointer_resolved_by_path
  test_route3_no_baseline_unverified
  test_route4_replaced_git
  test_route4_git_becomes_pointer
  test_route4_pointer_rewritten_in_place
  test_no_baseline_unverified
  test_status_never_wraps
  test_route2_submodule_drift
  test_fingerprint_session_json_roundtrip
  test_empty_fingerprints_tier1
  echo "All ${TEST_NAME} tests passed."
}

main "$@"
