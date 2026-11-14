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
  _gi "${repo}/src"    # src/ becomes its own repo (fresh: no host-exec surface)
  run_check "${repo}" "${fp}"
  # F5: a brand-new nested repo with no exec config and only sample hooks warns
  # and lets the baseline advance, rather than refusing like a planted redirect.
  eq "benign new nested repo warns (unverified), not refuses" "2" "${CHECK_RC}"
  has "names src as a new repo" "${CHECK_OUT}" "src/.git"
  has "says baseline will advance" "${CHECK_OUT}" "no recognized host-exec config"
  # But the same new repo carrying an exec config key IS a redirect.
  git -C "${repo}/src" config core.fsmonitor '/tmp/x'
  run_check "${repo}" "${fp}"
  eq "new nested repo with an exec config key is a redirect" "1" "${CHECK_RC}"
  has "names it as host-exec" "${CHECK_OUT}" "host-exec config or hooks"
}

test_route3_shape_rule_any_name() {
  info "Testing route 3 finds a repo-shaped dir by shape, not name..."
  local repo="${TEST_DIR}/r3shape" fp
  _mkrepo "${repo}"; fp="$(workspace_git_fingerprint "${repo}")"
  mkdir -p "${repo}/half"; printf 'ref: refs/heads/main\n' > "${repo}/half/HEAD"
  run_check "${repo}" "${fp}"
  eq "HEAD alone is not repo-shaped (git ignores it)" "0" "${CHECK_RC}"
  # A repo-shaped dir is found by shape, not by the name .git. With no config
  # and no hooks it carries no host-exec surface, so it warns (F5)...
  _shape "${repo}/vendor/lib"
  run_check "${repo}" "${fp}"
  eq "a benign repo-shaped dir (any name) warns" "2" "${CHECK_RC}"
  has "names vendor/lib" "${CHECK_OUT}" "vendor/lib"
  # ...but one carrying a planted hook is a redirect.
  mkdir -p "${repo}/vendor/lib/hooks"
  printf '#!/bin/sh\ntouch /tmp/x\n' > "${repo}/vendor/lib/hooks/pre-commit"
  run_check "${repo}" "${fp}"
  eq "a repo-shaped dir with a planted hook is a redirect" "1" "${CHECK_RC}"
  has "names vendor/lib as host-exec" "${CHECK_OUT}" "vendor/lib"
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
  has "names the pointer" "${CHECK_OUT}" "src/.git"
  has "says outside .git/modules" "${CHECK_OUT}" "pointer outside .git/modules"
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
# Config-steering routes git reads from OUTSIDE the two read-only mounts:
# core.hooksPath, a symlinked .git/hooks, and config include.path. Each runs on
# the host on a routine git status/commit, with a plain write to a tracked file.
###############################################################################
test_route_hookspath() {
  info "Testing core.hooksPath to a tracked directory..."
  local repo="${TEST_DIR}/hp" fp
  _mkrepo "${repo}"
  mkdir -p "${repo}/.husky/_"; printf '#!/bin/sh\necho a\n' > "${repo}/.husky/_/pre-commit"
  git -C "${repo}" config core.hooksPath .husky/_
  fp="$(workspace_git_fingerprint "${repo}")"
  run_check "${repo}" "${fp}"
  eq "repo with hooksPath set at launch passes" "0" "${CHECK_RC}"
  # Editing the hook the way an agent would is detected, naming the file.
  printf 'echo PWNED\n' >> "${repo}/.husky/_/pre-commit"
  run_check "${repo}" "${fp}"
  eq "hooksPath hook edit is a redirect" "1" "${CHECK_RC}"
  has "names the hooksPath hook" "${CHECK_OUT}" ".husky/_/pre-commit"
}

test_route_symlinked_hooks() {
  info "Testing a symlinked .git/hooks and a repoint..."
  local repo="${TEST_DIR}/sh" fp
  _mkrepo "${repo}"
  rm -rf "${repo}/.git/hooks"; mkdir "${repo}/.githooks"
  printf '#!/bin/sh\necho a\n' > "${repo}/.githooks/pre-commit"
  ln -s ../.githooks "${repo}/.git/hooks"
  fp="$(workspace_git_fingerprint "${repo}")"
  run_check "${repo}" "${fp}"
  eq "symlinked hooks at launch passes" "0" "${CHECK_RC}"
  printf 'echo PWNED\n' >> "${repo}/.githooks/pre-commit"
  run_check "${repo}" "${fp}"
  eq "editing a hook through the symlink is a redirect" "1" "${CHECK_RC}"
  has "names the hook through the link" "${CHECK_OUT}" ".git/hooks/pre-commit"
  # Repointing the link at a different directory with identical content still
  # drifts, because the link target itself is recorded.
  local repo2="${TEST_DIR}/sr" fp2
  _mkrepo "${repo2}"; rm -rf "${repo2}/.git/hooks"
  mkdir "${repo2}/h1" "${repo2}/h2"
  printf 'echo h\n' > "${repo2}/h1/pre-commit"; printf 'echo h\n' > "${repo2}/h2/pre-commit"
  ln -s ../h1 "${repo2}/.git/hooks"
  fp2="$(workspace_git_fingerprint "${repo2}")"
  rm "${repo2}/.git/hooks"; ln -s ../h2 "${repo2}/.git/hooks"
  run_check "${repo2}" "${fp2}"
  eq "repointing the hooks symlink is a redirect" "1" "${CHECK_RC}"
}

test_route_config_include() {
  info "Testing config include.path to a tracked file..."
  local repo="${TEST_DIR}/inc" fp
  _mkrepo "${repo}"
  echo '# shared' > "${repo}/.gitshared"
  git -C "${repo}" config include.path ../.gitshared
  fp="$(workspace_git_fingerprint "${repo}")"
  run_check "${repo}" "${fp}"
  eq "repo with an include at launch passes" "0" "${CHECK_RC}"
  printf '[core]\n\tfsmonitor = /tmp/x\n' >> "${repo}/.gitshared"
  run_check "${repo}" "${fp}"
  eq "editing an included config file is a redirect" "1" "${CHECK_RC}"
  has "names the included file" "${CHECK_OUT}" ".gitshared"
  # An include target OUTSIDE the worktree is not agent-writable, so an operator
  # editing it must not raise a false positive.
  local repo2="${TEST_DIR}/ext" fp2
  _mkrepo "${repo2}"
  echo '# e' > "${TEST_DIR}/extcfg"
  git -C "${repo2}" config include.path "${TEST_DIR}/extcfg"
  fp2="$(workspace_git_fingerprint "${repo2}")"
  printf '# operator edit\n' >> "${TEST_DIR}/extcfg"
  run_check "${repo2}" "${fp2}"
  eq "editing an out-of-workspace include does not flag" "0" "${CHECK_RC}"
}

test_f9_hash_cap() {
  info "Testing the exec-digest file cap bounds the hashing (F9)..."
  local repo="${TEST_DIR}/cap" fp lines
  _mkrepo "${repo}"   # ships ~14 .sample hooks, so a cap of 5 truncates
  lines="$(SANDBOX_GIT_EXEC_HASH_CAP=5 _git_dir_exec_lines "${repo}/.git" "${repo}")"
  has "cap records a truncation sentinel" "${lines}" "exec-files-truncated:"
  # Crossing the cap still changes the digest, so a redirect cannot hide beyond
  # it: the sentinel carries the file count.
  fp="$(SANDBOX_GIT_EXEC_HASH_CAP=5 workspace_git_fingerprint "${repo}")"
  printf '#!/bin/sh\n' > "${repo}/.git/hooks/pre-commit"
  local rc=0
  SANDBOX_GIT_EXEC_HASH_CAP=5 workspace_git_exec_check "${repo}" "${fp}" >/dev/null || rc=$?
  eq "adding a file past the cap still drifts" "1" "${rc}"
}

test_f9_nested_entry_cap() {
  info "Testing the nested-entry cap bounds a repo-shaped-dir flood (F9)..."
  local repo="${TEST_DIR}/ncap" fp i rc=0
  _mkrepo "${repo}"
  for i in $(seq 1 12); do _shape "${repo}/n${i}"; done   # 12 repo-shaped dirs
  fp="$(SANDBOX_GIT_NESTED_ENTRY_CAP=5 workspace_git_fingerprint "${repo}")"
  set +e
  CHECK_OUT="$(SANDBOX_GIT_NESTED_ENTRY_CAP=5 workspace_git_exec_check "${repo}" "${fp}")"
  CHECK_RC=$?
  set -e
  eq "a flood past the cap is unverified, not clean" "2" "${CHECK_RC}"
  has "names the overflow" "${CHECK_OUT}" "are unchecked"
}

test_benign_exec_key_breadth() {
  info "Testing a new nested repo with any exec config key refuses, not warns..."
  local base="${TEST_DIR}/ek" fp key d
  # Keys git runs that a blacklist must cover; each must make a NEW repo refuse.
  for key in "diff.external=/x" "pager.status=/x" "credential.helper=!/x" \
             "trailer.sob.command=/x" "core.fsmonitor=/x" "init.templateDir=/x"; do
    d="${base}/$(printf '%s' "${key%%=*}" | tr '.' '_')"
    _mkrepo "${d}"; fp="$(workspace_git_fingerprint "${d}")"
    _mkrepo "${d}/v"; git -C "${d}/v" config "${key%%=*}" "${key#*=}"
    run_check "${d}" "${fp}"
    eq "new nested repo with ${key%%=*} refuses" "1" "${CHECK_RC}"
  done
  # A plain https clone has no exec surface and stays benign (F5 UX preserved).
  d="${base}/https"; _mkrepo "${d}"; fp="$(workspace_git_fingerprint "${d}")"
  _mkrepo "${d}/v"; git -C "${d}/v" remote add origin https://example.com/r.git
  run_check "${d}" "${fp}"
  eq "new nested repo with an https remote stays benign" "2" "${CHECK_RC}"
  # An ext:: transport URL is an exec vector, so it refuses.
  d="${base}/ext"; _mkrepo "${d}"; fp="$(workspace_git_fingerprint "${d}")"
  _mkrepo "${d}/v"; git -C "${d}/v" remote add origin "ext::sh -c payload"
  run_check "${d}" "${fp}"
  eq "new nested repo with an ext:: remote refuses" "1" "${CHECK_RC}"
}

test_cap_does_not_hide_pointer() {
  info "Testing a dir flood cannot push a malicious pointer past the cap..."
  local repo="${TEST_DIR}/caphide" fp i
  _mkrepo "${repo}"; fp="$(workspace_git_fingerprint "${repo}")"
  # Pad with repo-shaped dirs that sort before the pointer, then plant a
  # pointer resolving outside .git/modules. Pointers are checked uncapped.
  for i in 1 2 3 4 5 6; do _shape "${repo}/aaa${i}"; done
  _shape "${TEST_DIR}/cap-evil-target"
  mkdir -p "${repo}/zsub"
  printf 'gitdir: ../../cap-evil-target\n' > "${repo}/zsub/.git"
  set +e
  CHECK_OUT="$(SANDBOX_GIT_NESTED_ENTRY_CAP=3 workspace_git_exec_check "${repo}" "${fp}")"
  CHECK_RC=$?
  set -e
  eq "the pointer is still a redirect despite the flood" "1" "${CHECK_RC}"
  has "names the hidden pointer" "${CHECK_OUT}" "pointer outside .git/modules"
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
  has "output is capped" "${CHECK_OUT}" "more"
  # Only the capped number of lines is printed, not all 256.
  if [[ "$(grep -c '^    p[0-9]* -> ' <<<"${CHECK_OUT}")" -le 20 ]]; then
    pass "at most 20 pointer lines printed"
  else
    fail "pointer list not capped"
  fi
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
  for k in inode modules_hash gitdir_kind gitdir_hash nested_hash gitdir_lines; do
    if [[ -n "$(jq -r --arg k "${k}" '.[$k] // ""' <<<"${got}")" ]]; then
      pass "fingerprint has ${k}"
    else
      fail "fingerprint missing ${k}"
    fi
  done
  if [[ "$(jq -r '.nested_map | type' <<<"${got}")" == "object" ]]; then
    pass "fingerprint nested_map is an object"
  else
    fail "fingerprint nested_map not an object"
  fi
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
  test_route_hookspath
  test_route_symlinked_hooks
  test_route_config_include
  test_f9_hash_cap
  test_f9_nested_entry_cap
  test_benign_exec_key_breadth
  test_cap_does_not_hide_pointer
  test_no_baseline_unverified
  test_status_never_wraps
  test_route2_submodule_drift
  test_fingerprint_session_json_roundtrip
  test_empty_fingerprints_tier1
  echo "All ${TEST_NAME} tests passed."
}

main "$@"
