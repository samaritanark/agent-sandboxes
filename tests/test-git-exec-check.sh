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
#   2. .git/modules/<n>/config   — submodule repo config, flagged on hash drift.
#   3. a nested .git elsewhere   — a planted repo, or a pointer outside modules.
#   4. a replaced .git directory — inode differs from the launch baseline.
#
# This test plants each route and asserts the detector flags it, that a clean
# repo and a legitimate submodule repo pass, and that workspace_git_fingerprint
# round-trips through session.json so resume/stop/status can read the baseline.
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

# run_check <repo> [<ino>] [<mh>] -> sets CHECK_OUT, CHECK_RC (hit count)
run_check() {
  local repo="$1"; shift
  set +e
  CHECK_OUT="$(workspace_git_exec_check "${repo}" "$@")"
  CHECK_RC=$?
  set -e
}

###############################################################################
# A clean repo and a legitimate submodule repo pass (no false positives)
###############################################################################
test_clean_and_legit_pass() {
  info "Testing clean repo + legitimate submodule pass..."
  local clean="${TEST_DIR}/clean"
  mkdir -p "${clean}"; _gi "${clean}"
  echo x > "${clean}/x"; git -C "${clean}" add . && git -C "${clean}" commit -qm c
  local ino mh
  ino="$(_git_stat_inode "${clean}/.git")"; mh="$(_git_modules_hash "${clean}")"
  eq "clean repo has no .git/modules" "none" "${mh}"
  run_check "${clean}" "${ino}" "${mh}"
  eq "clean repo passes" "0" "${CHECK_RC}"

  # A real submodule: baseline captured, then checked against itself -> clean.
  local sub="${TEST_DIR}/sub" super="${TEST_DIR}/super"
  mkdir -p "${sub}"; _gi "${sub}"; echo s > "${sub}/s"
  git -C "${sub}" add . && git -C "${sub}" commit -qm s
  mkdir -p "${super}"; _gi "${super}"; echo t > "${super}/t"
  git -C "${super}" add . && git -C "${super}" commit -qm t
  git -C "${super}" -c protocol.file.allow=always submodule add -q "${sub}" s1 2>/dev/null
  git -C "${super}" commit -qm addsub
  [[ -f "${super}/.git/modules/s1/config" ]] || fail "submodule config not created; cannot test route 2"
  local sino smh
  sino="$(_git_stat_inode "${super}/.git")"; smh="$(_git_modules_hash "${super}")"
  run_check "${super}" "${sino}" "${smh}"
  eq "legit submodule with matching baseline passes" "0" "${CHECK_RC}"
  SUPER="${super}"; SUPER_INO="${sino}"; SUPER_MH="${smh}"  # reused below
}

###############################################################################
# Route 1: .git/commondir redirect
###############################################################################
test_route1_commondir() {
  info "Testing route 1 (.git/commondir)..."
  local repo="${TEST_DIR}/r1"
  mkdir -p "${repo}"; _gi "${repo}"; echo a > "${repo}/a"
  git -C "${repo}" add . && git -C "${repo}" commit -qm a
  printf 'evil' > "${repo}/.git/commondir"
  run_check "${repo}"
  [[ "${CHECK_RC}" -ge 1 ]] && pass "commondir flagged" || fail "commondir not flagged"
  has "names commondir" "${CHECK_OUT}" "commondir"
}

###############################################################################
# Route 2: submodule config drift (hash differs from launch baseline)
###############################################################################
test_route2_submodule_drift() {
  info "Testing route 2 (.git/modules/*/config drift)..."
  [[ -n "${SUPER:-}" ]] || fail "SUPER not set (run test_clean_and_legit_pass first)"
  # Tamper the submodule's own repo config after the baseline was captured.
  printf '\n[core]\n\tfsmonitor = /tmp/x\n' >> "${SUPER}/.git/modules/s1/config"
  run_check "${SUPER}" "${SUPER_INO}" "${SUPER_MH}"
  [[ "${CHECK_RC}" -ge 1 ]] && pass "submodule config drift flagged" || fail "drift not flagged"
  has "names modules" "${CHECK_OUT}" ".git/modules"
}

###############################################################################
# Route 3: a nested .git in a subdirectory
###############################################################################
test_route3_nested_git() {
  info "Testing route 3 (nested .git)..."
  local repo="${TEST_DIR}/r3"
  mkdir -p "${repo}/src"; _gi "${repo}"
  echo c > "${repo}/src/c"; git -C "${repo}" add . && git -C "${repo}" commit -qm c
  _gi "${repo}/src"    # src/ becomes its own repo
  run_check "${repo}"
  [[ "${CHECK_RC}" -ge 1 ]] && pass "nested .git flagged" || fail "nested .git not flagged"
  has "names src/.git" "${CHECK_OUT}" "src/.git"
}

###############################################################################
# Route 4: a replaced .git directory (inode differs from baseline)
###############################################################################
test_route4_replaced_git() {
  info "Testing route 4 (replaced .git)..."
  local repo="${TEST_DIR}/r4"
  mkdir -p "${repo}"; _gi "${repo}"; echo a > "${repo}/a"
  git -C "${repo}" add . && git -C "${repo}" commit -qm a
  local ino mh
  ino="$(_git_stat_inode "${repo}/.git")"; mh="$(_git_modules_hash "${repo}")"
  mv "${repo}/.git" "${repo}/.git-old"; _gi "${repo}"
  run_check "${repo}" "${ino}" "${mh}"
  [[ "${CHECK_RC}" -ge 1 ]] && pass "replaced .git flagged" || fail "replaced .git not flagged"
  has "names inode change" "${CHECK_OUT}" "inode"
}

###############################################################################
# A legit submodule pointer file (gitdir: ../.git/modules/...) is NOT flagged
###############################################################################
test_submodule_pointer_not_flagged() {
  info "Testing submodule working-tree pointer is not a route-3 false positive..."
  [[ -n "${SUPER:-}" ]] || fail "SUPER not set"
  # super/s1/.git is a pointer file "gitdir: ../.git/modules/s1" — legitimate.
  [[ -f "${SUPER}/s1/.git" ]] || fail "expected submodule pointer file at s1/.git"
  # Check with a fresh (untampered) baseline for modules so route 2 stays quiet.
  local mh; mh="$(_git_modules_hash "${SUPER}")"
  # The route-2 config was tampered in test_route2; recompute uses current state,
  # so pass the CURRENT hash as baseline to isolate the route-3 pointer check.
  run_check "${SUPER}" "$(_git_stat_inode "${SUPER}/.git")" "${mh}"
  lacks "submodule pointer not flagged as nested .git" "${CHECK_OUT}" "pointer outside"
}

###############################################################################
# No launch baseline + submodules present => flagged as unverified
###############################################################################
test_no_baseline_modules_flagged() {
  info "Testing modules present but no baseline is flagged..."
  [[ -n "${SUPER:-}" ]] || fail "SUPER not set"
  run_check "${SUPER}"   # no baseline args
  [[ "${CHECK_RC}" -ge 1 ]] && pass "unverified modules flagged" || fail "not flagged"
  has "names no baseline" "${CHECK_OUT}" "no launch baseline"
}

###############################################################################
# Fingerprint round-trips through session.json (launch -> resume/stop/status)
###############################################################################
test_fingerprint_session_json_roundtrip() {
  info "Testing workspace_git_fingerprint survives session.json..."
  local repo="${TEST_DIR}/fp"
  mkdir -p "${repo}"; _gi "${repo}"; echo a > "${repo}/a"
  git -C "${repo}" add . && git -C "${repo}" commit -qm a
  local log_dir="${TEST_DIR}/log/ses-fp"; mkdir -p "${log_dir}"
  # Build the env var cmd_run builds, then write and read back.
  export SESSION_REPO_GIT_FINGERPRINTS
  SESSION_REPO_GIT_FINGERPRINTS="$(jq -c --arg p "${repo}" \
    --argjson fp "$(workspace_git_fingerprint "${repo}")" '{($p): $fp}' <<<"{}")"
  local repos_json; repos_json="$(jq -R '[.]' -c <<<"${repo}")"
  audit_write_session_json "${log_dir}" "ses-fp" claude 2 tester \
    "${repos_json}" "" pod-fp "2026-10-15T00:00:00Z" example.com >/dev/null
  local got_ino got_mh want_ino want_mh
  got_ino="$(jq -r --arg p "${repo}" '.repo_git_fingerprints[$p].inode' "${log_dir}/session.json")"
  got_mh="$(jq -r --arg p "${repo}" '.repo_git_fingerprints[$p].modules_hash' "${log_dir}/session.json")"
  want_ino="$(_git_stat_inode "${repo}/.git")"; want_mh="$(_git_modules_hash "${repo}")"
  eq "inode round-trips" "${want_ino}" "${got_ino}"
  eq "modules_hash round-trips" "${want_mh}" "${got_mh}"
  # And the baseline from session.json validates the untampered repo as clean.
  run_check "${repo}" "${got_ino}" "${got_mh}"
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

###############################################################################
# Route 2 evasion: a commondir redirect INSIDE a submodule gitdir, with the evil
# config OUTSIDE .git/modules, must still be caught (the hash covers commondir).
###############################################################################
test_route2_submodule_commondir() {
  info "Testing submodule commondir redirect is caught by the hash..."
  local sub="${TEST_DIR}/csub" super="${TEST_DIR}/csuper"
  mkdir -p "${sub}"; _gi "${sub}"; echo s > "${sub}/s"
  git -C "${sub}" add . && git -C "${sub}" commit -qm s
  mkdir -p "${super}"; _gi "${super}"; echo t > "${super}/t"
  git -C "${super}" add . && git -C "${super}" commit -qm t
  git -C "${super}" -c protocol.file.allow=always submodule add -q "${sub}" s1 2>/dev/null
  git -C "${super}" commit -qm addsub
  local ino mh
  ino="$(_git_stat_inode "${super}/.git")"; mh="$(_git_modules_hash "${super}")"
  # Redirect s1's gitdir common dir to .git/evil (outside .git/modules); the
  # fsmonitor lives in .git/evil/config, which a config-only hash would miss.
  mkdir -p "${super}/.git/evil"
  printf '[core]\n\tfsmonitor = /tmp/x\n' > "${super}/.git/evil/config"
  printf '../../evil' > "${super}/.git/modules/s1/commondir"
  grep -q fsmonitor "${super}/.git/modules/s1/config" && fail "setup leaked into module config"
  run_check "${super}" "${ino}" "${mh}"
  [[ "${CHECK_RC}" -ge 1 ]] && pass "submodule commondir redirect flagged (hash covers commondir)" \
    || fail "submodule commondir redirect NOT flagged — route-2 evasion"
  has "names modules drift" "${CHECK_OUT}" ".git/modules"
}

###############################################################################
# No baseline at all (pre-upgrade session) flags .git as unverifiable
###############################################################################
test_no_baseline_replacement_flagged() {
  info "Testing missing baseline flags .git as unverifiable..."
  local repo="${TEST_DIR}/nobase"
  mkdir -p "${repo}"; _gi "${repo}"; echo a > "${repo}/a"
  git -C "${repo}" add . && git -C "${repo}" commit -qm a
  run_check "${repo}"   # no inode/mh args, no submodules
  [[ "${CHECK_RC}" -ge 1 ]] && pass "no-baseline repo flagged as unverifiable" \
    || fail "no-baseline repo passed silently (a .git replacement would be invisible)"
  has "names missing baseline" "${CHECK_OUT}" "baseline missing"
}

main() {
  info "Running ${TEST_NAME} tests..."
  test_clean_and_legit_pass
  test_route1_commondir
  test_route3_nested_git
  test_route4_replaced_git
  test_submodule_pointer_not_flagged
  test_no_baseline_modules_flagged
  test_no_baseline_replacement_flagged
  test_route2_submodule_drift
  test_route2_submodule_commondir
  test_fingerprint_session_json_roundtrip
  test_empty_fingerprints_tier1
  echo "All ${TEST_NAME} tests passed."
}

main "$@"
