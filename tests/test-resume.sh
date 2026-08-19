#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-resume.sh — 'sandbox resume' recreate/guide decision (cluster-free).
#
# When a session's pod was torn down, resume either recreates it from
# session.json or guides the operator to relaunch (issue #70). The kubectl apply
# / wait path in recreate_session_pod needs a live cluster and is exercised
# manually. What's testable cluster-free:
#   - _resume_recreate_blocker: which sessions may be auto-recreated vs guided
#   - _resume_guide_command: the reconstructed 'sandbox run' invocation
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-resume"
TEST_DIR="$(mktemp -d /tmp/sandbox-resume-test-XXXXXX)"

fail() { echo "FAIL: $*" >&2; exit 1; }
cleanup() { rm -rf "${TEST_DIR}"; }
trap cleanup EXIT

# Pull in the resume helpers (and the domain/tier libs they call). bin/sandbox is
# source-guarded, so this defines its functions without running main.
# shellcheck disable=SC1090
source "${SANDBOX_ROOT}/bin/sandbox" >/dev/null 2>&1

# Override detect_platform so the macOS branch can be exercised on a Linux host
# (is_macos reads through it). Defaults to linux.
_set_platform() { eval "detect_platform() { echo '$1'; }"; }
_set_platform linux

# Write a synthetic session.json and echo its path.
mk_session() {
  local name="$1" json="$2"
  local p="${TEST_DIR}/${name}.json"
  printf '%s\n' "${json}" > "${p}"
  echo "${p}"
}

contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "${haystack}" == *"${needle}"* ]]; then
    pass "${label}"
  else
    fail "${label}: '${needle}' not found in: ${haystack}"
  fi
}

is_empty() {
  local label="$1" val="$2"
  if [[ -z "${val}" ]]; then pass "${label}"; else fail "${label}: expected empty, got '${val}'"; fi
}

test_blocker_allows_simple_sessions() {
  info "Testing recreatable sessions clear the blocker (tier 1/2, no profile, non-opencode)..."
  _set_platform linux
  local sj
  sj="$(mk_session tier1 '{"agent":"claude","tier":1,"profile":"","repos":[]}')"
  is_empty "tier1 claude recreatable" "$(_resume_recreate_blocker "${sj}")"
  sj="$(mk_session tier2 '{"agent":"codex","tier":2,"profile":"","repos":["/x/y"]}')"
  is_empty "tier2 codex recreatable" "$(_resume_recreate_blocker "${sj}")"
}

test_blocker_guides_the_rest() {
  info "Testing sessions needing unpersisted state are guided, not recreated..."
  _set_platform linux
  local sj
  sj="$(mk_session tier3 '{"agent":"claude","tier":3,"profile":"","repos":[]}')"
  contains "tier3 blocked" "$(_resume_recreate_blocker "${sj}")" "tier 3"
  sj="$(mk_session prof '{"agent":"claude","tier":2,"profile":"payments","repos":[]}')"
  contains "profile blocked" "$(_resume_recreate_blocker "${sj}")" "payments"
  sj="$(mk_session oc '{"agent":"opencode","tier":1,"profile":"","repos":[]}')"
  contains "opencode blocked" "$(_resume_recreate_blocker "${sj}")" "opencode"
  # macOS blocks even an otherwise-simple session.
  _set_platform macos
  sj="$(mk_session mac '{"agent":"claude","tier":1,"profile":"","repos":[]}')"
  contains "macOS blocked" "$(_resume_recreate_blocker "${sj}")" "macOS"
  _set_platform linux
}

test_guide_command_reconstructs_run() {
  info "Testing _resume_guide_command reconstructs the launch invocation..."
  _set_platform linux
  local sj cmd
  sj="$(mk_session guide '{"agent":"opencode","tier":2,"profile":"","repos":["/home/moo/app","/home/moo/lib"],"name":"payments-demo/opencode","allowed_domains":["totally-extra.example.com"]}')"
  cmd="$(_resume_guide_command "${sj}")"
  contains "names agent"        "${cmd}" "--agent opencode"
  contains "names tier"         "${cmd}" "--tier 2"
  contains "first repo"         "${cmd}" "--repo /home/moo/app"
  contains "second repo"        "${cmd}" "--repo /home/moo/lib"
  contains "session name"       "${cmd}" "--name 'payments-demo/opencode'"
  contains "extra allow-domain" "${cmd}" "--allow-domain totally-extra.example.com"
}

# recreate_session_pod must re-run the Tier 2 workspace launch gates and, on a
# gate refusal, abort BEFORE touching the cluster — resume must never relaunch a
# workspace a fresh 'sandbox run' would refuse (security review finding, #70).
test_recreate_reruns_gates_before_apply() {
  info "Testing recreate_session_pod re-runs the tier-2 gates and a refusal aborts before apply..."
  _set_platform linux
  local gatelog="${TEST_DIR}/gatelog" applied="${TEST_DIR}/applied"
  : > "${gatelog}"; : > "${applied}"

  SANDBOX_LOGS_DIR="${TEST_DIR}/logs"
  local sdir="${SANDBOX_LOGS_DIR}/ses-gate-test"
  mkdir -p "${sdir}" "${TEST_DIR}/repoA"
  printf '{"agent":"claude","tier":2,"name":"t","user":"u","repos":["%s"],"allowed_domains":[],"kube_api_cidr":"","kube_api_port":""}\n' \
    "${TEST_DIR}/repoA" > "${sdir}/session.json"

  # Stub cluster + build steps so nothing hits a real cluster; kubectl records
  # that an apply happened. resolve_* are pinned so the path is deterministic.
  prepare_agent_home() { :; }
  build_cilium_policy() { echo policy; }
  build_pod_manifest() { echo pod; }
  wait_for_pod() { :; }
  resolve_pod_name() { echo sandbox-x; }
  resolve_vetting_posture() { echo off; }
  resolve_inference_endpoint() { echo ""; }
  kubectl() { echo apply >> "${applied}"; }
  # Gate stubs record invocation; all pass for the first case.
  workspace_prescan()   { echo prescan >> "${gatelog}"; }
  check_masking_paths() { echo masking >> "${gatelog}"; }
  vetting_gate_repos()  { echo vetting >> "${gatelog}"; }
  secret_gate_repos()   { echo secret  >> "${gatelog}"; }

  # Case A — all gates pass: every gate runs, then the apply happens.
  ( recreate_session_pod "ses-gate-test" ) >/dev/null 2>&1 || true
  local ran; ran="$(tr '\n' ',' < "${gatelog}")"
  { grep -q prescan "${gatelog}" && grep -q masking "${gatelog}" \
    && grep -q vetting "${gatelog}" && grep -q secret "${gatelog}"; } \
    && pass "all four workspace gates run on recreate" || fail "missing gate(s): ${ran}"
  [[ -s "${applied}" ]] && pass "apply proceeds once gates pass" || fail "apply did not run when gates passed"

  # Case B — a gate refuses: apply must NOT run. The real gates fail closed via
  # die (exit), so the stub does the same; recreate_session_pod calls it as a
  # bare statement, so the exit aborts before any build/apply.
  : > "${applied}"
  secret_gate_repos() { die "secret gate refused (test)"; }
  ( recreate_session_pod "ses-gate-test" ) >/dev/null 2>&1 || true
  [[ ! -s "${applied}" ]] && pass "a gate refusal aborts before any cluster apply" \
    || fail "apply ran despite a gate refusal — resume would relaunch an ungated workspace"
}

# A pod that never becomes Ready must be torn down, not left orphaned in
# Pending/Running/Error for the operator to clean up by hand. recreate_session_pod
# runs wait_for_pod in a subshell and calls cmd_stop on failure.
test_recreate_tears_down_on_pod_failure() {
  info "Testing a recreated pod that fails to become Ready is torn down..."
  _set_platform linux
  local stoplog="${TEST_DIR}/stoplog"
  : > "${stoplog}"

  SANDBOX_LOGS_DIR="${TEST_DIR}/logs"
  local sdir="${SANDBOX_LOGS_DIR}/ses-fail-test"
  mkdir -p "${sdir}" "${TEST_DIR}/repoB"
  printf '{"agent":"claude","tier":2,"name":"t","user":"u","repos":["%s"],"allowed_domains":[],"kube_api_cidr":"","kube_api_port":""}\n' \
    "${TEST_DIR}/repoB" > "${sdir}/session.json"

  # Stub the build/cluster steps; gates all pass so the path reaches the wait.
  prepare_agent_home() { :; }
  build_cilium_policy() { echo policy; }
  build_pod_manifest() { echo pod; }
  resolve_pod_name() { echo sandbox-x; }
  resolve_vetting_posture() { echo off; }
  resolve_inference_endpoint() { echo ""; }
  kubectl() { :; }
  workspace_prescan()   { :; }
  check_masking_paths() { :; }
  vetting_gate_repos()  { :; }
  secret_gate_repos()   { :; }
  # The pod never becomes Ready: wait_for_pod exits non-zero (as the real one
  # does via exit 1). cmd_stop records that teardown ran.
  wait_for_pod() { return 1; }
  cmd_stop() { echo "stopped $1" >> "${stoplog}"; }

  ( recreate_session_pod "ses-fail-test" ) >/dev/null 2>&1 || true
  grep -q "stopped ses-fail-test" "${stoplog}" \
    && pass "failed pod triggers cmd_stop teardown" \
    || fail "pod-start failure did not tear down the session — pod would be orphaned"
}

main() {
  info "Running ${TEST_NAME} tests..."
  test_blocker_allows_simple_sessions
  test_blocker_guides_the_rest
  test_guide_command_reconstructs_run
  test_recreate_reruns_gates_before_apply
  test_recreate_tears_down_on_pod_failure
  echo "All ${TEST_NAME} tests passed."
}

main "$@"
