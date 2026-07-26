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

main() {
  info "Running ${TEST_NAME} tests..."
  test_blocker_allows_simple_sessions
  test_blocker_guides_the_rest
  test_guide_command_reconstructs_run
  echo "All ${TEST_NAME} tests passed."
}

main "$@"
