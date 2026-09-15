#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-teardown-reminder.sh — warn-only detector for sessions that ended
# without teardown (issue #94 Item 1), cluster-free.
#
# A node-pressure eviction (or a teardown that never completed) leaves a session
# whose session.json has no end_time while its credential Secrets stay live (the
# pod's ownerReference GC only fires on pod DELETION, not eviction). `sandbox
# list` should remind the operator to run `sandbox stop`. What's testable
# cluster-free:
#   - _teardown_reminder_reason: the pure predicate (end_time/phase/age/grace)
#   - warn_untorndown_sessions: end-to-end over fixture sessions with a mocked
#     kubectl, asserting exactly which sessions are flagged
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$(mktemp -d /tmp/sandbox-teardown-reminder-test-XXXXXX)"
cleanup() { rm -rf "${TEST_DIR}"; }
trap cleanup EXIT

# bin/sandbox is source-guarded, so this defines its functions (including
# _teardown_reminder_reason / warn_untorndown_sessions and the warn/is_macos
# helpers it relies on) without running main.
# shellcheck disable=SC1090
source "${SANDBOX_ROOT}/bin/sandbox" >/dev/null 2>&1

SANDBOX_NAMESPACE="sandbox"

expect_empty() {
  local label="$1" val="$2"
  if [[ -z "${val}" ]]; then pass "${label}"; else fail "${label}: expected no reminder, got '${val}'"; fi
}
expect_reason() {
  local label="$1" val="$2"
  if [[ -n "${val}" ]]; then pass "${label}"; else fail "${label}: expected a reminder, got none"; fi
}
contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "${haystack}" == *"${needle}"* ]]; then pass "${label}"
  else fail "${label}: '${needle}' not found in: ${haystack}"; fi
}
not_contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "${haystack}" != *"${needle}"* ]]; then pass "${label}"
  else fail "${label}: '${needle}' unexpectedly present in: ${haystack}"; fi
}

###############################################################################
# 1. Pure predicate _teardown_reminder_reason(end_time, phase, age, grace)
###############################################################################
test_predicate() {
  info "Testing _teardown_reminder_reason across end_time/phase/age combinations..."
  local grace=120

  # A stamped end_time means cmd_stop ran — never remind, whatever the phase.
  expect_empty "stopped + Failed → no reminder" \
    "$(_teardown_reminder_reason "2026-09-15T00:00:00Z" "Failed" 9999 "${grace}")"
  expect_empty "stopped + absent → no reminder" \
    "$(_teardown_reminder_reason "2026-09-15T00:00:00Z" "absent" 9999 "${grace}")"

  # No end_time + a live/launching/detached pod → healthy, never remind.
  expect_empty "no end_time + Running (detached keep-alive) → no reminder" \
    "$(_teardown_reminder_reason "" "Running" 9999 "${grace}")"
  expect_empty "no end_time + Pending (launching) → no reminder" \
    "$(_teardown_reminder_reason "" "Pending" 9999 "${grace}")"
  expect_empty "no end_time + Succeeded → no reminder" \
    "$(_teardown_reminder_reason "" "Succeeded" 9999 "${grace}")"
  expect_empty "no end_time + Unknown → no reminder" \
    "$(_teardown_reminder_reason "" "Unknown" 9999 "${grace}")"
  # jq renders a missing end_time as the string "null" — treat it as absent too.
  expect_empty "literal null end_time + Running → no reminder" \
    "$(_teardown_reminder_reason "null" "Running" 9999 "${grace}")"

  # No end_time + Failed (evicted/crashed) → always remind, regardless of age.
  expect_reason "no end_time + Failed (old) → reminder" \
    "$(_teardown_reminder_reason "" "Failed" 9999 "${grace}")"
  expect_reason "no end_time + Failed (fresh) → reminder" \
    "$(_teardown_reminder_reason "" "Failed" 1 "${grace}")"
  contains "Failed reminder names credentials" \
    "$(_teardown_reminder_reason "" "Failed" 9999 "${grace}")" "credentials not revoked"

  # No end_time + absent: suppressed inside the launch grace window, flagged
  # once older than it (the launch race — session.json is written before the pod
  # exists, so a still-launching session reads as absent+no-end_time).
  expect_empty "no end_time + absent (fresh, within grace) → no reminder" \
    "$(_teardown_reminder_reason "" "absent" 5 "${grace}")"
  expect_reason "no end_time + absent (older than grace) → reminder" \
    "$(_teardown_reminder_reason "" "absent" 300 "${grace}")"
  # Boundary: age == grace is not "less than", so it flags.
  expect_reason "no end_time + absent (age == grace) → reminder" \
    "$(_teardown_reminder_reason "" "absent" 120 "${grace}")"
  # grace=0 disables the suppression entirely.
  expect_reason "no end_time + absent (grace 0) → reminder" \
    "$(_teardown_reminder_reason "" "absent" 0 0)"
}

###############################################################################
# 2. warn_untorndown_sessions over fixture sessions with a mocked kubectl.
#
# The mock decides pod existence/phase from the pod name: *running* → Running,
# *failed* → Failed, *absent* → not found (get pod exits non-zero).
###############################################################################
kubectl() {
  local pod="" a
  # The pod name is the sole `sandbox-*` argument in `get pod -n <ns> <name>`.
  for a in "$@"; do
    case "${a}" in sandbox-*) pod="${a}" ;; esac
  done
  case "${pod}" in
    *absent*) return 1 ;;
    *failed*) [[ "$*" == *jsonpath* ]] && echo "Failed"; return 0 ;;
    *running*) [[ "$*" == *jsonpath* ]] && echo "Running"; return 0 ;;
    *) [[ "$*" == *jsonpath* ]] && echo "Unknown"; return 0 ;;
  esac
}

mk_fixture_session() {
  local sid="$1" json="$2"
  mkdir -p "${TEST_DIR}/logs/${sid}"
  printf '%s\n' "${json}" > "${TEST_DIR}/logs/${sid}/session.json"
}

test_warn_untorndown_sessions() {
  info "Testing warn_untorndown_sessions flags only abnormally-ended sessions..."
  SANDBOX_LOGS_DIR="${TEST_DIR}/logs"

  # Detached --keep-alive session: no end_time, pod Running → must NOT flag.
  mk_fixture_session "ses-healthy" \
    '{"pod_name":"sandbox-running-1","end_time":null}'
  # Cleanly stopped session → must NOT flag (has end_time), even if pod Failed.
  mk_fixture_session "ses-stopped" \
    '{"pod_name":"sandbox-failed-2","end_time":"2026-09-15T01:00:00Z"}'
  # Evicted/crashed session: no end_time, pod Failed → MUST flag.
  mk_fixture_session "ses-evicted" \
    '{"pod_name":"sandbox-failed-3","end_time":null}'
  # Session with no pod_name recorded (never got far enough) → must NOT flag.
  mk_fixture_session "ses-nopod" \
    '{"end_time":null}'

  local out
  out="$(warn_untorndown_sessions 2>&1 >/dev/null)"

  contains "evicted session is flagged" "${out}" "ses-evicted"
  contains "flag names the stop command" "${out}" "sandbox stop ses-evicted"
  not_contains "healthy detached session not flagged" "${out}" "ses-healthy"
  not_contains "cleanly stopped session not flagged" "${out}" "ses-stopped"
  not_contains "session without pod_name not flagged" "${out}" "ses-nopod"
}

test_absent_pod_launch_race() {
  info "Testing an absent pod is suppressed within the launch grace, flagged after..."
  SANDBOX_LOGS_DIR="${TEST_DIR}/logs-absent"
  mkdir -p "${SANDBOX_LOGS_DIR}"
  mk_fixture_session_in() {
    local base="$1" sid="$2" json="$3"
    mkdir -p "${base}/${sid}"
    printf '%s\n' "${json}" > "${base}/${sid}/session.json"
  }
  mk_fixture_session_in "${SANDBOX_LOGS_DIR}" "ses-launching" \
    '{"pod_name":"sandbox-absent-9","end_time":null}'

  # Freshly written session.json (age ~0) with the default grace → still
  # launching, must NOT flag.
  local out
  out="$(SANDBOX_TEARDOWN_REMINDER_GRACE=120 warn_untorndown_sessions 2>&1 >/dev/null)"
  not_contains "fresh absent pod (within grace) not flagged" "${out}" "ses-launching"

  # grace=0 removes the suppression → the same absent pod IS flagged.
  out="$(SANDBOX_TEARDOWN_REMINDER_GRACE=0 warn_untorndown_sessions 2>&1 >/dev/null)"
  contains "absent pod flagged once grace is 0" "${out}" "ses-launching"
}

test_cluster_unreachable() {
  info "Testing an unreachable cluster suppresses reminders (no false 'pod gone' storm)..."
  SANDBOX_LOGS_DIR="${TEST_DIR}/logs-unreachable"
  mkdir -p "${SANDBOX_LOGS_DIR}/ses-orphan"
  printf '%s\n' '{"pod_name":"sandbox-failed-x","end_time":null}' \
    > "${SANDBOX_LOGS_DIR}/ses-orphan/session.json"

  # Simulate a fully unreachable API server: every kubectl call fails.
  kubectl() { return 1; }

  local out
  out="$(SANDBOX_TEARDOWN_REMINDER_GRACE=0 warn_untorndown_sessions 2>&1 >/dev/null)"
  not_contains "no reminders when the cluster is unreachable" "${out}" "ses-orphan"
}

###############################################################################
# 3. _session_json_age_seconds returns a sane non-negative integer.
###############################################################################
test_age_seconds() {
  info "Testing _session_json_age_seconds..."
  local f="${TEST_DIR}/age.json"
  printf '{}' > "${f}"
  local age
  age="$(_session_json_age_seconds "${f}")"
  if [[ "${age}" =~ ^[0-9]+$ ]] && [[ "${age}" -lt 5 ]]; then
    pass "fresh file age is a small non-negative integer (${age})"
  else
    fail "age not a small integer: '${age}'"
  fi
  # Missing file must fail safe to 0 (treated as fresh), not error out.
  age="$(_session_json_age_seconds "${TEST_DIR}/does-not-exist.json")"
  if [[ "${age}" =~ ^[0-9]+$ ]]; then
    pass "missing file age fails safe to an integer (${age})"
  else
    fail "missing file age not an integer: '${age}'"
  fi
}

info "Running test-teardown-reminder tests..."
test_predicate
test_warn_untorndown_sessions
test_absent_pod_launch_race
test_age_seconds
# Runs last: it replaces the phase-based kubectl mock with an always-fail one.
test_cluster_unreachable
echo "All test-teardown-reminder tests passed."
