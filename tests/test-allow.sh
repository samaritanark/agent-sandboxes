#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-allow.sh — 'sandbox allow' hot-reload tests (cluster-free parts)
#
# The kubectl apply path needs a live cluster and is exercised manually.
# What's testable cluster-free:
#   - argument parsing (missing session-id, missing --add-domain)
#   - session.json must exist (pointer to a real session)
#   - blocked-destinations check fires on each --add-domain
#   - the policy-rebuild domain math: existing ∪ new − agent − tier
#   - session.json's allowed_domains is updated (no-op when nothing new)
#
# We can't run cmd_allow end-to-end because it calls ensure_cluster_ready
# and kubectl apply. Instead we exercise the underlying jq pipeline that
# computes the new domain set against a synthetic session.json.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-allow"
TEST_DIR="$(mktemp -d /tmp/sandbox-allow-test-XXXXXX)"
SANDBOX_LOGS_DIR="${TEST_DIR}/logs"

fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
  rm -rf "${TEST_DIR}"
}
trap cleanup EXIT

# shellcheck disable=SC1091
source "${SANDBOX_ROOT}/lib/agents.sh"
source "${SANDBOX_ROOT}/lib/tier.sh"

eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    pass "${label}"
  else
    fail "${label}: expected '${expected}', got '${actual}'"
  fi
}

# Build a minimal session.json for the merge logic to operate on.
make_session_json() {
  local sid="$1"
  local agent="$2"
  local tier="$3"
  shift 3
  local -a current_extras=("$@")

  local log_dir="${SANDBOX_LOGS_DIR}/${sid}"
  mkdir -p "${log_dir}"

  local agent_arr tier_arr extras_arr all_arr
  agent_arr="$(get_agent_domains "${agent}" | jq -R . | jq -s -c .)"
  tier_arr="$(get_tier_domains "${tier}" | jq -R . | jq -s -c .)"
  extras_arr="$(printf '%s\n' "${current_extras[@]+"${current_extras[@]}"}" \
    | jq -R . | jq -s -c 'map(select(. != ""))')"
  all_arr="$(jq -c -n \
    --argjson agent "${agent_arr}" \
    --argjson tier "${tier_arr}" \
    --argjson extras "${extras_arr}" \
    '$agent + $tier + $extras | unique')"

  jq -n \
    --arg id "${sid}" \
    --arg agent "${agent}" \
    --argjson tier "${tier}" \
    --argjson allowed "${all_arr}" \
    '{
      id: $id,
      agent: $agent,
      tier: $tier,
      kube_api_cidr: "",
      kube_api_port: "",
      allowed_domains: $allowed
    }' > "${log_dir}/session.json"

  echo "${log_dir}/session.json"
}

# Mirror of the merge pipeline inside cmd_allow (we don't have a single
# extracted function for it — the merge is inline in bin/sandbox).
# Returns JSON: { merged_full, merged_extras }
allow_merge() {
  local session_json="$1"
  shift
  local -a new=("$@")

  local agent tier
  agent="$(jq -r '.agent' "${session_json}")"
  tier="$(jq -r '.tier' "${session_json}")"

  local agent_arr tier_arr new_arr cur_arr
  agent_arr="$(get_agent_domains "${agent}" | jq -R . | jq -s -c .)"
  tier_arr="$(get_tier_domains "${tier}" | jq -R . | jq -s -c .)"
  new_arr="$(printf '%s\n' "${new[@]+"${new[@]}"}" | jq -R . | jq -s -c 'map(select(. != ""))')"
  cur_arr="$(jq '.allowed_domains' "${session_json}")"

  local merged_full merged_extras
  merged_full="$(jq -c -n \
    --argjson cur "${cur_arr}" \
    --argjson new "${new_arr}" \
    '($cur + $new) | unique')"
  merged_extras="$(jq -c -n \
    --argjson full "${merged_full}" \
    --argjson agent "${agent_arr}" \
    --argjson tier "${tier_arr}" \
    '($full - $agent - $tier)')"

  jq -c -n \
    --argjson full "${merged_full}" \
    --argjson extras "${merged_extras}" \
    '{full: $full, extras: $extras}'
}

###############################################################################
# Merge logic — the heart of cmd_allow
###############################################################################
test_merge_adds_new_domain() {
  info "Testing merge appends a new domain..."

  local sj
  sj="$(make_session_json ses-a claude 2 internal.example.com)"
  local out new_count
  out="$(allow_merge "${sj}" go.private.example.com)"
  new_count="$(jq -r '.full | length' <<<"${out}")"

  local existing_count
  existing_count="$(jq -r '.allowed_domains | length' "${sj}")"
  eq "merged_full grows by 1" \
     "$(( existing_count + 1 ))" "${new_count}"

  # extras must contain both internal.example.com and the new one,
  # and NOT contain any agent/tier domains.
  if jq -r '.extras[]' <<<"${out}" | grep -qx "go.private.example.com"; then
    pass "new domain in extras"
  else
    fail "new domain missing from extras"
  fi
  if jq -r '.extras[]' <<<"${out}" | grep -qx "internal.example.com"; then
    pass "existing extra preserved"
  else
    fail "existing extra missing from extras"
  fi
  if jq -r '.extras[]' <<<"${out}" | grep -qx "github.com"; then
    fail "tier domain leaked into extras (would cause duplicate matchName)"
  else
    pass "agent/tier domains stripped from extras"
  fi
}

test_merge_dedups_duplicate_add() {
  info "Testing merge dedups when --add-domain is already allowed..."

  local sj
  sj="$(make_session_json ses-b claude 2 internal.example.com)"
  local existing_count
  existing_count="$(jq -r '.allowed_domains | length' "${sj}")"

  # Try to add a domain that's already in allowed_domains (an agent domain).
  local out new_count
  out="$(allow_merge "${sj}" claude.ai)"
  new_count="$(jq -r '.full | length' <<<"${out}")"
  eq "duplicate add → no growth" "${existing_count}" "${new_count}"

  # Also: add an existing extra
  out="$(allow_merge "${sj}" internal.example.com)"
  new_count="$(jq -r '.full | length' <<<"${out}")"
  eq "duplicate extra add → no growth" "${existing_count}" "${new_count}"
}

test_merge_multiple_new() {
  info "Testing merge with multiple new domains at once..."

  local sj
  sj="$(make_session_json ses-c claude 2)"
  local existing_count
  existing_count="$(jq -r '.allowed_domains | length' "${sj}")"

  local out new_count
  out="$(allow_merge "${sj}" a.example.com b.example.com c.example.com)"
  new_count="$(jq -r '.full | length' <<<"${out}")"
  eq "three new domains → +3" "$(( existing_count + 3 ))" "${new_count}"
}

###############################################################################
# CLI-level — only the argument-validation paths (no cluster needed)
###############################################################################
test_cli_no_args() {
  info "Testing 'sandbox allow' with no args prints help..."

  # usage_allow exits 0 with help text
  local out
  if out="$(SANDBOX_LOGS_DIR="${SANDBOX_LOGS_DIR}" "${SANDBOX_ROOT}/bin/sandbox" allow 2>&1)"; then
    if echo "${out}" | grep -q 'sandbox allow'; then
      pass "no-args invocation prints help"
    else
      fail "no-args invocation did not look like help text: ${out}"
    fi
  else
    fail "no-args invocation exited non-zero (expected help exit 0)"
  fi
}

test_cli_missing_add_domain() {
  info "Testing 'sandbox allow <id>' with no --add-domain..."

  local out
  if out="$(SANDBOX_LOGS_DIR="${SANDBOX_LOGS_DIR}" "${SANDBOX_ROOT}/bin/sandbox" allow ses-fake 2>&1)"; then
    fail "expected non-zero exit; got: ${out}"
  else
    if echo "${out}" | grep -q '\-\-add-domain'; then
      pass "missing --add-domain produces a helpful error"
    else
      fail "error message did not mention --add-domain: ${out}"
    fi
  fi
}

test_cli_missing_session() {
  info "Testing 'sandbox allow <missing-id>' fails with no session.json..."

  local out
  if out="$(SANDBOX_LOGS_DIR="${SANDBOX_LOGS_DIR}" "${SANDBOX_ROOT}/bin/sandbox" \
            allow ses-never-existed --add-domain x.example.com 2>&1)"; then
    fail "expected non-zero exit; got: ${out}"
  else
    if echo "${out}" | grep -q 'No session.json'; then
      pass "missing session.json produces a clear error"
    else
      fail "error message did not mention session.json: ${out}"
    fi
  fi
}

test_cli_blocked_domain_rejected() {
  info "Testing 'sandbox allow <id> --add-domain pastebin.com' is rejected..."

  local sid="ses-blocktest"
  make_session_json "${sid}" claude 2 internal.example.com >/dev/null

  local out
  if out="$(SANDBOX_LOGS_DIR="${SANDBOX_LOGS_DIR}" "${SANDBOX_ROOT}/bin/sandbox" \
            allow "${sid}" --add-domain pastebin.com 2>&1)"; then
    fail "expected non-zero exit for blocked domain; got: ${out}"
  else
    if echo "${out}" | grep -qi 'block'; then
      pass "blocked-destinations check fires on --add-domain"
    else
      fail "error did not mention 'block': ${out}"
    fi
  fi

  # session.json must remain unchanged (no partial update on rejection)
  local len_now
  len_now="$(jq -r '.allowed_domains | length' \
    "${SANDBOX_LOGS_DIR}/${sid}/session.json")"
  local len_expected
  len_expected="$(get_agent_domains claude | wc -l | tr -d ' ')"
  len_expected="$(( len_expected + $(get_tier_domains 2 | wc -l | tr -d ' ') + 1 ))"
  eq "session.json unchanged after rejection" "${len_expected}" "${len_now}"
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""
  echo "Test logs dir: ${SANDBOX_LOGS_DIR}"
  echo ""

  test_merge_adds_new_domain
  test_merge_dedups_duplicate_add
  test_merge_multiple_new
  test_cli_no_args
  test_cli_missing_add_domain
  test_cli_missing_session
  test_cli_blocked_domain_rejected

  echo ""
  echo "All allow tests passed."
}

main "$@"
