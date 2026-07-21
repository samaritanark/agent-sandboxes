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

# Build a session.json WITHOUT deduping allowed_domains, to simulate either an
# operator whose extras repeat a built-in domain or a session written before
# creation started deduping (bin/sandbox). Used to reproduce the "-1 new
# domain(s)" regression.
make_session_json_raw() {
  local sid="$1" agent="$2" tier="$3"
  shift 3
  local -a raw_domains=("$@")

  local log_dir="${SANDBOX_LOGS_DIR}/${sid}"
  mkdir -p "${log_dir}"

  local allowed
  allowed="$(printf '%s\n' "${raw_domains[@]+"${raw_domains[@]}"}" \
    | jq -R . | jq -s -c 'map(select(. != ""))')"

  jq -n \
    --arg id "${sid}" \
    --arg agent "${agent}" \
    --argjson tier "${tier}" \
    --argjson allowed "${allowed}" \
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
# Returns JSON: { full, extras, added } where `added` is the count of
# GENUINELY-new domains (matches cmd_allow's "Applied: N new domain(s)").
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

  local merged_full merged_extras added
  merged_full="$(jq -c -n \
    --argjson cur "${cur_arr}" \
    --argjson new "${new_arr}" \
    '($cur + $new) | unique')"
  merged_extras="$(jq -c -n \
    --argjson full "${merged_full}" \
    --argjson agent "${agent_arr}" \
    --argjson tier "${tier_arr}" \
    '($full - $agent - $tier)')"
  added="$(jq -n \
    --argjson cur "${cur_arr}" \
    --argjson new "${new_arr}" \
    '(($new | unique) - ($cur | unique)) | length')"

  jq -c -n \
    --argjson full "${merged_full}" \
    --argjson extras "${merged_extras}" \
    --argjson added "${added}" \
    '{full: $full, extras: $extras, added: $added}'
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
# Regression: "-1 new domain(s)" — a session.json carrying duplicates (an
# operator extra repeating a built-in, or a pre-dedup session) must NOT report
# a negative/zero delta when a genuinely-new domain is added, and the reported
# count is the count of GENUINELY-new domains — never merged_total - old_total.
###############################################################################
test_added_count_never_negative_with_dupes() {
  info "Testing added-count stays correct when session.json has duplicates..."

  # A raw session.json with a duplicate '*.gitea.com' pair AND 'gitea.com'
  # already present — exactly the shape that produced "-1 new domain(s)".
  local sj
  sj="$(make_session_json_raw ses-dup claude 2 \
    "*.gitea.com" "*.gitea.com" "gitea.com" "internal.example.com")"

  # Re-adding an already-allowed domain: 0 genuinely new (not -1).
  local out added
  out="$(allow_merge "${sj}" gitea.com)"
  added="$(jq -r '.added' <<<"${out}")"
  eq "re-adding an allowed domain → added 0 (not negative)" "0" "${added}"

  # And the merged set is deduped (the stray '*.gitea.com' collapses).
  local full_count distinct_count
  full_count="$(jq -r '.full | length' <<<"${out}")"
  distinct_count="$(jq -r '.full | unique | length' <<<"${out}")"
  eq "merged_full is deduplicated" "${distinct_count}" "${full_count}"

  # Adding a genuinely-new domain reports exactly 1, despite the dupes.
  out="$(allow_merge "${sj}" brand.new.example.com)"
  added="$(jq -r '.added' <<<"${out}")"
  eq "one genuinely-new domain → added 1" "1" "${added}"
}

###############################################################################
# Fix A: session creation dedups the agent + tier + extras union. This mirrors
# the exact pipeline in bin/sandbox (cmd_run) — repeated extras and extras that
# collide with a built-in must collapse to one entry each, preserving first
# occurrence.
###############################################################################
test_creation_dedups_domains() {
  info "Testing session-creation dedup (mirror of bin/sandbox all_domains)..."

  # shellcheck disable=SC1091
  source "${SANDBOX_ROOT}/lib/platform.sh"

  # An extra that repeats a built-in claude domain, plus a self-repeat.
  local -a agent_domains=() tier_domains=()
  read_into_array agent_domains < <(get_agent_domains claude)
  read_into_array tier_domains < <(get_tier_domains 2)
  local -a opt_allow_domains=("claude.ai" "extra.example.com" "extra.example.com")

  local -a all_domains=(
    "${agent_domains[@]+"${agent_domains[@]}"}"
    "${tier_domains[@]+"${tier_domains[@]}"}"
    "${opt_allow_domains[@]+"${opt_allow_domains[@]}"}")
  local raw_count="${#all_domains[@]}"

  # The dedup pipeline copied verbatim from bin/sandbox.
  read_into_array all_domains < <(
    printf '%s\n' "${all_domains[@]+"${all_domains[@]}"}" | awk 'NF && !seen[$0]++')
  local deduped_count="${#all_domains[@]}"

  if [[ "${deduped_count}" -lt "${raw_count}" ]]; then
    pass "duplicate extras collapsed (${raw_count} → ${deduped_count})"
  else
    fail "expected dedup to shrink the list (${raw_count} → ${deduped_count})"
  fi

  # No value appears twice. Use byte-exact dedup (awk keyed on the whole line):
  # `sort -u` under a UTF-8 locale collates '*.claude.ai' and 'claude.ai' as
  # equal and would undercount, masking whether the real dedup worked.
  local uniq_count
  uniq_count="$(printf '%s\n' "${all_domains[@]}" | awk '!seen[$0]++' | wc -l | tr -d ' ')"
  eq "no duplicates remain after creation dedup" "${uniq_count}" "${deduped_count}"

  # 'extra.example.com' survives exactly once.
  local occ
  occ="$(printf '%s\n' "${all_domains[@]}" | grep -cx 'extra.example.com')"
  eq "repeated extra kept exactly once" "1" "${occ}"
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
  test_added_count_never_negative_with_dupes
  test_creation_dedups_domains
  test_cli_no_args
  test_cli_missing_add_domain
  test_cli_missing_session
  test_cli_blocked_domain_rejected

  echo ""
  echo "All allow tests passed."
}

main "$@"
