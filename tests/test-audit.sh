#!/usr/bin/env bash
# tests/test-audit.sh — Audit log tests
# Verifies: session.json is written, contains required fields, end_time is set on exit
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-audit"
TEST_LOG_DIR="$(mktemp -d /tmp/sandbox-audit-test-XXXXXX)"

fail() { echo "FAIL: $*" >&2; exit 1; }

# Source audit library
source "${SANDBOX_ROOT}/lib/platform.sh"
source "${SANDBOX_ROOT}/lib/agents.sh"
source "${SANDBOX_ROOT}/lib/tier.sh"
source "${SANDBOX_ROOT}/lib/audit.sh"

cleanup() {
  rm -rf "${TEST_LOG_DIR}"
}
trap cleanup EXIT

###############################################################################
# Test: audit_write_session_json produces valid JSON with required fields
###############################################################################
test_session_json_structure() {
  info "Testing session.json creation..."

  local session_id="ses-20260401-120000-abcd"
  local log_dir="${TEST_LOG_DIR}/${session_id}"
  mkdir -p "${log_dir}"

  audit_write_session_json \
    "${log_dir}" \
    "${session_id}" \
    "claude" \
    "2" \
    "testuser" \
    "/tmp/test-repo" \
    "my-test-session" \
    "sandbox-claude-abcd" \
    "2026-04-01T12:00:00Z" \
    "api.anthropic.com" "claude.ai" "github.com"

  local json_file="${log_dir}/session.json"

  if [[ ! -f "${json_file}" ]]; then
    fail "session.json was not created"
  fi

  # Validate JSON
  if ! jq . "${json_file}" &>/dev/null; then
    fail "session.json is not valid JSON"
  fi
  pass "session.json is valid JSON"

  # Check required fields
  local required_fields=("id" "agent" "tier" "user" "start_time" "allowed_domains" "credential_type" "retention_days")
  for field in "${required_fields[@]}"; do
    local value
    value="$(jq -r ".${field} // \"MISSING\"" "${json_file}")"
    if [[ "${value}" == "MISSING" ]] || [[ "${value}" == "null" ]]; then
      fail "session.json missing required field: ${field}"
    else
      pass "session.json has field '${field}': ${value}"
    fi
  done

  # Check end_time starts null
  local end_time
  end_time="$(jq -r '.end_time' "${json_file}")"
  if [[ "${end_time}" == "null" ]]; then
    pass "session.json end_time is null (session running)"
  else
    fail "session.json end_time should be null at start, got: ${end_time}"
  fi

  # Check agent-specific fields
  local agent
  agent="$(jq -r '.agent' "${json_file}")"
  [[ "${agent}" == "claude" ]] && pass "agent field correct: claude" || fail "agent field wrong: ${agent}"

  local tier
  tier="$(jq -r '.tier' "${json_file}")"
  [[ "${tier}" == "2" ]] && pass "tier field correct: 2" || fail "tier field wrong: ${tier}"

  local cred_type
  cred_type="$(jq -r '.credential_type' "${json_file}")"
  [[ "${cred_type}" == "oauth" ]] && pass "credential_type correct: oauth" || fail "credential_type wrong: ${cred_type}"

  local retention
  retention="$(jq -r '.retention_days' "${json_file}")"
  [[ "${retention}" == "90" ]] && pass "retention_days correct: 90" || fail "retention_days wrong: ${retention}"

  local domains
  domains="$(jq -r '.allowed_domains | length' "${json_file}")"
  [[ "${domains}" -eq 3 ]] && pass "allowed_domains has 3 entries" || fail "allowed_domains has ${domains} entries (expected 3)"
}

###############################################################################
# Test: audit_update_end_time sets end_time correctly
###############################################################################
test_end_time_update() {
  info "Testing end_time update..."

  local session_id="ses-20260401-130000-efgh"
  local log_dir="${TEST_LOG_DIR}/${session_id}"
  mkdir -p "${log_dir}"

  audit_write_session_json \
    "${log_dir}" \
    "${session_id}" \
    "opencode" \
    "1" \
    "testuser" \
    "" \
    "" \
    "sandbox-opencode-efgh" \
    "2026-04-01T13:00:00Z" \
    "opencode-endpoint.example.test"

  local end_time="2026-04-01T13:45:30Z"
  audit_update_end_time "${log_dir}" "${end_time}"

  local stored_end
  stored_end="$(jq -r '.end_time' "${log_dir}/session.json")"

  if [[ "${stored_end}" == "${end_time}" ]]; then
    pass "end_time correctly set to ${end_time}"
  else
    fail "end_time should be '${end_time}' but got '${stored_end}'"
  fi
}

###############################################################################
# Test: Tier 3 session gets retention_days = 180
###############################################################################
test_tier3_retention() {
  info "Testing Tier 3 retention days..."

  local session_id="ses-20260401-140000-ijkl"
  local log_dir="${TEST_LOG_DIR}/${session_id}"
  mkdir -p "${log_dir}"

  audit_write_session_json \
    "${log_dir}" \
    "${session_id}" \
    "claude" \
    "3" \
    "testuser" \
    "/tmp/test-repo" \
    "" \
    "sandbox-claude-ijkl" \
    "2026-04-01T14:00:00Z" \
    "api.anthropic.com"

  local retention
  retention="$(jq -r '.retention_days' "${log_dir}/session.json")"

  if [[ "${retention}" == "180" ]]; then
    pass "Tier 3 retention_days = 180 (correct)"
  else
    fail "Tier 3 retention_days should be 180, got: ${retention}"
  fi
}

###############################################################################
# Test: audit_list_sessions finds session directories
###############################################################################
test_list_sessions() {
  info "Testing audit_list_sessions..."

  local found
  found="$(audit_list_sessions "${TEST_LOG_DIR}" | wc -l | tr -d ' ')"

  # Should find the sessions we created above
  if [[ "${found}" -ge 3 ]]; then
    pass "audit_list_sessions found ${found} sessions"
  else
    fail "audit_list_sessions found only ${found} sessions (expected >= 3)"
  fi
}

###############################################################################
# Test: audit_capture_transcript copies only transcripts modified during the
# session — files that predate the session.json reference are excluded.
###############################################################################
test_capture_transcript_claude() {
  info "Testing transcript capture (claude)..."

  local session_id="ses-20260401-150000-trcl"
  local log_dir="${TEST_LOG_DIR}/${session_id}"
  local agent_home="${TEST_LOG_DIR}/home-claude"
  mkdir -p "${log_dir}" "${agent_home}/projects/-workspace"

  # session.json is the '-newer' reference; pin its mtime to mid-window.
  audit_write_session_json \
    "${log_dir}" "${session_id}" "claude" "1" "testuser" "" "" "sandbox-claude-trcl" \
    "2026-04-01T15:00:00Z" "api.anthropic.com"
  touch -d "2026-04-01T15:00:00" "${log_dir}/session.json"

  # A transcript from an earlier session (must be excluded).
  echo '{"old":true}' > "${agent_home}/projects/-workspace/old-session.jsonl"
  touch -d "2026-04-01T14:00:00" "${agent_home}/projects/-workspace/old-session.jsonl"

  # This session's transcript (must be captured).
  echo '{"new":true}' > "${agent_home}/projects/-workspace/this-session.jsonl"
  touch -d "2026-04-01T15:30:00" "${agent_home}/projects/-workspace/this-session.jsonl"

  audit_capture_transcript "${log_dir}" "claude" "${agent_home}"

  [[ -f "${log_dir}/transcript/this-session.jsonl" ]] \
    && pass "captured the in-window claude transcript" \
    || fail "in-window claude transcript was not captured"

  [[ ! -e "${log_dir}/transcript/old-session.jsonl" ]] \
    && pass "excluded the pre-session claude transcript" \
    || fail "pre-session transcript leaked into the capture"

  local got
  got="$(cat "${log_dir}/transcript/this-session.jsonl")"
  [[ "${got}" == '{"new":true}' ]] \
    && pass "captured transcript content is intact" \
    || fail "captured transcript content was altered: ${got}"
}

###############################################################################
# Test: codex transcripts (sessions/YYYY/MM/DD/rollout-*.jsonl) are captured.
###############################################################################
test_capture_transcript_codex() {
  info "Testing transcript capture (codex)..."

  local session_id="ses-20260401-160000-trcx"
  local log_dir="${TEST_LOG_DIR}/${session_id}"
  local agent_home="${TEST_LOG_DIR}/home-codex"
  mkdir -p "${log_dir}" "${agent_home}/sessions/2026/04/01"

  audit_write_session_json \
    "${log_dir}" "${session_id}" "codex" "1" "testuser" "" "" "sandbox-codex-trcx" \
    "2026-04-01T16:00:00Z" "api.openai.com"
  touch -d "2026-04-01T16:00:00" "${log_dir}/session.json"

  local rollout="${agent_home}/sessions/2026/04/01/rollout-2026-04-01T16-05-00-abc.jsonl"
  echo '{"codex":true}' > "${rollout}"
  touch -d "2026-04-01T16:05:00" "${rollout}"

  audit_capture_transcript "${log_dir}" "codex" "${agent_home}"

  [[ -f "${log_dir}/transcript/rollout-2026-04-01T16-05-00-abc.jsonl" ]] \
    && pass "captured the codex rollout transcript" \
    || fail "codex rollout transcript was not captured"
}

###############################################################################
# Test: opencode storage subtree is captured with its layout preserved.
###############################################################################
test_capture_transcript_opencode() {
  info "Testing transcript capture (opencode)..."

  local session_id="ses-20260401-170000-trco"
  local log_dir="${TEST_LOG_DIR}/${session_id}"
  local agent_home="${TEST_LOG_DIR}/home-opencode"
  mkdir -p "${log_dir}" "${agent_home}/storage/message/ses_abc"

  audit_write_session_json \
    "${log_dir}" "${session_id}" "opencode" "1" "testuser" "" "" "sandbox-opencode-trco" \
    "2026-04-01T17:00:00Z" "opencode-endpoint.example.test"
  touch -d "2026-04-01T17:00:00" "${log_dir}/session.json"

  local msg="${agent_home}/storage/message/ses_abc/msg-1.json"
  echo '{"opencode":true}' > "${msg}"
  touch -d "2026-04-01T17:10:00" "${msg}"

  audit_capture_transcript "${log_dir}" "opencode" "${agent_home}"

  [[ -f "${log_dir}/transcript/message/ses_abc/msg-1.json" ]] \
    && pass "captured opencode storage file with layout preserved" \
    || fail "opencode storage subtree was not captured correctly"
}

###############################################################################
# Test: a session with no in-window transcript produces no transcript dir and
# does not error.
###############################################################################
test_capture_transcript_no_match() {
  info "Testing transcript capture with no matching files..."

  local session_id="ses-20260401-180000-trnm"
  local log_dir="${TEST_LOG_DIR}/${session_id}"
  local agent_home="${TEST_LOG_DIR}/home-empty"
  mkdir -p "${log_dir}" "${agent_home}/projects/-workspace"

  audit_write_session_json \
    "${log_dir}" "${session_id}" "claude" "1" "testuser" "" "" "sandbox-claude-trnm" \
    "2026-04-01T18:00:00Z" "api.anthropic.com"
  touch -d "2026-04-01T18:00:00" "${log_dir}/session.json"

  # Only a stale transcript exists.
  echo '{"old":true}' > "${agent_home}/projects/-workspace/stale.jsonl"
  touch -d "2026-04-01T17:00:00" "${agent_home}/projects/-workspace/stale.jsonl"

  audit_capture_transcript "${log_dir}" "claude" "${agent_home}"

  [[ ! -d "${log_dir}/transcript" ]] \
    && pass "no transcript directory created when nothing matches" \
    || fail "transcript directory created despite no in-window files"
}

###############################################################################
# Test: audit_record_agent_session_id writes the pinned ID into session.json.
###############################################################################
test_record_agent_session_id() {
  info "Testing agent_session_id recording..."

  local session_id="ses-20260401-190000-trid"
  local log_dir="${TEST_LOG_DIR}/${session_id}"
  mkdir -p "${log_dir}"

  audit_write_session_json \
    "${log_dir}" "${session_id}" "claude" "1" "testuser" "" "" "sandbox-claude-trid" \
    "2026-04-01T19:00:00Z" "api.anthropic.com"

  # Field starts null.
  local before
  before="$(jq -r '.agent_session_id' "${log_dir}/session.json")"
  [[ "${before}" == "null" ]] \
    && pass "agent_session_id starts null" \
    || fail "agent_session_id should start null, got: ${before}"

  audit_record_agent_session_id "${log_dir}" "11111111-2222-4333-8444-555555555555"
  local after
  after="$(jq -r '.agent_session_id' "${log_dir}/session.json")"
  [[ "${after}" == "11111111-2222-4333-8444-555555555555" ]] \
    && pass "agent_session_id recorded correctly" \
    || fail "agent_session_id wrong: ${after}"
}

###############################################################################
# Test: with a pinned conversation ID, capture copies exactly that file and is
# immune to overlap — a second session's transcript modified in the same window
# is NOT captured. This is the property the mtime fallback cannot guarantee.
###############################################################################
test_capture_transcript_claude_pinned() {
  info "Testing transcript capture (claude, pinned ID, concurrent sessions)..."

  local session_id="ses-20260401-200000-trpn"
  local log_dir="${TEST_LOG_DIR}/${session_id}"
  local agent_home="${TEST_LOG_DIR}/home-claude-pinned"
  local mine="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
  local theirs="ffffffff-0000-4111-8222-333333333333"
  mkdir -p "${log_dir}" "${agent_home}/projects/-workspace"

  audit_write_session_json \
    "${log_dir}" "${session_id}" "claude" "1" "testuser" "" "" "sandbox-claude-trpn" \
    "2026-04-01T20:00:00Z" "api.anthropic.com"
  touch -d "2026-04-01T20:00:00" "${log_dir}/session.json"

  # Two transcripts, BOTH modified after the session started — as happens when
  # a second claude session runs concurrently in the shared agent home.
  echo '{"mine":true}'   > "${agent_home}/projects/-workspace/${mine}.jsonl"
  echo '{"theirs":true}' > "${agent_home}/projects/-workspace/${theirs}.jsonl"
  touch -d "2026-04-01T20:30:00" "${agent_home}/projects/-workspace/${mine}.jsonl"
  touch -d "2026-04-01T20:31:00" "${agent_home}/projects/-workspace/${theirs}.jsonl"

  audit_capture_transcript "${log_dir}" "claude" "${agent_home}" "${mine}"

  [[ -f "${log_dir}/transcript/${mine}.jsonl" ]] \
    && pass "captured this session's pinned transcript" \
    || fail "pinned transcript was not captured"

  [[ ! -e "${log_dir}/transcript/${theirs}.jsonl" ]] \
    && pass "concurrent session's transcript excluded (no overlap)" \
    || fail "concurrent session's transcript leaked into the capture"
}

###############################################################################
# Test: session.json records profile and overlay when SESSION_PROFILE /
# SESSION_OVERLAY are exported, and empty strings when they aren't.
# Locks the contract bin/sandbox depends on after Phase 2.
###############################################################################
test_session_json_profile_overlay_fields() {
  info "Testing profile/overlay fields in session.json..."

  local session_id="ses-20260401-210000-prfo"
  local log_dir="${TEST_LOG_DIR}/${session_id}"
  mkdir -p "${log_dir}"

  # With profile + overlay set
  (
    export SESSION_PROFILE="innkeeper-dev"
    export SESSION_OVERLAY="/home/jdoe/overlays/innkeeper"
    audit_write_session_json \
      "${log_dir}" "${session_id}" "claude" "2" "testuser" \
      "/tmp/repo" "" "sandbox-${session_id}" "2026-04-01T21:00:00Z" \
      "api.anthropic.com" >/dev/null
  )

  local profile overlay
  profile="$(jq -r '.profile' "${log_dir}/session.json")"
  overlay="$(jq -r '.overlay' "${log_dir}/session.json")"
  [[ "${profile}" == "innkeeper-dev" ]] \
    && pass "profile field recorded" \
    || fail "profile field expected 'innkeeper-dev', got '${profile}'"
  [[ "${overlay}" == "/home/jdoe/overlays/innkeeper" ]] \
    && pass "overlay field recorded" \
    || fail "overlay field expected '/home/jdoe/overlays/innkeeper', got '${overlay}'"

  # Without either env var set — fields exist but empty
  local sid2="ses-20260401-210100-bare"
  local log2="${TEST_LOG_DIR}/${sid2}"
  mkdir -p "${log2}"
  (
    unset SESSION_PROFILE SESSION_OVERLAY
    audit_write_session_json \
      "${log2}" "${sid2}" "claude" "1" "testuser" \
      "" "" "sandbox-${sid2}" "2026-04-01T21:01:00Z" \
      "api.anthropic.com" >/dev/null
  )

  profile="$(jq -r '.profile' "${log2}/session.json")"
  overlay="$(jq -r '.overlay' "${log2}/session.json")"
  [[ "${profile}" == "" ]] \
    && pass "profile empty when unset" \
    || fail "profile expected empty, got '${profile}'"
  [[ "${overlay}" == "" ]] \
    && pass "overlay empty when unset" \
    || fail "overlay expected empty, got '${overlay}'"

  # Fields must still be present in the JSON (not null/missing) so
  # downstream tooling can rely on the schema.
  local has_profile has_overlay
  has_profile="$(jq 'has("profile")' "${log2}/session.json")"
  has_overlay="$(jq 'has("overlay")' "${log2}/session.json")"
  [[ "${has_profile}" == "true" ]] \
    && pass "profile key present even when empty" \
    || fail "profile key missing from session.json"
  [[ "${has_overlay}" == "true" ]] \
    && pass "overlay key present even when empty" \
    || fail "overlay key missing from session.json"
}

###############################################################################
# Test: session.json records kube_api_cidr / kube_api_port when set, and
# empty strings when not. These fields are read by 'sandbox allow' to
# rebuild the policy without re-resolving the API server.
###############################################################################
test_session_json_kube_api_fields() {
  info "Testing kube_api_cidr/port fields in session.json..."

  local session_id="ses-20260401-220000-kube"
  local log_dir="${TEST_LOG_DIR}/${session_id}"
  mkdir -p "${log_dir}"

  # With kube API server info set
  (
    export SESSION_KUBE_API_CIDR="10.0.0.1/32"
    export SESSION_KUBE_API_PORT="6443"
    audit_write_session_json \
      "${log_dir}" "${session_id}" "claude" "3" "testuser" \
      "/tmp/repo" "" "sandbox-${session_id}" "2026-04-01T22:00:00Z" \
      "api.anthropic.com" >/dev/null
  )

  local cidr port
  cidr="$(jq -r '.kube_api_cidr' "${log_dir}/session.json")"
  port="$(jq -r '.kube_api_port' "${log_dir}/session.json")"
  [[ "${cidr}" == "10.0.0.1/32" ]] \
    && pass "kube_api_cidr recorded" \
    || fail "kube_api_cidr expected '10.0.0.1/32', got '${cidr}'"
  [[ "${port}" == "6443" ]] \
    && pass "kube_api_port recorded" \
    || fail "kube_api_port expected '6443', got '${port}'"

  # Without — fields are present but empty (Tier 1/2 case)
  local sid2="ses-20260401-220100-tier1"
  local log2="${TEST_LOG_DIR}/${sid2}"
  mkdir -p "${log2}"
  (
    unset SESSION_KUBE_API_CIDR SESSION_KUBE_API_PORT
    audit_write_session_json \
      "${log2}" "${sid2}" "claude" "1" "testuser" \
      "" "" "sandbox-${sid2}" "2026-04-01T22:01:00Z" \
      "api.anthropic.com" >/dev/null
  )

  cidr="$(jq -r '.kube_api_cidr' "${log2}/session.json")"
  port="$(jq -r '.kube_api_port' "${log2}/session.json")"
  [[ "${cidr}" == "" ]] \
    && pass "kube_api_cidr empty when unset" \
    || fail "kube_api_cidr expected empty, got '${cidr}'"
  [[ "${port}" == "" ]] \
    && pass "kube_api_port empty when unset" \
    || fail "kube_api_port expected empty, got '${port}'"
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""
  echo "Test log directory: ${TEST_LOG_DIR}"
  echo ""

  test_session_json_structure
  test_session_json_profile_overlay_fields
  test_session_json_kube_api_fields
  test_end_time_update
  test_tier3_retention
  test_list_sessions
  test_capture_transcript_claude
  test_capture_transcript_codex
  test_capture_transcript_opencode
  test_capture_transcript_no_match
  test_record_agent_session_id
  test_capture_transcript_claude_pinned

  echo ""
  echo "All audit tests passed."
}

main "$@"
