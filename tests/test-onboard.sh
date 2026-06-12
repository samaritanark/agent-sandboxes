#!/usr/bin/env bash
# tests/test-onboard.sh — Host-to-sandbox credential staging tests
# Verifies: stage_file copy + chmod 0600 + idempotency, force overwrite,
# missing-source handling, opencode refusal, forbidden env-var warning,
# starter config write. Cluster-free; HOME is redirected per case.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-onboard"
TEST_DIR="$(mktemp -d /tmp/sandbox-onboard-test-XXXXXX)"

fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
  rm -rf "${TEST_DIR}"
}
trap cleanup EXIT

# Set up a fresh fake HOME for each test case. We re-export HOME and
# re-source lib/onboard.sh so ONBOARD_AGENT_HOME_BASE picks up the new
# value (it references ${HOME} at source time).
new_home() {
  local h="${TEST_DIR}/home-$1"
  mkdir -p "${h}"
  echo "${h}"
}

eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    pass "${label}"
  else
    fail "${label}: expected '${expected}', got '${actual}'"
  fi
}

# Helper: source lib/onboard.sh against an explicit HOME.
load_onboard_with_home() {
  HOME="$1"
  ONBOARD_AGENT_HOME_BASE="${HOME}/.sandbox/agent-home"
  # shellcheck disable=SC1091
  source "${SANDBOX_ROOT}/lib/onboard.sh"
}

###############################################################################
# stage_file — the core copy primitive
###############################################################################
test_stage_file_basics() {
  info "Testing stage_file copy + permissions..."

  local h
  h="$(new_home stage)"
  load_onboard_with_home "${h}"

  local src="${h}/src.json"
  local dst="${h}/dst.json"
  echo '{"a":1}' > "${src}"
  # Make src world-readable so we can confirm the copy enforces 0600.
  chmod 0644 "${src}"

  local result
  result="$(stage_file "${src}" "${dst}" false false)"
  eq "stage_file returns 'copied'" "copied" "${result}"
  [[ -f "${dst}" ]] && pass "stage_file wrote the destination" \
    || fail "destination missing after stage_file"

  local mode
  mode="$(stat -c '%a' "${dst}")"
  eq "stage_file sets mode 0600" "600" "${mode}"
}

test_stage_file_idempotent() {
  info "Testing stage_file skip-when-exists without --force..."

  local h
  h="$(new_home idem)"
  load_onboard_with_home "${h}"

  local src="${h}/src.json"
  local dst="${h}/dst.json"
  echo "first" > "${src}"

  stage_file "${src}" "${dst}" false false >/dev/null

  # Mutate src to confirm we don't silently overwrite.
  echo "second" > "${src}"
  local result
  result="$(stage_file "${src}" "${dst}" false false)"
  eq "second run returns 'skipped-exists'" "skipped-exists" "${result}"
  eq "destination unchanged" "first" "$(cat "${dst}")"
}

test_stage_file_force() {
  info "Testing stage_file --force overwrites..."

  local h
  h="$(new_home force)"
  load_onboard_with_home "${h}"

  local src="${h}/src.json"
  local dst="${h}/dst.json"
  echo "first" > "${src}"
  stage_file "${src}" "${dst}" false false >/dev/null
  echo "second" > "${src}"

  local result
  result="$(stage_file "${src}" "${dst}" false true)"
  eq "force returns 'copied'" "copied" "${result}"
  eq "destination updated with --force" "second" "$(cat "${dst}")"
}

test_stage_file_dry_run() {
  info "Testing stage_file --dry-run leaves filesystem untouched..."

  local h
  h="$(new_home dry)"
  load_onboard_with_home "${h}"

  local src="${h}/src.json"
  local dst="${h}/dst.json"
  echo "data" > "${src}"

  local result
  result="$(stage_file "${src}" "${dst}" true false)"
  eq "dry-run returns 'copied'" "copied" "${result}"
  [[ ! -f "${dst}" ]] && pass "dry-run wrote nothing to filesystem" \
    || fail "dry-run wrote the destination — should not have"
}

test_stage_file_missing_source() {
  info "Testing stage_file with missing source..."

  local h
  h="$(new_home missing)"
  load_onboard_with_home "${h}"

  local result
  result="$(stage_file "${h}/no-such-file" "${h}/dst.json" false false)"
  eq "missing source returns 'missing-src'" "missing-src" "${result}"
}

###############################################################################
# onboard_agent — per-agent dispatch
###############################################################################
test_onboard_agent_claude_real() {
  info "Testing onboard_agent claude (real run with credentials present)..."

  local h
  h="$(new_home claude-real)"
  load_onboard_with_home "${h}"

  mkdir -p "${h}/.claude"
  echo '{"oauth":"fake"}' > "${h}/.claude/.credentials.json"
  echo '{"theme":"dark"}' > "${h}/.claude/settings.json"
  chmod 0644 "${h}/.claude/.credentials.json"

  onboard_agent claude false false >/dev/null

  local cred="${h}/.sandbox/agent-home/claude/.credentials.json"
  local sett="${h}/.sandbox/agent-home/claude/settings.json"
  [[ -f "${cred}" ]] && pass "credentials staged for claude" \
    || fail "claude credentials missing"
  [[ -f "${sett}" ]] && pass "settings staged for claude" \
    || fail "claude settings missing"
  eq "credentials mode 0600" "600" "$(stat -c '%a' "${cred}")"
}

test_onboard_agent_claude_no_host_state() {
  info "Testing onboard_agent claude when no host state exists..."

  local h
  h="$(new_home claude-empty)"
  load_onboard_with_home "${h}"

  # No ~/.claude/ on the host.
  local out
  out="$(onboard_agent claude false false)"
  # We don't fail; we report each file as missing-src.
  if echo "${out}" | grep -q "no host-side state"; then
    pass "missing host state is reported, not fatal"
  else
    fail "expected 'no host-side state' message; got: ${out}"
  fi

  [[ ! -f "${h}/.sandbox/agent-home/claude/.credentials.json" ]] \
    && pass "no destination file created when source absent" \
    || fail "destination file appeared with no source"
}

test_onboard_agent_opencode_refusal() {
  info "Testing onboard_agent opencode refusal..."

  local h
  h="$(new_home opencode)"
  load_onboard_with_home "${h}"

  local out
  out="$(onboard_agent opencode false false)"
  if echo "${out}" | grep -qi "refused"; then
    pass "opencode refusal printed"
  else
    fail "expected 'refused' in output; got: ${out}"
  fi
  if echo "${out}" | grep -q "sandbox secret"; then
    pass "refusal points at 'sandbox secret'"
  else
    fail "refusal missing pointer to 'sandbox secret'; got: ${out}"
  fi

  [[ ! -d "${h}/.sandbox/agent-home/opencode" ]] \
    || [[ -z "$(ls -A "${h}/.sandbox/agent-home/opencode" 2>/dev/null)" ]] \
    && pass "opencode agent-home not populated" \
    || fail "opencode agent-home should be empty / nonexistent"
}

###############################################################################
# warn_forbidden_env
###############################################################################
test_onboard_codex_sandbox_mode_fresh() {
  info "Testing onboard_agent codex seeds sandbox_mode with no host config..."

  local h
  h="$(new_home codex-fresh)"
  load_onboard_with_home "${h}"

  # Host has auth but no ~/.codex/config.toml.
  mkdir -p "${h}/.codex"
  echo '{"oauth":"fake"}' > "${h}/.codex/auth.json"

  onboard_agent codex false false >/dev/null

  local cfg="${h}/.sandbox/agent-home/codex/config.toml"
  [[ -f "${cfg}" ]] && pass "config.toml created when host had none" \
    || fail "config.toml not created"
  grep -q 'sandbox_mode = "danger-full-access"' "${cfg}" \
    && pass "sandbox_mode seeded" \
    || fail "sandbox_mode not seeded; got: $(cat "${cfg}")"
  eq "seeded config mode 0600" "600" "$(stat -c '%a' "${cfg}")"
}

test_onboard_codex_sandbox_mode_prepended() {
  info "Testing onboard_agent codex prepends sandbox_mode above [tables]..."

  local h
  h="$(new_home codex-prepend)"
  load_onboard_with_home "${h}"

  # Host config opens with a table header — the top-level key must land
  # ABOVE it to remain a top-level key in TOML.
  mkdir -p "${h}/.codex"
  echo '{"oauth":"fake"}' > "${h}/.codex/auth.json"
  printf '[projects."/workspace"]\ntrust_level = "trusted"\n' \
    > "${h}/.codex/config.toml"

  onboard_agent codex false false >/dev/null

  local cfg="${h}/.sandbox/agent-home/codex/config.toml"
  local first_key
  first_key="$(grep -nE '^[^#[:space:]]' "${cfg}" | head -1)"
  if echo "${first_key}" | grep -q 'sandbox_mode'; then
    pass "sandbox_mode is the first non-comment key (above the table)"
  else
    fail "sandbox_mode not prepended above table; first key: ${first_key}"
  fi
  grep -q 'trust_level = "trusted"' "${cfg}" \
    && pass "operator's existing table preserved" \
    || fail "operator config content lost"
}

test_onboard_codex_sandbox_mode_idempotent() {
  info "Testing onboard_agent codex leaves an operator's sandbox_mode alone..."

  local h
  h="$(new_home codex-idem)"
  load_onboard_with_home "${h}"

  mkdir -p "${h}/.codex"
  echo '{"oauth":"fake"}' > "${h}/.codex/auth.json"
  printf 'sandbox_mode = "workspace-write"\n' > "${h}/.codex/config.toml"

  local out
  out="$(onboard_agent codex false false)"

  local cfg="${h}/.sandbox/agent-home/codex/config.toml"
  grep -q 'sandbox_mode = "workspace-write"' "${cfg}" \
    && pass "existing sandbox_mode preserved" \
    || fail "operator's sandbox_mode was overwritten"
  [[ "$(grep -c 'sandbox_mode' "${cfg}")" -eq 1 ]] \
    && pass "no duplicate sandbox_mode key" \
    || fail "duplicate sandbox_mode key written"
  echo "${out}" | grep -q "leaving it as-is" \
    && pass "onboard reports it left the value alone" \
    || fail "expected 'leaving it as-is' note; got: ${out}"
}

test_onboard_codex_sandbox_mode_dry_run() {
  info "Testing onboard_agent codex dry-run writes no sandbox_mode..."

  local h
  h="$(new_home codex-dry)"
  load_onboard_with_home "${h}"

  mkdir -p "${h}/.codex"
  echo '{"oauth":"fake"}' > "${h}/.codex/auth.json"

  local out
  out="$(onboard_agent codex true false)"

  [[ ! -f "${h}/.sandbox/agent-home/codex/config.toml" ]] \
    && pass "dry-run wrote no config.toml" \
    || fail "dry-run created config.toml"
  echo "${out}" | grep -q 'would set sandbox_mode' \
    && pass "dry-run reports the intended change" \
    || fail "dry-run missing 'would set sandbox_mode'; got: ${out}"
}

test_warn_forbidden_env() {
  info "Testing warn_forbidden_env counts and message..."

  local h
  h="$(new_home env)"
  load_onboard_with_home "${h}"

  # No forbidden vars set
  unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN OPENAI_API_KEY
  local out count
  out="$(warn_forbidden_env 2>&1)"
  count="$(echo "${out}" | tail -1)"
  eq "no forbidden env → count 0" "0" "${count}"

  # One forbidden var
  out="$(ANTHROPIC_API_KEY=sk-x warn_forbidden_env 2>&1)"
  count="$(echo "${out}" | tail -1)"
  eq "one forbidden env → count 1" "1" "${count}"
  if echo "${out}" | grep -q "ANTHROPIC_API_KEY"; then
    pass "warning names the offending env var"
  else
    fail "warning did not name the env var"
  fi
}

###############################################################################
# write_starter_user_config
###############################################################################
test_write_starter_user_config() {
  info "Testing write_starter_user_config idempotency..."

  local h
  h="$(new_home config)"
  load_onboard_with_home "${h}"

  # First call writes
  write_starter_user_config false false >/dev/null
  [[ -f "${h}/.sandbox/config.yaml" ]] && pass "starter config written" \
    || fail "starter config missing"
  eq "starter config mode 0600" "600" "$(stat -c '%a' "${h}/.sandbox/config.yaml")"
  if grep -q "overlay:" "${h}/.sandbox/config.yaml"; then
    pass "starter config mentions overlay key"
  else
    fail "starter config should mention overlay"
  fi

  # Second call without --force leaves it alone (idempotent)
  echo "# user edit" >> "${h}/.sandbox/config.yaml"
  write_starter_user_config false false >/dev/null
  if grep -q "# user edit" "${h}/.sandbox/config.yaml"; then
    pass "second call preserved user edits"
  else
    fail "second call overwrote user edits"
  fi

  # --force overwrites
  write_starter_user_config false true >/dev/null
  if grep -q "# user edit" "${h}/.sandbox/config.yaml"; then
    fail "--force did not overwrite"
  else
    pass "--force overwrote the file"
  fi

  # Dry-run does nothing
  local h2
  h2="$(new_home config-dry)"
  load_onboard_with_home "${h2}"
  write_starter_user_config true false >/dev/null
  [[ ! -f "${h2}/.sandbox/config.yaml" ]] \
    && pass "dry-run wrote no config" \
    || fail "dry-run wrote the config — should not have"
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""
  echo "Test directory: ${TEST_DIR}"
  echo ""

  test_stage_file_basics
  test_stage_file_idempotent
  test_stage_file_force
  test_stage_file_dry_run
  test_stage_file_missing_source
  test_onboard_agent_claude_real
  test_onboard_agent_claude_no_host_state
  test_onboard_agent_opencode_refusal
  test_onboard_codex_sandbox_mode_fresh
  test_onboard_codex_sandbox_mode_prepended
  test_onboard_codex_sandbox_mode_idempotent
  test_onboard_codex_sandbox_mode_dry_run
  test_warn_forbidden_env
  test_write_starter_user_config

  echo ""
  echo "All onboard tests passed."
}

main "$@"
