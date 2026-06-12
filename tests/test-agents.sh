#!/usr/bin/env bash
# tests/test-agents.sh — lib/agents.sh helper tests
# Verifies the per-agent launch-flag helpers, focusing on
# get_agent_sandbox_flags: Codex disables its inner bwrap OS-sandbox at launch
# (so it works without re-running 'sandbox onboard'), other agents add nothing.
# Cluster-free.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-agents"

fail() { echo "FAIL: $*" >&2; exit 1; }

source "${SANDBOX_ROOT}/lib/agents.sh"

eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    pass "${label}"
  else
    fail "${label}: expected '${expected}', got '${actual}'"
  fi
}

###############################################################################
# get_agent_sandbox_flags
###############################################################################
test_sandbox_flags_codex() {
  info "Testing get_agent_sandbox_flags disables Codex's inner sandbox..."
  eq "codex gets danger-full-access" \
    "--sandbox danger-full-access" "$(get_agent_sandbox_flags codex)"
}

test_sandbox_flags_others_empty() {
  info "Testing get_agent_sandbox_flags adds nothing for other agents..."
  eq "claude gets no sandbox flag"   "" "$(get_agent_sandbox_flags claude)"
  eq "opencode gets no sandbox flag" "" "$(get_agent_sandbox_flags opencode)"
  eq "unknown agent gets no flag"    "" "$(get_agent_sandbox_flags bogus)"
}

test_sandbox_flags_keep_approvals() {
  info "Testing the Codex flag is sandbox-only (no approval bypass)..."
  # Governance (GOVERNANCE.md §6): we disable only the inner OS-sandbox, never
  # Codex's human-in-the-loop approval prompts. Guard against a future edit
  # sneaking an approval-bypass flag into this helper.
  local flags
  flags="$(get_agent_sandbox_flags codex)"
  if [[ "${flags}" == *"--ask-for-approval"* \
     || "${flags}" == *"bypass"* \
     || "${flags}" == *"--yolo"* ]]; then
    fail "codex sandbox flags must not touch approvals; got: ${flags}"
  fi
  pass "codex sandbox flags leave approval policy untouched"
}

test_sandbox_flags_word_split() {
  info "Testing the flag string splits into exactly two argv tokens..."
  # bin/sandbox appends these via 'read -ra'; confirm it yields a clean
  # two-token flag+value pair (no quoting/spacing surprises).
  local -a parts
  read -ra parts <<< "$(get_agent_sandbox_flags codex)"
  eq "two argv tokens"     "2"                     "${#parts[@]}"
  eq "first token is flag" "--sandbox"             "${parts[0]}"
  eq "second is the mode"  "danger-full-access"    "${parts[1]}"
}

main() {
  info "Running ${TEST_NAME} tests..."
  test_sandbox_flags_codex
  test_sandbox_flags_others_empty
  test_sandbox_flags_keep_approvals
  test_sandbox_flags_word_split
  echo "All ${TEST_NAME} tests passed."
}

main "$@"
