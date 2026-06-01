#!/usr/bin/env bash
# tests/test-blocked-domains.sh — Blocked destination rejection tests
# Verifies: blocked domains from config/blocked-destinations.yaml
# are rejected at CLI validation level (not just network level)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-blocked-domains"

fail() { echo "FAIL: $*" >&2; exit 1; }

# Source the checks library to test directly
source "${SANDBOX_ROOT}/lib/platform.sh"
source "${SANDBOX_ROOT}/lib/checks.sh"

###############################################################################
# Test: Blocked domains are rejected by check_domain_not_blocked
###############################################################################

# check_domain_not_blocked exits non-zero on a match, so each call is wrapped
# in a subshell ( ... ) to contain that exit to the assertion instead of
# terminating the whole test run.
test_domain_blocked() {
  local domain="$1"
  local test_label="$2"

  info "Testing that '${domain}' is blocked..."

  if ( check_domain_not_blocked "${domain}" ) 2>/dev/null; then
    fail "${test_label}: Domain '${domain}' should be blocked but was allowed"
  else
    pass "${test_label}: Domain '${domain}' correctly rejected"
  fi
}

test_domain_allowed() {
  local domain="$1"
  local test_label="$2"

  info "Testing that '${domain}' is allowed..."

  if ( check_domain_not_blocked "${domain}" ) 2>/dev/null; then
    pass "${test_label}: Domain '${domain}' correctly allowed"
  else
    fail "${test_label}: Domain '${domain}' should be allowed but was blocked"
  fi
}

###############################################################################
# Test: sandbox run --allow-domain with blocked domain is rejected
###############################################################################
test_cli_rejects_blocked_domain() {
  local domain="slack.com"
  info "Testing CLI rejects --allow-domain ${domain}..."

  local output
  if output="$("${SANDBOX_ROOT}/bin/sandbox" run \
    --agent claude --tier 1 \
    --allow-domain "${domain}" \
    --dry-run 2>&1)"; then
    fail "CLI should have rejected blocked domain '${domain}' but exited 0"
  else
    if echo "${output}" | grep -qi "block\|forbidden\|not allowed"; then
      pass "CLI correctly rejected --allow-domain ${domain}"
    else
      fail "CLI rejected '${domain}' but error message was unclear: ${output}"
    fi
  fi
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""
  echo "Blocked destinations config: ${SANDBOX_ROOT}/config/blocked-destinations.yaml"
  echo ""

  # Test exact blocked domains and wildcard subdomain matching.
  # pastebin.com is listed in blocked-destinations.yaml with both an exact
  # entry and a *.pastebin.com wildcard, so it exercises both code paths.
  test_domain_blocked "pastebin.com" "pastebin-exact"
  test_domain_blocked "raw.pastebin.com" "pastebin-wildcard-subdomain"
  test_domain_blocked "somecompany.slack.com" "slack-wildcard"
  test_domain_blocked "tenant.teams.microsoft.com" "teams-wildcard"

  # Apex of a '*.domain' rule must be blocked too — otherwise
  # '--allow-domain slack.com' would slip past the '*.slack.com' block.
  test_domain_blocked "slack.com"            "slack-apex"
  test_domain_blocked "discord.com"          "discord-apex"
  test_domain_blocked "teams.microsoft.com"  "teams-apex"

  # Prefix wildcards ('smtp.*', 'mail.*') must actually match.
  test_domain_blocked "smtp.example.com"     "smtp-prefix-wildcard"
  test_domain_blocked "mail.example.org"     "mail-prefix-wildcard"

  # Test allowed domains (not in blocklist)
  test_domain_allowed "api.anthropic.com"   "anthropic-not-blocked"
  test_domain_allowed "github.com"          "github-not-blocked"
  test_domain_allowed "pypi.org"            "pypi-not-blocked"
  test_domain_allowed "registry.npmjs.org"  "npm-not-blocked"
  # A domain that merely *contains* a blocked label must not be caught
  # (e.g. 'slack.com.evil.test' or 'notslack.com' are not blocked).
  test_domain_allowed "notslack.com"        "substring-not-overmatched"
  test_domain_allowed "myteams.microsoft.example.com" "label-boundary-respected"

  # Test CLI integration
  test_cli_rejects_blocked_domain

  echo ""
  echo "All blocked domain tests passed."
}

main "$@"
