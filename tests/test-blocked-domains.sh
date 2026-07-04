#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-blocked-domains.sh — Blocked destination rejection tests
# Verifies: blocked domains from config/blocked-destinations.yaml
# are rejected at CLI validation level (not just network level)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-blocked-domains"

fail() { echo "FAIL: $*" >&2; exit 1; }

# Source the checks library to test directly. checks.sh reads the block lists
# via lib/config.sh's bounded YAML extractor, so config.sh must be sourced too.
source "${SANDBOX_ROOT}/lib/platform.sh"
source "${SANDBOX_ROOT}/lib/config.sh"
source "${SANDBOX_ROOT}/lib/profile.sh"
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

# check_egress_target_not_blocked is the entry point all egress destinations now
# go through. For an IP literal it must also run the blocked-CIDR membership
# check — that is what catches a kube API server given as a bare IP (the common
# case), which matches no blocked_domains pattern. 169.254.0.0/16 is a shipped
# block, so a literal inside it must be rejected.
test_combiner_ip_routes_to_cidr() {
  info "Testing check_egress_target_not_blocked routes IP literals to the CIDR check..."
  if ( check_egress_target_not_blocked "169.254.169.254" ) 2>/dev/null; then
    fail "IP-literal 169.254.169.254 should be rejected (inside blocked 169.254.0.0/16)"
  else
    pass "IP-literal in a blocked CIDR is rejected by the combiner"
  fi
  if ( check_egress_target_not_blocked "8.8.8.8" ) 2>/dev/null \
     && ( check_egress_target_not_blocked "github.com" ) 2>/dev/null; then
    pass "allowed IP + domain still pass the combiner"
  else
    fail "allowed IP/domain should not be rejected"
  fi
}

###############################################################################
# Test: --infra-endpoint with a blocked host is rejected at the CLI.
# Regression for the bypass where --infra-endpoint URLs were handed straight to
# the policy builder and never block-checked. Tier 1 reaches validation without
# a cluster or --repo, so this fails fast at input validation.
###############################################################################
test_cli_rejects_blocked_infra_endpoint() {
  info "Testing CLI rejects --infra-endpoint with a blocked host..."
  local output
  if output="$("${SANDBOX_ROOT}/bin/sandbox" run \
    --agent claude --tier 1 \
    --infra-endpoint https://slack.com \
    --dry-run 2>&1)"; then
    fail "CLI should have rejected --infra-endpoint https://slack.com but exited 0"
  else
    if echo "${output}" | grep -qi "block\|forbidden\|not allowed"; then
      pass "CLI rejects a blocked --infra-endpoint (bypass closed)"
    else
      fail "CLI rejected the endpoint but error message was unclear: ${output}"
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

  # DNS names are case-insensitive and a trailing '.' is the same host. A block
  # check that compared them literally let '--allow-domain SLACK.COM' / 'slack.com.'
  # walk past a blocked 'slack.com' and land verbatim in the Cilium allow rule
  # (which lowercases/dot-normalizes it) — reaching the very host meant to be
  # blocked. These must all be rejected exactly like their canonical form.
  test_domain_blocked "SLACK.COM"            "slack-apex-uppercase"
  test_domain_blocked "Slack.Com"            "slack-apex-mixedcase"
  test_domain_blocked "slack.com."           "slack-apex-trailing-dot"
  test_domain_blocked "SLACK.COM."           "slack-apex-upper-and-dot"
  test_domain_blocked "SomeCompany.Slack.Com" "slack-wildcard-mixedcase"
  test_domain_blocked "raw.PASTEBIN.com."    "pastebin-wildcard-upper-and-dot"

  # Test allowed domains (not in blocklist)
  test_domain_allowed "api.anthropic.com"   "anthropic-not-blocked"
  test_domain_allowed "github.com"          "github-not-blocked"
  test_domain_allowed "pypi.org"            "pypi-not-blocked"
  test_domain_allowed "registry.npmjs.org"  "npm-not-blocked"
  # A domain that merely *contains* a blocked label must not be caught
  # (e.g. 'slack.com.evil.test' or 'notslack.com' are not blocked).
  test_domain_allowed "notslack.com"        "substring-not-overmatched"
  test_domain_allowed "myteams.microsoft.example.com" "label-boundary-respected"
  # Normalization must not over-block: a non-blocked host in any case / with a
  # trailing dot still passes.
  test_domain_allowed "GitHub.com"          "allowed-mixedcase-passes"
  test_domain_allowed "github.com."         "allowed-trailing-dot-passes"

  # Combiner: IP-literal targets route to the blocked-CIDR check.
  test_combiner_ip_routes_to_cidr

  # Test CLI integration
  test_cli_rejects_blocked_domain
  test_cli_rejects_blocked_infra_endpoint

  echo ""
  echo "All blocked domain tests passed."
}

main "$@"
