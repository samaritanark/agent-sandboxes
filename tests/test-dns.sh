#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-dns.sh — split-horizon DNS rendering tests (lib/dns.sh).
# Verifies: resolvectl JSON -> internal-zone extraction skips the "." catch-all;
# config.yaml internal_dns_zones parse; effective-zone merge/dedupe with
# last-known fallback; CoreDNS server-block + ConfigMap rendering. Cluster-free.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-dns"
TEST_DIR="$(mktemp -d /tmp/sandbox-dns-test-XXXXXX)"

fail() { echo "FAIL: $*" >&2; exit 1; }
cleanup() { rm -rf "${TEST_DIR}"; }
trap cleanup EXIT

# lib/dns.sh references USER_SANDBOX_CONFIG and SANDBOX_SPLIT_DNS_STATE at
# call time via globals, so we point them at the scratch dir before sourcing.
USER_SANDBOX_CONFIG="${TEST_DIR}/config.yaml"
SANDBOX_SPLIT_DNS_STATE="${TEST_DIR}/split-dns.zones"
source "${SANDBOX_ROOT}/lib/platform.sh"
source "${SANDBOX_ROOT}/lib/config.sh"
source "${SANDBOX_ROOT}/lib/dns.sh"

# Make live detection deterministic regardless of the test host's own
# systemd-resolved state: stub resolvectl to report nothing, so the
# dns_effective_zones cases exercise the config/last-known paths in isolation.
# (dns_zones_from_json is tested directly against a captured fixture above.)
resolvectl() { return 1; }

eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    pass "${label}"
  else
    fail "${label}: expected '${expected}', got '${actual}'"
  fi
}

# A two-link systemd-resolved snapshot: a VPN link with an internal routing
# domain + two servers, and the default link carrying the "." catch-all.
FIXTURE='[
  {"ifname":"tun0","defaultRoute":true,
   "servers":[{"addressString":"10.8.48.53"},{"addressString":"10.4.48.53"}],
   "searchDomains":[{"name":"example.cloud","routeOnly":false}]},
  {"ifname":"wlp1s0","defaultRoute":true,
   "servers":[{"addressString":"1.1.1.1"}],
   "searchDomains":[{"name":".","routeOnly":true}]},
  {"ifname":"docker0","defaultRoute":false}
]'

###############################################################################
# dns_zones_from_json — extraction + catch-all skip
###############################################################################
test_zones_from_json() {
  info "Testing dns_zones_from_json..."
  local out
  out="$(printf '%s' "${FIXTURE}" | dns_zones_from_json)"
  eq "internal zone + servers, catch-all skipped" \
     "example.cloud 10.8.48.53 10.4.48.53" "${out}"

  # No internal routing domains (only catch-all) -> empty.
  local only_default='[{"ifname":"wlp1s0","servers":[{"addressString":"1.1.1.1"}],"searchDomains":[{"name":".","routeOnly":true}]}]'
  out="$(printf '%s' "${only_default}" | dns_zones_from_json)"
  eq "only catch-all -> empty" "" "${out}"

  # Two internal domains on one link both map to that link's servers.
  local multi='[{"ifname":"tun0","servers":[{"addressString":"10.8.48.53"}],"searchDomains":[{"name":"example.cloud"},{"name":"corp.example"}]}]'
  out="$(printf '%s' "${multi}" | dns_zones_from_json)"
  eq "two domains, one link" "example.cloud 10.8.48.53
corp.example 10.8.48.53" "${out}"
}

###############################################################################
# dns_config_zones — explicit ~/.sandbox/config.yaml escape hatch
###############################################################################
test_config_zones() {
  info "Testing dns_config_zones..."
  cat > "${USER_SANDBOX_CONFIG}" <<'YAML'
internal_dns_zones:
  - example.cloud 10.8.48.53 10.4.48.53
  - corp.internal 10.9.0.1
YAML
  local out
  out="$(dns_config_zones)"
  eq "config zones parsed" "example.cloud 10.8.48.53 10.4.48.53
corp.internal 10.9.0.1" "${out}"
  rm -f "${USER_SANDBOX_CONFIG}"
}

###############################################################################
# render_split_dns_blocks / render_split_dns_configmap
###############################################################################
test_render() {
  info "Testing render_split_dns_blocks + configmap..."
  local blocks
  blocks="$(printf 'example.cloud 10.8.48.53 10.4.48.53\n' | render_split_dns_blocks)"
  local expected_block='example.cloud:53 {
    errors
    cache 30
    forward . 10.8.48.53 10.4.48.53 {
        policy sequential
    }
}'
  eq "server block" "${expected_block}" "${blocks}"

  # A zone with no servers is dropped.
  eq "zone w/o servers dropped" "" "$(printf 'lonely.zone\n' | render_split_dns_blocks)"

  # Empty input -> empty ConfigMap (no manifest emitted).
  eq "empty -> no manifest" "" "$(printf '' | render_split_dns_configmap)"

  # Full ConfigMap shape: key present, blocks indented by 4 under the literal.
  local cm
  cm="$(printf 'example.cloud 10.8.48.53 10.4.48.53\n' | render_split_dns_configmap)"
  case "${cm}" in
    *"name: coredns-custom"*) pass "configmap name" ;;
    *) fail "configmap name missing: ${cm}" ;;
  esac
  case "${cm}" in
    *"  sandbox-split-horizon.server: |"*) pass "configmap key" ;;
    *) fail "configmap key missing: ${cm}" ;;
  esac
  case "${cm}" in
    *"    example.cloud:53 {"*) pass "block indented under key" ;;
    *) fail "block not indented: ${cm}" ;;
  esac
}

###############################################################################
# dns_effective_zones — merge/dedupe + last-known persistence
###############################################################################
test_effective_zones_persistence() {
  info "Testing dns_effective_zones persistence + dedupe..."
  rm -f "${USER_SANDBOX_CONFIG}" "${SANDBOX_SPLIT_DNS_STATE}"

  # No resolvectl in the unit env and no state/config yet -> empty.
  eq "cold start -> empty" "" "$(dns_effective_zones)"

  # Seed last-known state (simulates a prior on-VPN detection) and confirm it
  # is used when live detection yields nothing (VPN momentarily down).
  printf 'example.cloud 10.8.48.53 10.4.48.53\n' > "${SANDBOX_SPLIT_DNS_STATE}"
  eq "falls back to last-known" \
     "example.cloud 10.8.48.53 10.4.48.53" "$(dns_effective_zones)"

  # config.yaml takes precedence on a zone conflict (first occurrence wins).
  cat > "${USER_SANDBOX_CONFIG}" <<'YAML'
internal_dns_zones:
  - example.cloud 10.99.0.1
YAML
  eq "config overrides last-known on conflict" \
     "example.cloud 10.99.0.1" "$(dns_effective_zones)"
  rm -f "${USER_SANDBOX_CONFIG}" "${SANDBOX_SPLIT_DNS_STATE}"
}

test_zones_from_json
test_config_zones
test_render
test_effective_zones_persistence

echo "All ${TEST_NAME} tests passed."
