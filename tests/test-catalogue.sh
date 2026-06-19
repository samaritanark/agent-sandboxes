#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-catalogue.sh — Dependency catalogue resolution + validation
# (Phase 5). Verifies org/overlay resolution order, digest-pinning enforcement,
# the egress-vs-blocked-destinations check, and overlay-additive behaviour.
# Cluster-free.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT_REAL="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$(mktemp -d /tmp/sandbox-catalogue-test-XXXXXX)"
HOME="${TEST_DIR}/home"; mkdir -p "${HOME}"
SANDBOX_NAMESPACE="sandbox"

cleanup() { rm -rf "${TEST_DIR}"; }
trap cleanup EXIT

# A throwaway SANDBOX_ROOT so org-catalogue resolution reads our fixtures, not
# the repo's (empty) config/catalogue. lib/* is symlinked from the real root.
SANDBOX_ROOT="${TEST_DIR}/root"
mkdir -p "${SANDBOX_ROOT}/config/catalogue" "${SANDBOX_ROOT}/lib"
ln -s "${SANDBOX_ROOT_REAL}/lib"/*.sh "${SANDBOX_ROOT}/lib/"

USER_SANDBOX_CONFIG="${HOME}/.sandbox/config.yaml"
BLOCKED_DESTINATIONS_CONFIG="${SANDBOX_ROOT}/config/blocked-destinations.yaml"
cat > "${BLOCKED_DESTINATIONS_CONFIG}" <<'YAML'
blocked_domains:
  - "*.slack.com"
blocked_cidrs:
  - "169.254.0.0/16"
YAML

source "${SANDBOX_ROOT}/lib/config.sh"
source "${SANDBOX_ROOT}/lib/profile.sh"
source "${SANDBOX_ROOT}/lib/checks.sh"
source "${SANDBOX_ROOT}/lib/catalogue.sh"

DIGEST="sha256:0000000000000000000000000000000000000000000000000000000000000000"

eq() {
  local label="$1" expected="$2" actual="$3"
  [[ "${expected}" == "${actual}" ]] && pass "${label}" \
    || fail "${label}: expected '${expected}', got '${actual}'"
}

write_org_entry() {
  local name="$1"; shift
  printf '%s\n' "$@" > "${SANDBOX_ROOT}/config/catalogue/${name}.yaml"
}

###############################################################################
# Resolution
###############################################################################
test_resolution_order() {
  info "Testing catalogue resolution order (org first, overlay adds)..."
  write_org_entry innkeeper-mcp \
    "name: innkeeper-mcp" "kind: mcp" "image: ghcr.io/x/innkeeper@${DIGEST}" "port: 8080"

  local path
  path="$(catalogue_resolve innkeeper-mcp)"
  eq "org entry resolves" "${SANDBOX_ROOT}/config/catalogue/innkeeper-mcp.yaml" "${path}"

  # A miss returns rc=1 with no output.
  if catalogue_resolve nonexistent >/dev/null 2>&1; then
    fail "resolving a nonexistent entry should fail"
  fi
  pass "missing entry returns non-zero"

  # Overlay adds an entry the org doesn't have.
  local overlay="${TEST_DIR}/overlay"
  mkdir -p "${overlay}/catalogue"
  printf '%s\n' "name: team-mcp" "kind: mcp" "image: ghcr.io/x/team@${DIGEST}" "port: 9000" \
    > "${overlay}/catalogue/team-mcp.yaml"
  SANDBOX_OVERLAY="${overlay}" eq "overlay entry resolves" \
    "${overlay}/catalogue/team-mcp.yaml" "$(SANDBOX_OVERLAY="${overlay}" catalogue_resolve team-mcp)"

  # Org wins on a name collision (overlay cannot override).
  printf '%s\n' "name: innkeeper-mcp" "kind: mcp" "image: ghcr.io/EVIL/x@${DIGEST}" "port: 1" \
    > "${overlay}/catalogue/innkeeper-mcp.yaml"
  eq "org wins collision" "${SANDBOX_ROOT}/config/catalogue/innkeeper-mcp.yaml" \
    "$(SANDBOX_OVERLAY="${overlay}" catalogue_resolve innkeeper-mcp)"
}

test_invalid_names() {
  info "Testing catalogue name validation (traversal etc.)..."
  catalogue_is_valid_name "innkeeper-mcp" || fail "valid name rejected"
  for bad in "" "../escape" "a/b" ".hidden"; do
    if catalogue_is_valid_name "${bad}"; then
      fail "invalid name '${bad}' accepted"
    fi
  done
  pass "name validation rejects traversal/empty/hidden"
}

###############################################################################
# Field access + defaults
###############################################################################
test_fields_and_defaults() {
  info "Testing catalogue_field defaults..."
  write_org_entry fielded \
    "name: fielded" "kind: mcp" "image: ghcr.io/x/f@${DIGEST}" "port: 8080"
  local p; p="$(catalogue_resolve fielded)"
  eq "kind" "mcp" "$(catalogue_field "${p}" kind)"
  eq "port" "8080" "$(catalogue_field "${p}" port)"
  eq "missing → default" "/mcp" "$(catalogue_field "${p}" mcp_path /mcp)"
  eq "missing → empty" "" "$(catalogue_field "${p}" nope)"
}

###############################################################################
# Validation
###############################################################################
test_validate_good() {
  info "Testing a sound entry validates..."
  write_org_entry good \
    "name: good" "kind: mcp" "image: ghcr.io/x/g@${DIGEST}" "port: 8080" \
    "egress:" "  - api.internal.example.com" "secrets:" "  - GOOD_TOKEN"
  catalogue_validate_entry "$(catalogue_resolve good)" good \
    || fail "sound entry should validate"
  pass "sound entry validates"
}

test_validate_rejects() {
  info "Testing validation failures..."

  # Mutable tag (no digest).
  write_org_entry tagimg "name: tagimg" "kind: mcp" "image: ghcr.io/x/t:latest" "port: 8080"
  catalogue_validate_entry "$(catalogue_resolve tagimg)" tagimg 2>/dev/null \
    && fail "mutable-tag image should be rejected"
  pass "mutable-tag image rejected"

  # Bad kind.
  write_org_entry badkind "name: badkind" "kind: widget" "image: ghcr.io/x/b@${DIGEST}" "port: 8080"
  catalogue_validate_entry "$(catalogue_resolve badkind)" badkind 2>/dev/null \
    && fail "bad kind should be rejected"
  pass "bad kind rejected"

  # Bad port.
  write_org_entry badport "name: badport" "kind: service" "image: ghcr.io/x/b@${DIGEST}" "port: 99999"
  catalogue_validate_entry "$(catalogue_resolve badport)" badport 2>/dev/null \
    && fail "out-of-range port should be rejected"
  pass "out-of-range port rejected"

  # Blocked egress domain.
  write_org_entry blockedegress "name: blockedegress" "kind: service" \
    "image: ghcr.io/x/b@${DIGEST}" "port: 9000" "egress:" "  - hooks.slack.com"
  catalogue_validate_entry "$(catalogue_resolve blockedegress)" blockedegress 2>/dev/null \
    && fail "blocked egress should be rejected"
  pass "blocked egress rejected"

  # Allow-all egress.
  write_org_entry starall "name: starall" "kind: service" \
    "image: ghcr.io/x/b@${DIGEST}" "port: 9000" "egress:" "  - '*'"
  catalogue_validate_entry "$(catalogue_resolve starall)" starall 2>/dev/null \
    && fail "allow-all egress should be rejected"
  pass "allow-all egress rejected"

  # Invalid secret name (lowercase).
  write_org_entry badsecret "name: badsecret" "kind: service" \
    "image: ghcr.io/x/b@${DIGEST}" "port: 9000" "secrets:" "  - lower-case"
  catalogue_validate_entry "$(catalogue_resolve badsecret)" badsecret 2>/dev/null \
    && fail "invalid secret name should be rejected"
  pass "invalid secret name rejected"
}

###############################################################################
# Phase 3 — browser-class hardening + privilege-escalation refusal
###############################################################################
test_validate_rejects_privilege_escalation() {
  info "Testing privilege-escalation fields are rejected..."

  # cap_add written as a block list (catalogue_field is scalar-only — this is
  # the case catalogue_has_key exists to catch).
  write_org_entry capadd "name: capadd" "kind: service" \
    "image: ghcr.io/x/c@${DIGEST}" "port: 9000" "cap_add:" "  - SYS_ADMIN"
  catalogue_validate_entry "$(catalogue_resolve capadd)" capadd 2>/dev/null \
    && fail "cap_add should be rejected"
  pass "cap_add (list) rejected"

  # privileged as a scalar.
  write_org_entry priv "name: priv" "kind: service" \
    "image: ghcr.io/x/p@${DIGEST}" "port: 9000" "privileged: true"
  catalogue_validate_entry "$(catalogue_resolve priv)" priv 2>/dev/null \
    && fail "privileged should be rejected"
  pass "privileged rejected"

  # host_network.
  write_org_entry hnet "name: hnet" "kind: service" \
    "image: ghcr.io/x/h@${DIGEST}" "port: 9000" "host_network: true"
  catalogue_validate_entry "$(catalogue_resolve hnet)" hnet 2>/dev/null \
    && fail "host_network should be rejected"
  pass "host_network rejected"
}

test_validate_browser_class() {
  info "Testing browser-class signature requirements..."

  # A browser entry without verify_signature is rejected.
  write_org_entry br1 "name: br1" "kind: mcp" "class: browser" \
    "image: mcr/x@${DIGEST}" "port: 8931"
  catalogue_validate_entry "$(catalogue_resolve br1)" br1 2>/dev/null \
    && fail "browser without verify_signature should be rejected"
  pass "browser requires verify_signature"

  # verify_signature: true but neither key nor identity/issuer → rejected.
  write_org_entry br2 "name: br2" "kind: mcp" "class: browser" \
    "image: mcr/x@${DIGEST}" "port: 8931" "verify_signature: true"
  catalogue_validate_entry "$(catalogue_resolve br2)" br2 2>/dev/null \
    && fail "verify_signature without key/identity should be rejected"
  pass "verify_signature without key/identity rejected"
}

main() {
  test_resolution_order
  test_invalid_names
  test_fields_and_defaults
  test_validate_good
  test_validate_rejects
  test_validate_rejects_privilege_escalation
  test_validate_browser_class
  echo "All catalogue tests passed."
}
main "$@"
