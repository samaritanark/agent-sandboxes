#!/usr/bin/env bash
# tests/test-profile.sh — Profile + overlay resolution tests
# Verifies: is_numeric_profile, resolve_overlay_path (env vs config file),
# find_profile_path (user wins over overlay), and the overlay-aware
# extension of check_domain_not_blocked. Cluster-free.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-profile"
TEST_DIR="$(mktemp -d /tmp/sandbox-profile-test-XXXXXX)"
HOME="${TEST_DIR}/home"
mkdir -p "${HOME}"

fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
  rm -rf "${TEST_DIR}"
}
trap cleanup EXIT

# Point the global at the per-test HOME so we don't read the developer's
# real ~/.sandbox/config.yaml during the run.
USER_SANDBOX_CONFIG="${HOME}/.sandbox/config.yaml"

source "${SANDBOX_ROOT}/lib/platform.sh"
source "${SANDBOX_ROOT}/lib/config.sh"
source "${SANDBOX_ROOT}/lib/profile.sh"
source "${SANDBOX_ROOT}/lib/checks.sh"

eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    pass "${label}"
  else
    fail "${label}: expected '${expected}', got '${actual}'"
  fi
}

###############################################################################
# is_numeric_profile
###############################################################################
test_is_numeric_profile() {
  info "Testing is_numeric_profile..."

  for n in 1 2 3; do
    if ! is_numeric_profile "${n}"; then
      fail "is_numeric_profile ${n} should be true"
    fi
  done
  pass "is_numeric_profile recognizes 1, 2, 3"

  for n in 0 4 5 foo bar "" "1.0"; do
    if is_numeric_profile "${n}"; then
      fail "is_numeric_profile '${n}' should be false"
    fi
  done
  pass "is_numeric_profile rejects non-tier values"
}

###############################################################################
# resolve_overlay_path
###############################################################################
test_resolve_overlay_env() {
  info "Testing resolve_overlay_path from SANDBOX_OVERLAY env..."

  eq "env wins"           "/path/to/overlay" \
                          "$(SANDBOX_OVERLAY=/path/to/overlay resolve_overlay_path)"
  eq "tilde expansion"    "${HOME}/o" \
                          "$(SANDBOX_OVERLAY='~/o' resolve_overlay_path)"
  eq "unset → empty"      "" \
                          "$(SANDBOX_OVERLAY="" resolve_overlay_path)"
}

test_resolve_overlay_config_file() {
  info "Testing resolve_overlay_path from ~/.sandbox/config.yaml..."

  mkdir -p "${HOME}/.sandbox"
  cat > "${HOME}/.sandbox/config.yaml" <<'YAML'
overlay: ~/team-overlay
extra_allowed_domains:
  - some.example.com
YAML

  # SANDBOX_OVERLAY unset → fall through to the config file's overlay: key
  unset SANDBOX_OVERLAY
  eq "config file overlay key" "${HOME}/team-overlay" "$(resolve_overlay_path)"

  # SANDBOX_OVERLAY wins over the file
  eq "env beats file" "/from/env" "$(SANDBOX_OVERLAY=/from/env resolve_overlay_path)"

  rm -f "${HOME}/.sandbox/config.yaml"
}

###############################################################################
# find_profile_path — user dir wins over overlay
###############################################################################
test_find_profile_path() {
  info "Testing find_profile_path lookup order..."

  local overlay="${TEST_DIR}/overlay"
  mkdir -p "${HOME}/.sandbox/profiles" "${overlay}/profiles"

  # Only in overlay → resolves to overlay
  echo "tier: 2" > "${overlay}/profiles/team-only.yaml"
  unset SANDBOX_OVERLAY
  eq "resolves overlay-only profile" \
     "${overlay}/profiles/team-only.yaml" \
     "$(SANDBOX_OVERLAY="${overlay}" find_profile_path team-only)"

  # In both user and overlay → user wins
  echo "tier: 1" > "${HOME}/.sandbox/profiles/shared.yaml"
  echo "tier: 3" > "${overlay}/profiles/shared.yaml"
  eq "user dir wins over overlay" \
     "${HOME}/.sandbox/profiles/shared.yaml" \
     "$(SANDBOX_OVERLAY="${overlay}" find_profile_path shared)"

  # Missing → returns 1 with no output
  local out
  if out="$(SANDBOX_OVERLAY="${overlay}" find_profile_path no-such-profile 2>&1)"; then
    fail "missing profile should have failed, but returned: ${out}"
  fi
  pass "missing profile returns non-zero"

  # No overlay configured + user-only profile
  unset SANDBOX_OVERLAY
  rm -f "${HOME}/.sandbox/profiles/shared.yaml"
  echo "tier: 2" > "${HOME}/.sandbox/profiles/user-only.yaml"
  eq "user-only profile, no overlay" \
     "${HOME}/.sandbox/profiles/user-only.yaml" \
     "$(find_profile_path user-only)"
}

###############################################################################
# overlay_blocked_destinations_file
###############################################################################
test_overlay_blocked_destinations_file() {
  info "Testing overlay_blocked_destinations_file..."

  local overlay="${TEST_DIR}/overlay-with-blocks"
  mkdir -p "${overlay}"

  # No overlay configured → empty
  unset SANDBOX_OVERLAY
  eq "no overlay → empty path" "" "$(overlay_blocked_destinations_file)"

  # Overlay configured but no blocked-destinations.yaml → empty
  eq "overlay without blocked file → empty" "" \
     "$(SANDBOX_OVERLAY="${overlay}" overlay_blocked_destinations_file)"

  # File present → returns the path
  cat > "${overlay}/blocked-destinations.yaml" <<'YAML'
blocked_domains:
  - "blocked.example.com"
YAML
  eq "overlay file path" "${overlay}/blocked-destinations.yaml" \
     "$(SANDBOX_OVERLAY="${overlay}" overlay_blocked_destinations_file)"
}

###############################################################################
# check_domain_not_blocked — overlay extends, cannot weaken
#
# Each case runs in a subshell so the `exit 1` inside check_domain_not_blocked
# (on a blocked match) does not terminate the parent test.
###############################################################################
test_check_domain_with_overlay() {
  info "Testing check_domain_not_blocked overlay extension..."

  local overlay="${TEST_DIR}/overlay-blocks"
  mkdir -p "${overlay}"
  cat > "${overlay}/blocked-destinations.yaml" <<'YAML'
blocked_domains:
  - "overlay-blocked.example.com"
  - "*.overlay-wild.example.com"
YAML

  # Allowed under both org file + overlay file
  ( SANDBOX_OVERLAY="${overlay}" check_domain_not_blocked github.com >/dev/null 2>&1 ) \
    && pass "allowed domain (not in either block list)" \
    || fail "github.com should not be blocked"

  # Org-level block still wins (pastebin.com is in the shipped
  # config/blocked-destinations.yaml). Overlay must not weaken it.
  ( SANDBOX_OVERLAY="${overlay}" check_domain_not_blocked pastebin.com >/dev/null 2>&1 ) \
    && fail "pastebin.com should still be blocked by the org file" \
    || pass "org-level block holds with overlay configured"

  # Overlay-only block
  ( SANDBOX_OVERLAY="${overlay}" check_domain_not_blocked overlay-blocked.example.com >/dev/null 2>&1 ) \
    && fail "overlay-blocked domain should be blocked" \
    || pass "overlay exact-match block applies"

  # Overlay wildcard
  ( SANDBOX_OVERLAY="${overlay}" check_domain_not_blocked sub.overlay-wild.example.com >/dev/null 2>&1 ) \
    && fail "overlay wildcard subdomain should be blocked" \
    || pass "overlay wildcard block applies"

  # No overlay configured → only org check (sanity)
  unset SANDBOX_OVERLAY
  ( check_domain_not_blocked github.com >/dev/null 2>&1 ) \
    && pass "no overlay → org-only path still works" \
    || fail "github.com should pass with no overlay"
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""
  echo "Test directory: ${TEST_DIR}"
  echo "HOME override:  ${HOME}"
  echo ""

  test_is_numeric_profile
  test_resolve_overlay_env
  test_resolve_overlay_config_file
  test_find_profile_path
  test_overlay_blocked_destinations_file
  test_check_domain_with_overlay

  echo ""
  echo "All profile/overlay tests passed."
}

main "$@"
