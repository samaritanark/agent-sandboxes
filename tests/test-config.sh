#!/usr/bin/env bash
# tests/test-config.sh — YAML helper + persistent-extras loader tests
# Verifies: extract_yaml_{scalar,list}_from_file parse the formats we
# document; load_extra_allowed_domains_from_file wraps the list helper
# correctly; load_user_extra_allowed_domains honors USER_SANDBOX_CONFIG
# and SANDBOX_EXTRA_ALLOWED_DOMAINS together. Cluster-free.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-config"
TEST_DIR="$(mktemp -d /tmp/sandbox-config-test-XXXXXX)"

fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
  rm -rf "${TEST_DIR}"
}
trap cleanup EXIT

# Source the unit under test. lib/config.sh references USER_SANDBOX_CONFIG
# at function-call time via the global default, so we override it per case.
USER_SANDBOX_CONFIG="${TEST_DIR}/never-existed.yaml"
source "${SANDBOX_ROOT}/lib/config.sh"

# eq <label> <expected> <actual>
eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    pass "${label}"
  else
    fail "${label}: expected '${expected}', got '${actual}'"
  fi
}

###############################################################################
# extract_yaml_scalar_from_file
###############################################################################
test_scalar_extraction() {
  info "Testing extract_yaml_scalar_from_file..."

  local f="${TEST_DIR}/scalar.yaml"
  cat > "${f}" <<'YAML'
tier: 2
default_repo: ~/repos/dev-app
profile: "quoted-name"
single: 'single-quoted'
trailing: value-with-trailing-spaces
with_comment: actual-value  # inline comment should not leak
YAML

  eq "plain scalar"        "2"               "$(extract_yaml_scalar_from_file "${f}" tier)"
  eq "scalar with tilde"   "~/repos/dev-app" "$(extract_yaml_scalar_from_file "${f}" default_repo)"
  eq "double-quoted"       "quoted-name"     "$(extract_yaml_scalar_from_file "${f}" profile)"
  eq "single-quoted"       "single-quoted"   "$(extract_yaml_scalar_from_file "${f}" single)"
  eq "trailing whitespace" "value-with-trailing-spaces" \
                                             "$(extract_yaml_scalar_from_file "${f}" trailing)"
  eq "inline comment stripped" "actual-value" \
                                             "$(extract_yaml_scalar_from_file "${f}" with_comment)"
  eq "missing key returns empty" ""           "$(extract_yaml_scalar_from_file "${f}" no_such_key)"
  eq "missing file returns empty" ""          "$(extract_yaml_scalar_from_file "${TEST_DIR}/nope" tier)"
}

###############################################################################
# extract_yaml_list_from_file — block-style with bounded extraction
###############################################################################
test_list_extraction() {
  info "Testing extract_yaml_list_from_file..."

  local f="${TEST_DIR}/list.yaml"
  cat > "${f}" <<'YAML'
# Comment line above the key
extra_allowed_domains:
  - one.example.com
  - "two.example.com"
  - 'three.example.com'
  - four.example.com  # inline comment
secrets:
  - secret-a
  - secret-b
# Another top-level
tier: 2
YAML

  local domains
  domains="$(extract_yaml_list_from_file "${f}" extra_allowed_domains)"
  eq "extra_allowed_domains line count" "4" "$(echo "${domains}" | wc -l | tr -d ' ')"
  eq "first entry"                      "one.example.com"   "$(echo "${domains}" | sed -n 1p)"
  eq "double-quoted entry stripped"     "two.example.com"   "$(echo "${domains}" | sed -n 2p)"
  eq "single-quoted entry stripped"     "three.example.com" "$(echo "${domains}" | sed -n 3p)"
  eq "inline comment stripped"          "four.example.com"  "$(echo "${domains}" | sed -n 4p)"

  # Bounded extraction: list under 'secrets:' must NOT bleed into a
  # separate list query above it (and the trailing 'tier:' top-level key
  # must terminate it).
  local secrets
  secrets="$(extract_yaml_list_from_file "${f}" secrets)"
  eq "secrets line count" "2" "$(echo "${secrets}" | wc -l | tr -d ' ')"

  # tier is a scalar, not a list — list extraction should return empty.
  local empty
  empty="$(extract_yaml_list_from_file "${f}" tier)"
  eq "scalar key returns no list items" "" "${empty}"

  # Missing file → empty
  eq "missing file returns empty list" "" "$(extract_yaml_list_from_file "${TEST_DIR}/nope" extra_allowed_domains)"
}

###############################################################################
# load_extra_allowed_domains_from_file — the per-file wrapper used by both
# user and per-repo config loading
###############################################################################
test_per_file_loader() {
  info "Testing load_extra_allowed_domains_from_file..."

  local f="${TEST_DIR}/per-repo.yaml"
  cat > "${f}" <<'YAML'
extra_allowed_domains:
  - internal-registry.example.com
  - go.private.example.com
YAML

  local out
  out="$(load_extra_allowed_domains_from_file "${f}")"
  eq "loader line count" "2" "$(echo "${out}" | wc -l | tr -d ' ')"
  eq "first" "internal-registry.example.com" "$(echo "${out}" | sed -n 1p)"
  eq "second" "go.private.example.com"       "$(echo "${out}" | sed -n 2p)"

  # Missing file → empty (no error)
  eq "loader on missing file → empty" "" "$(load_extra_allowed_domains_from_file "${TEST_DIR}/nope")"
}

###############################################################################
# load_user_extra_allowed_domains — file + env var union
###############################################################################
test_user_loader_combined() {
  info "Testing load_user_extra_allowed_domains (file + env var)..."

  local f="${TEST_DIR}/user-config.yaml"
  cat > "${f}" <<'YAML'
extra_allowed_domains:
  - file-a.example.com
  - file-b.example.com
YAML

  USER_SANDBOX_CONFIG="${f}" \
  SANDBOX_EXTRA_ALLOWED_DOMAINS="env-c.example.com,env-d.example.com" \
    load_user_extra_allowed_domains > "${TEST_DIR}/out"

  local n
  n="$(wc -l < "${TEST_DIR}/out" | tr -d ' ')"
  eq "combined line count" "4" "${n}"
  eq "file source first"  "file-a.example.com" "$(sed -n 1p "${TEST_DIR}/out")"
  eq "env source picked up" "env-c.example.com" "$(sed -n 3p "${TEST_DIR}/out")"
  eq "env entries trimmed of whitespace" "env-d.example.com" "$(sed -n 4p "${TEST_DIR}/out")"

  # Env-only (no file)
  USER_SANDBOX_CONFIG="${TEST_DIR}/no-such-file" \
  SANDBOX_EXTRA_ALLOWED_DOMAINS="only-env.example.com" \
    load_user_extra_allowed_domains > "${TEST_DIR}/out2"
  eq "env-only single line" "only-env.example.com" "$(cat "${TEST_DIR}/out2")"
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""
  echo "Test directory: ${TEST_DIR}"
  echo ""

  test_scalar_extraction
  test_list_extraction
  test_per_file_loader
  test_user_loader_combined

  echo ""
  echo "All config tests passed."
}

main "$@"
