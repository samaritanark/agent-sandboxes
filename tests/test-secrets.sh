#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-secrets.sh — Host-side secret store tests
# Verifies: name validation, set from stdin, set from file, list, delete,
# secret_get_value error on missing, idempotent re-create from cmd_secret.
# Cluster-side helpers (create_session_secrets / delete_session_secrets)
# are touched only structurally — they need a live k3s cluster to fully
# exercise, which the cluster-required test suite covers.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-secrets"
TEST_DIR="$(mktemp -d /tmp/sandbox-secrets-test-XXXXXX)"

fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
  rm -rf "${TEST_DIR}"
}
trap cleanup EXIT

# Point the store at a temp dir for the whole test — we never touch the
# developer's real ~/.sandbox/secrets/ this way.
export SANDBOX_SECRETS_DIR="${TEST_DIR}/secrets"
SANDBOX_NAMESPACE="sandbox"  # referenced by cluster helpers, not exercised here

# shellcheck disable=SC1091
source "${SANDBOX_ROOT}/lib/secrets.sh"

eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    pass "${label}"
  else
    fail "${label}: expected '${expected}', got '${actual}'"
  fi
}

###############################################################################
# Name validation
###############################################################################
test_validate_name_accepts_envvar_style() {
  info "Testing secret_validate_name accepts env-var-style names..."

  local n
  for n in JIRA_PAT GITEA_TOKEN _LEADING_UNDERSCORE A B12 LONG_NAME_WITH_UNDERSCORES; do
    if ! ( secret_validate_name "${n}" 2>/dev/null ); then
      fail "valid name rejected: ${n}"
    fi
  done
  pass "all valid names accepted"
}

test_validate_name_rejects_bad() {
  info "Testing secret_validate_name rejects malformed names..."

  local n
  for n in "" lowercase "Mixed_Case" "1LEADING_DIGIT" "HAS-DASH" "HAS SPACE" "HAS.DOT"; do
    if ( secret_validate_name "${n}" 2>/dev/null ); then
      fail "invalid name accepted: '${n}'"
    fi
  done
  pass "all invalid names rejected"

  # Length cap
  local long
  long="$(printf 'A%.0s' $(seq 1 65))"
  if ( secret_validate_name "${long}" 2>/dev/null ); then
    fail "65-char name accepted (should be capped at 64)"
  fi
  pass "over-length name rejected"
}

###############################################################################
# Set / get / delete cycle
###############################################################################
test_set_from_stdin() {
  info "Testing secret_set_from_stdin..."

  echo "tok-abcd1234" | secret_set_from_stdin JIRA_PAT
  [[ -f "${SANDBOX_SECRETS_DIR}/JIRA_PAT" ]] \
    && pass "store file created" \
    || fail "store file missing"

  eq "store mode 0600" "600" "$(stat -c '%a' "${SANDBOX_SECRETS_DIR}/JIRA_PAT")"
  eq "value round-trips"   "tok-abcd1234" "$(secret_get_value JIRA_PAT | tr -d '\n')"
  ( secret_exists JIRA_PAT ) && pass "secret_exists returns 0 for stored name" \
                              || fail "secret_exists should be 0"
}

test_set_from_stdin_no_trailing_newline() {
  info "Testing that secret values can be raw (no trailing newline)..."

  # printf — no trailing newline
  printf '%s' "rawvalue" | secret_set_from_stdin RAW_VALUE
  eq "raw byte-for-byte" "rawvalue" "$(secret_get_value RAW_VALUE)"
}

test_set_from_file() {
  info "Testing secret_set_from_file..."

  local src="${TEST_DIR}/srcfile"
  printf '%s' "from-file-value" > "${src}"
  secret_set_from_file GITEA_TOKEN "${src}"

  eq "value matches file"  "from-file-value" "$(secret_get_value GITEA_TOKEN)"
  eq "store mode 0600"     "600"             "$(stat -c '%a' "${SANDBOX_SECRETS_DIR}/GITEA_TOKEN")"

  # Missing source file → exits
  ( secret_set_from_file BAD_TOKEN "${TEST_DIR}/nope" 2>/dev/null ) \
    && fail "set_from_file with missing source should have failed" \
    || pass "set_from_file rejects missing source"
}

test_set_from_env() {
  info "Testing secret_set_from_env (happy path)..."

  # Use a uniquely-named env var so it can't collide with anything in the
  # test runner's environment.
  export TEST_SECRETS_FROM_ENV_SRC="env-token-value"
  secret_set_from_env FROM_ENV_DEST TEST_SECRETS_FROM_ENV_SRC

  eq "value pulled from env" "env-token-value" "$(secret_get_value FROM_ENV_DEST)"
  eq "store mode 0600"       "600"             "$(stat -c '%a' "${SANDBOX_SECRETS_DIR}/FROM_ENV_DEST")"
  unset TEST_SECRETS_FROM_ENV_SRC
}

test_set_from_env_unset_var() {
  info "Testing secret_set_from_env errors on unset source var..."

  unset TEST_SECRETS_UNSET 2>/dev/null || true
  ( secret_set_from_env FROM_ENV_UNSET TEST_SECRETS_UNSET 2>/dev/null ) \
    && fail "set_from_env on unset var should have failed" \
    || pass "set_from_env on unset var exits non-zero"

  # And it must NOT have created the destination file.
  [[ ! -f "${SANDBOX_SECRETS_DIR}/FROM_ENV_UNSET" ]] \
    && pass "no store file on unset-var failure" \
    || fail "store file should not exist after failed set_from_env"
}

test_set_from_env_empty_var() {
  info "Testing secret_set_from_env errors on empty source var..."

  export TEST_SECRETS_EMPTY=""
  ( secret_set_from_env FROM_ENV_EMPTY TEST_SECRETS_EMPTY 2>/dev/null ) \
    && fail "set_from_env on empty var should have failed" \
    || pass "set_from_env on empty var exits non-zero"

  [[ ! -f "${SANDBOX_SECRETS_DIR}/FROM_ENV_EMPTY" ]] \
    && pass "no store file on empty-var failure" \
    || fail "store file should not exist after failed set_from_env"
  unset TEST_SECRETS_EMPTY
}

test_set_overwrites() {
  info "Testing that secret_set overwrites an existing entry..."

  echo "first" | secret_set_from_stdin OVERWRITE_TEST
  echo "second" | secret_set_from_stdin OVERWRITE_TEST
  eq "overwritten value" "second" "$(secret_get_value OVERWRITE_TEST | tr -d '\n')"
}

test_get_missing_dies() {
  info "Testing secret_get_value on a missing name..."

  ( secret_get_value NEVER_STORED 2>/dev/null ) \
    && fail "get on missing secret should have failed" \
    || pass "get on missing secret exits non-zero"
}

test_delete() {
  info "Testing secret_delete..."

  echo "delete-me" | secret_set_from_stdin TO_DELETE
  ( secret_exists TO_DELETE ) || fail "stored secret not present before delete"
  secret_delete TO_DELETE
  ( secret_exists TO_DELETE ) && fail "secret still present after delete"
  pass "delete removes the store file"

  # Idempotent — second delete is a no-op (no error)
  secret_delete TO_DELETE
  pass "second delete is a no-op"
}

###############################################################################
# Listing
###############################################################################
test_list_format() {
  info "Testing secret_list output format..."

  # Clear store
  rm -rf "${SANDBOX_SECRETS_DIR}"
  echo "a" | secret_set_from_stdin LIST_A
  echo "bb" | secret_set_from_stdin LIST_B

  local out
  out="$(secret_list)"
  local n
  n="$(echo "${out}" | wc -l | tr -d ' ')"
  eq "list line count" "2" "${n}"

  # Each line starts with the name
  echo "${out}" | grep -q '^LIST_A' && pass "list includes LIST_A" \
    || fail "list missing LIST_A: ${out}"
  echo "${out}" | grep -q '^LIST_B' && pass "list includes LIST_B" \
    || fail "list missing LIST_B"

  # Values must NEVER appear in the output (sanity)
  if echo "${out}" | grep -q 'bb'; then
    # 'bb' is the actual stored value of LIST_B — if it shows up, list
    # is leaking values. (Risk of false positive if a stat field
    # contains the literal "bb"; vanishingly unlikely.)
    fail "list output appears to contain a secret value"
  fi
  pass "list does not leak secret values"
}

test_list_empty() {
  info "Testing secret_list with no store..."

  rm -rf "${SANDBOX_SECRETS_DIR}"
  local out
  out="$(secret_list)"
  eq "empty store → empty output" "" "${out}"
}

###############################################################################
# session_secrets_name — used by manifest layer
###############################################################################
test_session_secrets_name() {
  info "Testing session_secrets_name..."
  eq "name format" "session-secrets-ses-abc" "$(session_secrets_name ses-abc)"
}

###############################################################################
# create_dependency_secrets — Phase 5 per-dependency bundle. The cluster path
# needs a live k3s (covered by the cluster suite); here we exercise only the
# zero-names no-op branch, which must return success WITHOUT calling kubectl.
###############################################################################
test_create_dependency_secrets_noop() {
  info "Testing create_dependency_secrets no-op with zero names..."
  # If this reached kubectl it would fail (no cluster); a clean rc=0 proves the
  # early return fired.
  create_dependency_secrets "dep-x-ses-abc" "ses-abc" || fail "zero-name bundle should be a no-op success"
  pass "zero-name dependency bundle is a no-op"
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""
  echo "Store directory: ${SANDBOX_SECRETS_DIR}"
  echo ""

  test_validate_name_accepts_envvar_style
  test_validate_name_rejects_bad
  test_set_from_stdin
  test_set_from_stdin_no_trailing_newline
  test_set_from_file
  test_set_from_env
  test_set_from_env_unset_var
  test_set_from_env_empty_var
  test_set_overwrites
  test_get_missing_dies
  test_delete
  test_list_format
  test_list_empty
  test_session_secrets_name
  test_create_dependency_secrets_noop

  echo ""
  echo "All secrets tests passed."
}

main "$@"
