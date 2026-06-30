#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-secret-gate.sh — Secret gate + configurable masking tests
# Verifies: is_path_masked covers the built-in + configured masked set;
# config_add_masked_path writes/dedups masked_paths into a repo config;
# scan_repo_secrets classifies findings as masked/unmasked; secret_gate_repos
# refuses on an unmasked secret, passes once it is masked, and proceeds (with
# a notice) under --i-accept-unmasked-secrets. Cluster-free; the scan cases
# skip gracefully when betterleaks is not installed.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-secret-gate"
TEST_DIR="$(mktemp -d /tmp/sandbox-secret-gate-XXXXXX)"

fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() { rm -rf "${TEST_DIR}"; }
trap cleanup EXIT

# Units under test. config.sh provides the read/write helpers that
# filesystem.sh's masking/gate logic consumes; platform.sh + manifest.sh
# are needed for the volume-mount emission check.
source "${SANDBOX_ROOT}/lib/platform.sh"
source "${SANDBOX_ROOT}/lib/config.sh"
source "${SANDBOX_ROOT}/lib/filesystem.sh"
source "${SANDBOX_ROOT}/lib/manifest.sh"

# eq <label> <expected> <actual>
eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    pass "${label}"
  else
    fail "${label}: expected '${expected}', got '${actual}'"
  fi
}

# A throwaway git repo with a couple of non-allowlisted secrets. betterleaks
# allowlists canonical example keys (AKIAIOSFODNN7EXAMPLE, ...), so the
# planted values are deliberately not those.
make_repo() {
  local repo="$1"
  mkdir -p "${repo}/nested"
  git -C "${repo}" init -q
  git -C "${repo}" config user.email "test@sandbox"
  git -C "${repo}" config user.name "Test"
  printf 'AWS_SECRET_ACCESS_KEY=wJalrXKtZFEMs3K7zDpNGabPxRfiZYz9Qm2VnT4u\n' > "${repo}/.env"
  printf 'github_pat=ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z\n' > "${repo}/nested/config.txt"
}

###############################################################################
# is_path_masked — built-in + configured truth table
###############################################################################
test_is_path_masked() {
  info "Testing is_path_masked..."
  local repo="${TEST_DIR}/masktruth"
  mkdir -p "${repo}/.sandbox"

  is_path_masked "${repo}" ".env"            && pass "built-in .env masked"        || fail ".env should be masked"
  is_path_masked "${repo}" ".npmrc"          && pass "built-in .npmrc masked"      || fail ".npmrc should be masked"
  is_path_masked "${repo}" ".kube/config"    && pass ".kube/* masked"              || fail ".kube/config should be masked"
  is_path_masked "${repo}" "admin-openrc.sh" && pass "root *-openrc.sh masked"     || fail "openrc should be masked"

  is_path_masked "${repo}" "nested/config.txt" && fail "nested file should NOT be masked" || pass "nested unmasked"
  is_path_masked "${repo}" "sub/admin-openrc.sh" && fail "nested openrc should NOT be masked" || pass "nested openrc unmasked"
  is_path_masked "${repo}" ".env.production" && fail ".env.production not in built-in set" || pass ".env.production unmasked"

  # After configuring it, the nested file becomes masked.
  printf 'masked_paths:\n  - "nested/config.txt"\n' > "${repo}/.sandbox/config.yaml"
  is_path_masked "${repo}" "nested/config.txt" && pass "configured path masked" || fail "configured nested should be masked"
}

###############################################################################
# config_add_masked_path — create, dedup, coexist with other keys
###############################################################################
test_config_add_masked_path() {
  info "Testing config_add_masked_path..."
  local cfg="${TEST_DIR}/cfgwrite/.sandbox/config.yaml"

  config_add_masked_path "${cfg}" "nested/config.txt"
  eq "creates masked_paths key" "nested/config.txt" \
     "$(load_repo_masked_paths "${TEST_DIR}/cfgwrite")"

  # Idempotent — re-adding the same path does not duplicate it.
  config_add_masked_path "${cfg}" "nested/config.txt"
  local count
  count="$(load_repo_masked_paths "${TEST_DIR}/cfgwrite" | wc -l | tr -d ' ')"
  eq "dedup keeps one entry" "1" "${count}"

  # A second distinct path is appended.
  config_add_masked_path "${cfg}" "secrets/prod.yaml"
  count="$(load_repo_masked_paths "${TEST_DIR}/cfgwrite" | wc -l | tr -d ' ')"
  eq "second path appended" "2" "${count}"

  # Coexists with a pre-existing extra_allowed_domains block.
  local cfg2="${TEST_DIR}/cfgcoexist/.sandbox/config.yaml"
  mkdir -p "$(dirname "${cfg2}")"
  printf 'extra_allowed_domains:\n  - git.example.com\n' > "${cfg2}"
  config_add_masked_path "${cfg2}" "creds.json"
  eq "domains preserved" "git.example.com" \
     "$(load_extra_allowed_domains_from_file "${cfg2}")"
  eq "mask added alongside" "creds.json" \
     "$(load_repo_masked_paths "${TEST_DIR}/cfgcoexist")"
}

###############################################################################
# scan_repo_secrets — classifies findings as masked / unmasked
###############################################################################
test_scan_classification() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  info "Testing scan_repo_secrets classification..."

  local repo="${TEST_DIR}/scan"
  make_repo "${repo}"

  local out="${TEST_DIR}/scan.out"
  scan_repo_secrets "${repo}" > "${out}"

  # The root .env secret is masked (built-in); the nested one is not.
  grep -q "$(printf '^yes\t.env\t')" "${out}"            && pass ".env classified masked"    || fail ".env should be masked finding"
  grep -q "$(printf '^no\tnested/config.txt\t')" "${out}" && pass "nested classified unmasked" || fail "nested should be unmasked finding"

  # Secret values must be redacted — the raw token must not appear.
  if grep -q "ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z" "${out}"; then
    fail "raw secret leaked into scan output (should be redacted)"
  fi
  pass "secret values redacted in output"
}

###############################################################################
# secret_gate_repos — refuse, then pass after masking, then override
###############################################################################
test_gate() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  info "Testing secret_gate_repos..."

  local repo="${TEST_DIR}/gate"
  make_repo "${repo}"

  # Without masking and without override → refuse (exit non-zero). Run in a
  # subshell so the gate's `exit 1` doesn't take down the test.
  if ( secret_gate_repos "false" "${repo}" >/dev/null 2>&1 ); then
    fail "gate should refuse on an unmasked secret"
  fi
  pass "gate refuses on unmasked secret"

  # Override → proceeds (exit 0) despite the unmasked secret.
  if ( secret_gate_repos "true" "${repo}" >/dev/null 2>&1 ); then
    pass "override proceeds despite unmasked secret"
  else
    fail "override should proceed"
  fi

  # Mask the offending file → gate passes.
  config_add_masked_path "${repo}/.sandbox/config.yaml" "nested/config.txt"
  if ( secret_gate_repos "false" "${repo}" >/dev/null 2>&1 ); then
    pass "gate passes once the secret is masked"
  else
    fail "gate should pass after masking the file"
  fi
}

###############################################################################
# Fail closed on scanner failure — a betterleaks runtime error must NOT look
# like "no secrets found". Uses a stub betterleaks that exits non-zero without
# writing a report (the nastiest case: exit 1 is also the leaks-found code).
###############################################################################
test_scan_failure_fails_closed() {
  command -v jq &>/dev/null || skip "jq not installed"
  info "Testing fail-closed on betterleaks scan failure..."

  local repo="${TEST_DIR}/scanfail"
  make_repo "${repo}"

  # Stub that mimics a crash: exit 1, leave the report path empty/unwritten.
  local stub="${TEST_DIR}/stubbin"
  mkdir -p "${stub}"
  cat > "${stub}/betterleaks" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
  chmod +x "${stub}/betterleaks"

  # scan_repo_secrets emits an `error` sentinel rather than zero findings.
  local out
  out="$(PATH="${stub}:${PATH}" scan_repo_secrets "${repo}")"
  if printf '%s\n' "${out}" | grep -q "$(printf '^error\t')"; then
    pass "scan emits error sentinel on scanner failure"
  else
    fail "expected an 'error' sentinel line, got: ${out}"
  fi

  # The gate refuses the launch (exit non-zero) on that sentinel...
  if ( PATH="${stub}:${PATH}" secret_gate_repos "false" "${repo}" >/dev/null 2>&1 ); then
    fail "gate should refuse when the scanner fails"
  fi
  pass "gate refuses on scanner failure"

  # ...and the override does NOT bypass a failed scan (it accepts known
  # secrets, not an uninspected workspace).
  if ( PATH="${stub}:${PATH}" secret_gate_repos "true" "${repo}" >/dev/null 2>&1 ); then
    fail "override should not bypass a failed scan"
  fi
  pass "override does not bypass a failed scan"
}

###############################################################################
# build_volume_mounts_block — a configured masked_path becomes an overlay mount
###############################################################################
test_manifest_mount() {
  info "Testing configured masked_paths reach the pod manifest..."
  local repo="${TEST_DIR}/manifest"
  make_repo "${repo}"
  config_add_masked_path "${repo}/.sandbox/config.yaml" "nested/config.txt"

  # Single repo → workspace mounts at /workspace; the configured nested file
  # gets an overlay-empty-file mount at /workspace/nested/config.txt.
  local block
  block="$(build_volume_mounts_block 2 "" "" "" "${repo}")"
  if echo "${block}" | grep -q "mountPath: /workspace/nested/config.txt"; then
    pass "configured masked_path emits an overlay mount"
  else
    fail "expected overlay mount for nested/config.txt in:\n${block}"
  fi
  # The built-in .env overlay is still emitted alongside it.
  echo "${block}" | grep -q "mountPath: /workspace/.env" \
    && pass "built-in .env overlay still emitted" \
    || fail "built-in .env overlay missing"
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""
  echo "Test directory: ${TEST_DIR}"
  echo ""

  test_is_path_masked
  test_config_add_masked_path
  test_manifest_mount
  test_scan_classification
  test_gate
  test_scan_failure_fails_closed

  echo ""
  echo "All secret-gate tests passed."
}

main "$@"
