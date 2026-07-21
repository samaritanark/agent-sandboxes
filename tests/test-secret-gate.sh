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
source "${SANDBOX_ROOT}/lib/profile.sh"
source "${SANDBOX_ROOT}/lib/filesystem.sh"
source "${SANDBOX_ROOT}/lib/manifest.sh"
# The gate now consults vetting status to decide whether to honor a repo's
# accepted_secrets list (Phase 2), so the vetting unit is in scope here too.
source "${SANDBOX_ROOT}/lib/vetting.sh"
# resolve_inference_endpoint (agents.sh) + inference_endpoint_is_trusted
# (checks.sh) back the trusted-endpoint gate downgrade.
source "${SANDBOX_ROOT}/lib/agents.sh"
source "${SANDBOX_ROOT}/lib/checks.sh"

# Hermetic user config so a real ~/.sandbox/config.yaml never leaks into a test.
USER_SANDBOX_CONFIG="${TEST_DIR}/user-config.yaml"
: > "${USER_SANDBOX_CONFIG}"

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

# Two distinct betterleaks-flagged tokens (github PAT shape). SEALED_TOK is
# planted where the encrypted-at-rest exemption should apply; PLAIN_TOK where a
# plaintext secret must still block. Deliberately not canonical example keys
# (betterleaks allowlists those).
SEALED_TOK="ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z"
PLAIN_TOK="ghp_bC4eF6gH8iJ0kL2mN4oP6qR8sT0uV2wX4yZ6a"

# fixture_sealedsecret <file> — a well-formed SealedSecret whose only secret is
# in spec.encryptedData (line 8). The template block carries no secret.
fixture_sealedsecret() {
  mkdir -p "$(dirname "$1")"
  cat > "$1" <<EOF
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: mysecret
  namespace: default
spec:
  encryptedData:
    token: ${SEALED_TOK}
  template:
    metadata:
      name: mysecret
    type: Opaque
EOF
}

# fixture_sealed_template_leak <file> — a SealedSecret with an encryptedData
# value (line 7, safe) AND a plaintext secret smuggled into spec.template.data
# (line 10, must still block).
fixture_sealed_template_leak() {
  mkdir -p "$(dirname "$1")"
  cat > "$1" <<EOF
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: leaky
spec:
  encryptedData:
    good: ${SEALED_TOK}
  template:
    data:
      token: ${PLAIN_TOK}
EOF
}

# fixture_sealed_nested_spec <file> — a SealedSecret whose real encryptedData
# value is at the top level (line 7, safe) AND a plaintext secret smuggled into
# a nested spec.template.spec.encryptedData block (line 12, must still block).
# The nested block reproduces the same spec:/encryptedData: key pair one level
# down, so a top-two-of-stack ancestry check would wrongly exempt it.
fixture_sealed_nested_spec() {
  mkdir -p "$(dirname "$1")"
  cat > "$1" <<EOF
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: nested
spec:
  encryptedData:
    good: ${SEALED_TOK}
  template:
    spec:
      encryptedData:
        token: ${PLAIN_TOK}
EOF
}

# fixture_sealed_extraobjects <file> — a SealedSecret nested as a Helm
# `extraObjects:` list element (not a top-level document). The only secret is in
# spec.encryptedData (line 8); the template block carries none. Exercises the
# nested-object path: kind/apiVersion sit at the element indent, not indent 0.
fixture_sealed_extraobjects() {
  mkdir -p "$(dirname "$1")"
  cat > "$1" <<EOF
extraObjects:
  - apiVersion: bitnami.com/v1alpha1
    kind: SealedSecret
    metadata:
      name: creds
    spec:
      encryptedData:
        token: ${SEALED_TOK}
      template:
        metadata:
          name: creds
EOF
}

# fixture_extraobjects_mixed <file> — two elements in one extraObjects: list. The
# first is a real SealedSecret (encryptedData, line 6, safe). The second is a
# plaintext kind: Secret that reuses a spec.encryptedData: shape (line 11) to try
# to borrow the first element's SealedSecret-ness. The list-element boundary must
# keep them separate: line 6 exempt, line 11 still blocks.
fixture_extraobjects_mixed() {
  mkdir -p "$(dirname "$1")"
  cat > "$1" <<EOF
extraObjects:
  - apiVersion: bitnami.com/v1alpha1
    kind: SealedSecret
    spec:
      encryptedData:
        token: ${SEALED_TOK}
  - apiVersion: v1
    kind: Secret
    spec:
      encryptedData:
        token: ${PLAIN_TOK}
EOF
}

# fixture_sealed_multidoc <file> — a SealedSecret doc (encryptedData, line 7,
# safe) and a sibling plaintext `kind: Secret` doc (stringData, line 14, must
# still block) in one multi-document file.
fixture_sealed_multidoc() {
  mkdir -p "$(dirname "$1")"
  cat > "$1" <<EOF
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: sealed-one
spec:
  encryptedData:
    token: ${SEALED_TOK}
---
apiVersion: v1
kind: Secret
metadata:
  name: plain-one
stringData:
  token: ${PLAIN_TOK}
EOF
}

# fixture_sops <file> — a SOPS-encrypted Secret; the flagged value (line 6) is
# wrapped in an ENC[AES256_GCM,...] envelope.
fixture_sops() {
  mkdir -p "$(dirname "$1")"
  cat > "$1" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: sops-secret
data:
  token: ENC[AES256_GCM,data:${SEALED_TOK},iv:abc,tag:def,type:str]
sops:
  mac: ENC[AES256_GCM,data:xyz,type:str]
EOF
}

# fixture_sops_unencrypted_leak <file> — SOPS file with one ENC[...] value
# (line 6, safe) and an unencrypted plaintext key alongside it (line 7, must
# still block — SOPS's unencrypted_regex escape hatch).
fixture_sops_unencrypted_leak() {
  mkdir -p "$(dirname "$1")"
  cat > "$1" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: sops-leaky
data:
  token: ENC[AES256_GCM,data:${SEALED_TOK},iv:abc,tag:def,type:str]
  plainkey: ${PLAIN_TOK}
EOF
}

# fixture_sops_sameline_comment <file> — a plaintext secret (line 6) whose line
# ALSO carries an ENC[AES256_GCM,...] string in a trailing comment. The flagged
# secret's span is OUTSIDE the envelope, so it must still block: presence of an
# envelope on the line is not containment.
fixture_sops_sameline_comment() {
  mkdir -p "$(dirname "$1")"
  cat > "$1" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: sneaky
data:
  token: ${PLAIN_TOK} # rotated from ENC[AES256_GCM,data:old,type:str]
EOF
}

# fixture_sops_nonyaml <file> — a non-YAML (source) file with a plaintext
# secret and an ENC[AES256_GCM,...] string in a comment on the same line. The
# SOPS branch is file-type agnostic, so containment (not the bare envelope)
# must be what gates it: this must still block.
fixture_sops_nonyaml() {
  mkdir -p "$(dirname "$1")"
  cat > "$1" <<EOF
# config.py
API_KEY = "${PLAIN_TOK}"  # was ENC[AES256_GCM,data:old,type:str]
EOF
}

# colspan_of <file> <line> <token> — echo "<startcol> <endcol>" for <token> on
# <line> as betterleaks reports them (StartColumn/EndColumn are one past the
# real 1-based positions). Lets the scanner-free unit test feed the classifier
# the same column span the real scanner would.
colspan_of() {
  awk -v n="$2" -v t="$3" \
    'NR==n { i = index($0, t); if (i) print (i + 1) " " (i + length(t)) }' "$1"
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
# Repo-root ignore file: writer/reader for the `sandbox exceptions` store —
# betterleaks-native `relpath:rule:line` fingerprints with own-line comments.
# Scanner-free.
###############################################################################
test_exceptions_accept_list() {
  info "Testing repo-root ignore-file reader/writer..."
  local repo="${TEST_DIR}/excwrite"; mkdir -p "${repo}"
  local ign; ign="$(repo_ignore_file "${repo}")"
  eq "defaults to .betterleaksignore" "${repo}/.betterleaksignore" "${ign}"
  local fp1="deploy/values.yaml:generic-api-key:155"
  local fp2="config/app.env:github-pat:3"

  ignorefile_add_fingerprint "${ign}" "${fp1}" "sealed secret, reviewed AH"
  eq "creates the ignore file with the entry" "${fp1}" \
     "$(load_repo_ignore_fingerprints "${repo}")"

  # The reason is a full-line comment ABOVE the entry — betterleaks does not
  # support trailing inline comments, so the entry line must stay bare.
  grep -q '^# sealed secret, reviewed AH$' "${ign}" \
    && pass "reason stored as an own-line comment" || fail "reason comment missing"
  grep -qxF "${fp1}" "${ign}" \
    && pass "entry line is the bare fingerprint" || fail "entry line not bare"

  # Idempotent on the fingerprint even with a different reason.
  ignorefile_add_fingerprint "${ign}" "${fp1}" "a different note"
  eq "dedup keeps one entry" "1" \
     "$(load_repo_ignore_fingerprints "${repo}" | wc -l | tr -d ' ')"

  # A second distinct fingerprint (no reason) is appended.
  ignorefile_add_fingerprint "${ign}" "${fp2}"
  eq "second fingerprint appended" "2" \
     "$(load_repo_ignore_fingerprints "${repo}" | wc -l | tr -d ' ')"

  # The reader strips comments/blank lines but returns entries verbatim.
  printf '\n# a stray note\n' >> "${ign}"
  eq "comments and blanks are stripped" "2" \
     "$(load_repo_ignore_fingerprints "${repo}" | wc -l | tr -d ' ')"

  # A repo that already carries a .gitleaksignore gets appended there instead
  # of growing a second, conflicting store.
  local repo2="${TEST_DIR}/excgitleaks"; mkdir -p "${repo2}"
  printf 'old/entry.txt:github-pat:9\n' > "${repo2}/.gitleaksignore"
  eq "existing .gitleaksignore is preferred" "${repo2}/.gitleaksignore" \
     "$(repo_ignore_file "${repo2}")"
  ignorefile_add_fingerprint "$(repo_ignore_file "${repo2}")" "${fp1}"
  eq "appends to the existing file" "2" \
     "$(load_repo_ignore_fingerprints "${repo2}" | wc -l | tr -d ' ')"

  # remove_yaml_list_from_file — the migrate helper retires an
  # accepted_secrets: block but leaves every other key intact.
  local cfg="${TEST_DIR}/excmigrate/.sandbox/config.yaml"
  mkdir -p "$(dirname "${cfg}")"
  printf 'masked_paths:\n  - "creds.json"\naccepted_secrets:\n  - "a:b:1:deadbeef00000000"  # note\n  - "c:d:2:deadbeef11111111"\nextra_allowed_domains:\n  - git.example.com\n' > "${cfg}"
  remove_yaml_list_from_file "${cfg}" "accepted_secrets"
  eq "accepted_secrets block removed" "" \
     "$(load_repo_accepted_secrets "${TEST_DIR}/excmigrate")"
  eq "masked_paths preserved" "creds.json" \
     "$(load_repo_masked_paths "${TEST_DIR}/excmigrate")"
  eq "domains preserved" "git.example.com" \
     "$(load_extra_allowed_domains_from_file "${cfg}")"
}

###############################################################################
# leakscan_fingerprints_for — resolves a live finding to its recorded entry;
# reports not-found for a location the scanner does not flag.
###############################################################################
test_fingerprint_resolver() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  info "Testing leakscan_fingerprints_for..."

  local repo="${TEST_DIR}/fpres"
  mkdir -p "${repo}/deploy"
  git -C "${repo}" init -q
  git -C "${repo}" config user.email "test@sandbox"
  git -C "${repo}" config user.name "Test"
  printf 'api_key: %s\n' "${PLAIN_TOK}" > "${repo}/deploy/values.yaml"
  git -C "${repo}" add -A 2>/dev/null

  # Learn the rule+line the scanner assigns (avoid hard-coding a rule name).
  local m rel rule ln match
  IFS=$'\t' read -r m rel rule ln match < <(scan_repo_secrets "${repo}" | grep "^no	deploy/values.yaml	" | head -n1)
  [[ -n "${rule}" ]] || fail "expected a finding in deploy/values.yaml to resolve"

  # Capture rc without set -e aborting on the resolver's non-zero returns.
  local out rc
  rc=0; out="$(leakscan_fingerprints_for "${repo}" "deploy/values.yaml" "${rule}" "${ln}")" || rc=$?
  eq "resolver returns 0 for a live finding" "0" "${rc}"
  eq "resolved entry is the native RELPATH:RULE:LINE fingerprint" \
     "deploy/values.yaml:${rule}:${ln}" "${out}"

  # A line the scanner does not flag → not-found (rc 1), no output.
  rc=0; out="$(leakscan_fingerprints_for "${repo}" "deploy/values.yaml" "${rule}" 999)" || rc=$?
  eq "resolver returns 1 for a non-finding location" "1" "${rc}"
  [[ -z "${out}" ]] && pass "no output for a non-finding location" || fail "expected no output, got: '${out}'"
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
# scan_repo_secrets — gitignored dependency trees are skipped, but a tracked
# directory sharing the name (first-party content) is still scanned. Guards the
# _leakscan_write_config exclusion: perf without a coverage hole.
###############################################################################
test_dep_dir_exclusion() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  info "Testing gitignored dependency-tree exclusion..."

  local repo="${TEST_DIR}/depdirs"
  mkdir -p "${repo}"/{src,.venv/lib,packages/a/.venv,vendor}
  git -C "${repo}" init -q
  git -C "${repo}" config user.email "test@sandbox"
  git -C "${repo}" config user.name "Test"
  # .venv (root and nested) is gitignored; vendor is NOT — it is committed
  # first-party content that happens to use a dependency-tree name.
  printf '.venv/\npackages/a/.venv/\n' > "${repo}/.gitignore"
  # A non-example token so betterleaks' default allowlist does not swallow it.
  local tok='ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z'
  local d
  for d in src .venv/lib packages/a/.venv vendor; do
    printf 'token = "%s"\n' "${tok}" > "${repo}/${d}/leak.txt"
  done
  git -C "${repo}" add -A 2>/dev/null   # tracks src + vendor; .venv dirs stay ignored

  local out="${TEST_DIR}/depdirs.out"
  scan_repo_secrets "${repo}" > "${out}"

  # The gitignored virtualenvs (root and nested) must NOT be scanned.
  grep -q "$(printf '\t.venv/lib/leak.txt\t')" "${out}" \
    && fail "gitignored .venv must be excluded from the scan" \
    || pass "gitignored .venv excluded"
  grep -q "$(printf '\tpackages/a/.venv/leak.txt\t')" "${out}" \
    && fail "nested gitignored .venv must be excluded from the scan" \
    || pass "nested gitignored .venv excluded"

  # First-party content — tracked src, and a tracked dir that merely shares the
  # 'vendor' name — must still be scanned and flagged.
  grep -q "$(printf '^no\tsrc/leak.txt\t')" "${out}" \
    && pass "tracked src still scanned" \
    || fail "tracked src should still be a finding, got: $(cat "${out}")"
  grep -q "$(printf '^no\tvendor/leak.txt\t')" "${out}" \
    && pass "tracked vendor/ still scanned (not skipped by name)" \
    || fail "tracked vendor/ should still be scanned, got: $(cat "${out}")"
}

###############################################################################
# Known-safe artifact skip (LEAKSCAN_SKIP_PATHS) — a detect-secrets
# `.secrets.baseline` is skipped even though it is TRACKED (unlike the
# gitignore-gated dependency trees), and disabling exclusions scans it again.
###############################################################################
test_known_safe_paths() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  info "Testing known-safe artifact skip (.secrets.baseline)..."

  local repo="${TEST_DIR}/safepaths"
  mkdir -p "${repo}/sub"
  git -C "${repo}" init -q
  git -C "${repo}" config user.email "test@sandbox"
  git -C "${repo}" config user.name "Test"
  local tok='ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z'
  # A detect-secrets baseline is committed (tracked), so the gitignore gate
  # would never skip it — the unconditional LEAKSCAN_SKIP_PATHS list must.
  printf '{"results": {}, "note": "%s"}\n' "${tok}" > "${repo}/.secrets.baseline"
  # A lookalike must NOT be swept up (the entry is anchored to a full name).
  printf 'tok = "%s"\n' "${tok}" > "${repo}/sub/.secrets.baseline.bak"
  printf 'tok = "%s"\n' "${tok}" > "${repo}/sub/app.txt"
  git -C "${repo}" add -A 2>/dev/null

  local out="${TEST_DIR}/safepaths.out"
  scan_repo_secrets "${repo}" > "${out}"
  grep -q "$(printf '\t.secrets.baseline\t')" "${out}" \
    && fail "tracked .secrets.baseline must be skipped, got: $(cat "${out}")" \
    || pass "tracked .secrets.baseline skipped (unconditional)"
  grep -q "$(printf '^no\tsub/.secrets.baseline.bak\t')" "${out}" \
    && pass ".secrets.baseline.bak NOT swept up (anchored match)" \
    || fail "the anchored skip should not match .secrets.baseline.bak"
  grep -q "$(printf '^no\tsub/app.txt\t')" "${out}" \
    && pass "ordinary file still scanned" \
    || fail "sub/app.txt should still be flagged"

  # Disabling exclusions scans the baseline too (stricter).
  local _saved_user="${USER_SANDBOX_CONFIG}"
  USER_SANDBOX_CONFIG="${TEST_DIR}/safepaths-nouser.yaml"
  mkdir -p "${repo}/.sandbox"
  printf 'leakscan_dep_exclusions: off\n' > "${repo}/.sandbox/config.yaml"
  scan_repo_secrets "${repo}" > "${TEST_DIR}/safepaths-off.out"
  grep -q "$(printf '^no\t.secrets.baseline\t')" "${TEST_DIR}/safepaths-off.out" \
    && pass "leakscan_dep_exclusions: off scans .secrets.baseline (stricter)" \
    || fail ".secrets.baseline should be scanned when exclusions disabled"
  rm -f "${repo}/.sandbox/config.yaml"
  USER_SANDBOX_CONFIG="${_saved_user}"
}

###############################################################################
# Dependency-tree exclusion config — the operator overlay may WIDEN the skip
# set (loosening, so operator-only); a repo/user may DISABLE it (stricter, so
# local); a repo may NOT widen it (local loosening is blocked by construction).
###############################################################################
test_dep_dir_config() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  info "Testing dependency-tree exclusion config (widen/lock/disable)..."

  # Hermetic user config (an absent file → no user-level override leaking in).
  local _saved_user="${USER_SANDBOX_CONFIG}"
  USER_SANDBOX_CONFIG="${TEST_DIR}/depcfg-nouser.yaml"

  # A repo with a gitignored .venv (a built-in skip) and a gitignored 'privlib'
  # (a name NOT in the built-in set → scanned by default).
  local repo="${TEST_DIR}/depcfg"
  mkdir -p "${repo}/.venv/lib" "${repo}/privlib"
  git -C "${repo}" init -q
  git -C "${repo}" config user.email "test@sandbox"
  git -C "${repo}" config user.name "Test"
  printf '.venv/\nprivlib/\n' > "${repo}/.gitignore"
  local tok='ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z'
  printf 'token = "%s"\n' "${tok}" > "${repo}/.venv/lib/leak.txt"
  printf 'token = "%s"\n' "${tok}" > "${repo}/privlib/leak.txt"

  # Baseline: privlib is not a known dependency name → scanned and flagged.
  scan_repo_secrets "${repo}" > "${TEST_DIR}/depcfg-base.out"
  grep -q "$(printf '^no\tprivlib/leak.txt\t')" "${TEST_DIR}/depcfg-base.out" \
    && pass "unknown gitignored dir scanned by default" \
    || fail "privlib should be scanned by default, got: $(cat "${TEST_DIR}/depcfg-base.out")"

  # (1) Operator overlay adds 'privlib' → now excluded.
  local overlay="${TEST_DIR}/overlay"
  mkdir -p "${overlay}"
  printf 'leakscan_extra_dep_dirs:\n  - privlib\n' > "${overlay}/config.yaml"
  ( export SANDBOX_OVERLAY="${overlay}"; scan_repo_secrets "${repo}" ) > "${TEST_DIR}/depcfg-op.out"
  grep -q "$(printf '\tprivlib/leak.txt\t')" "${TEST_DIR}/depcfg-op.out" \
    && fail "operator overlay should exclude privlib, got: $(cat "${TEST_DIR}/depcfg-op.out")" \
    || pass "operator overlay widens the skip set (privlib excluded)"

  # (2) The SAME key in the REPO config must be ignored — local widening blocked.
  mkdir -p "${repo}/.sandbox"
  printf 'leakscan_extra_dep_dirs:\n  - privlib\n' > "${repo}/.sandbox/config.yaml"
  scan_repo_secrets "${repo}" > "${TEST_DIR}/depcfg-repo.out"
  grep -q "$(printf '^no\tprivlib/leak.txt\t')" "${TEST_DIR}/depcfg-repo.out" \
    && pass "repo config cannot widen the skip set (privlib still scanned)" \
    || fail "repo-level leakscan_extra_dep_dirs must be ignored, got: $(cat "${TEST_DIR}/depcfg-repo.out")"
  rm -f "${repo}/.sandbox/config.yaml"

  # (3) Local disable: leakscan_dep_exclusions: off → even .venv is scanned.
  printf 'leakscan_dep_exclusions: off\n' > "${repo}/.sandbox/config.yaml"
  scan_repo_secrets "${repo}" > "${TEST_DIR}/depcfg-off.out"
  grep -q "$(printf '^no\t.venv/lib/leak.txt\t')" "${TEST_DIR}/depcfg-off.out" \
    && pass "leakscan_dep_exclusions: off scans dependency trees (stricter)" \
    || fail ".venv should be scanned when exclusions disabled, got: $(cat "${TEST_DIR}/depcfg-off.out")"
  rm -f "${repo}/.sandbox/config.yaml"

  USER_SANDBOX_CONFIG="${_saved_user}"
}

###############################################################################
# Inline allow comments. By DEFAULT the gate HONORS `# gitleaks:allow` /
# `# betterleaks:allow` on a secret line (parity with the team's other
# betterleaks runs) — a would-be finding is suppressed. An operator/org that
# does not trust inline suppression sets `leakscan_inline_allow: off` in the
# overlay, which restores --ignore-gitleaks-allow and re-flags the line. The
# knob is overlay-only (a repo/user config cannot change it).
###############################################################################
test_inline_allow_default_honored() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  info "Testing that inline allow comments are honored by default..."

  local repo="${TEST_DIR}/inlineallow"
  mkdir -p "${repo}"
  git -C "${repo}" init -q
  git -C "${repo}" config user.email "test@sandbox"
  git -C "${repo}" config user.name "Test"
  local tok='ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z'
  printf 'token = "%s" # gitleaks:allow\n' "${tok}" > "${repo}/allow.txt"
  printf 'token = "%s" # betterleaks:allow\n' "${tok}" > "${repo}/allow2.txt"
  git -C "${repo}" add -A 2>/dev/null

  # No overlay → honoring is the default → both lines suppressed, clean scan.
  scan_repo_secrets "${repo}" > "${TEST_DIR}/inlineallow.out"
  grep -q "$(printf '\tallow.txt\t')" "${TEST_DIR}/inlineallow.out" \
    && fail "gitleaks:allow should be honored by default, got: $(cat "${TEST_DIR}/inlineallow.out")" \
    || pass "inline gitleaks:allow is honored by default (line suppressed)"
  grep -q "$(printf '\tallow2.txt\t')" "${TEST_DIR}/inlineallow.out" \
    && fail "betterleaks:allow should be honored by default, got: $(cat "${TEST_DIR}/inlineallow.out")" \
    || pass "inline betterleaks:allow is honored by default (line suppressed)"
}

test_inline_allow_overlay_disallow() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  info "Testing that overlay leakscan_inline_allow: off re-flags the lines..."

  local repo="${TEST_DIR}/inlineallow2"
  mkdir -p "${repo}"
  git -C "${repo}" init -q
  git -C "${repo}" config user.email "test@sandbox"
  git -C "${repo}" config user.name "Test"
  local tok='ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z'
  printf 'token = "%s" # gitleaks:allow\n' "${tok}" > "${repo}/allow.txt"
  printf 'token = "%s" # betterleaks:allow\n' "${tok}" > "${repo}/allow2.txt"
  git -C "${repo}" add -A 2>/dev/null

  # Overlay turns honoring off → --ignore-gitleaks-allow restored → flagged.
  local overlay="${TEST_DIR}/inlineallow-overlay"
  mkdir -p "${overlay}"
  printf 'leakscan_inline_allow: off\n' > "${overlay}/config.yaml"
  ( export SANDBOX_OVERLAY="${overlay}"; scan_repo_secrets "${repo}" ) > "${TEST_DIR}/inlineallow2.out"
  grep -q "$(printf '^no\tallow.txt\t')" "${TEST_DIR}/inlineallow2.out" \
    && pass "overlay off: inline gitleaks:allow does not bypass the gate" \
    || fail "overlay off should re-flag gitleaks:allow, got: $(cat "${TEST_DIR}/inlineallow2.out")"
  grep -q "$(printf '^no\tallow2.txt\t')" "${TEST_DIR}/inlineallow2.out" \
    && pass "overlay off: inline betterleaks:allow does not bypass the gate" \
    || fail "overlay off should re-flag betterleaks:allow, got: $(cat "${TEST_DIR}/inlineallow2.out")"

  # A repo-local config must NOT be able to disable honoring (overlay-only).
  mkdir -p "${repo}/.sandbox"
  printf 'leakscan_inline_allow: off\n' > "${repo}/.sandbox/config.yaml"
  scan_repo_secrets "${repo}" > "${TEST_DIR}/inlineallow2-repo.out"
  grep -q "$(printf '\tallow.txt\t')" "${TEST_DIR}/inlineallow2-repo.out" \
    && fail "repo config must not disable honoring, got: $(cat "${TEST_DIR}/inlineallow2-repo.out")" \
    || pass "repo-local leakscan_inline_allow is ignored (overlay-only)"
}

###############################################################################
# Operator-owned ignore baseline (-i). An operator may keep a REVIEWED baseline
# of accepted fingerprints in the overlay (<overlay>/.betterleaksignore); the
# gate passes it via -i. Suppressing findings is a loosening, so — like
# leakscan_extra_dep_dirs — it is read only from the overlay, never a repo/user
# config; with no overlay the -i default (".") is replaced by a neutral empty
# dir, so the finding still surfaces.
###############################################################################
test_operator_ignore_baseline() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  info "Testing operator-owned betterleaks ignore baseline (-i)..."

  local _saved_user="${USER_SANDBOX_CONFIG}"
  USER_SANDBOX_CONFIG="${TEST_DIR}/opign-nouser.yaml"

  local repo="${TEST_DIR}/opign"
  mkdir -p "${repo}"
  git -C "${repo}" init -q
  git -C "${repo}" config user.email "test@sandbox"
  git -C "${repo}" config user.name "Test"
  local tok='ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z'
  printf 'token = "%s"\n' "${tok}" > "${repo}/app.txt"
  git -C "${repo}" add -A 2>/dev/null

  # Baseline: the secret is in an unmasked path → flagged.
  scan_repo_secrets "${repo}" > "${TEST_DIR}/opign-base.out"
  grep -q "$(printf '^no\tapp.txt\t')" "${TEST_DIR}/opign-base.out" \
    && pass "secret flagged without an operator baseline" \
    || fail "app.txt should be flagged by default, got: $(cat "${TEST_DIR}/opign-base.out")"

  # Seed an overlay baseline with the finding fingerprints exactly as
  # betterleaks derives them for this workspace (they are path-based).
  local report; report="$(mktemp "${TEST_DIR}/opign-fp-XXXXXX")"
  _betterleaks_run "$(realpath "${repo}")" "${report}" "" "" >/dev/null 2>&1 || true
  local overlay="${TEST_DIR}/opign-overlay"
  mkdir -p "${overlay}"
  jq -r '.[].Fingerprint' "${report}" > "${overlay}/.betterleaksignore"

  # Operator overlay baseline suppresses the accepted fingerprints.
  ( export SANDBOX_OVERLAY="${overlay}"; scan_repo_secrets "${repo}" ) > "${TEST_DIR}/opign-op.out"
  grep -q "$(printf '\tapp.txt\t')" "${TEST_DIR}/opign-op.out" \
    && fail "operator baseline should suppress the accepted finding, got: $(cat "${TEST_DIR}/opign-op.out")" \
    || pass "operator overlay .betterleaksignore suppresses the accepted fingerprint"

  # Without the overlay the baseline does not apply (neutral -i) → still flagged.
  scan_repo_secrets "${repo}" > "${TEST_DIR}/opign-nooverlay.out"
  grep -q "$(printf '^no\tapp.txt\t')" "${TEST_DIR}/opign-nooverlay.out" \
    && pass "no overlay → neutral -i, finding still reported" \
    || fail "without the overlay baseline app.txt should still be flagged"

  USER_SANDBOX_CONFIG="${_saved_user}"
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
  if ( secret_gate_repos "false" "false" "${repo}" >/dev/null 2>&1 ); then
    fail "gate should refuse on an unmasked secret"
  fi
  pass "gate refuses on unmasked secret"

  # Override → proceeds (exit 0) despite the unmasked secret.
  if ( secret_gate_repos "true" "false" "${repo}" >/dev/null 2>&1 ); then
    pass "override proceeds despite unmasked secret"
  else
    fail "override should proceed"
  fi

  # Mask the offending file → gate passes.
  config_add_masked_path "${repo}/.sandbox/config.yaml" "nested/config.txt"
  if ( secret_gate_repos "false" "false" "${repo}" >/dev/null 2>&1 ); then
    pass "gate passes once the secret is masked"
  else
    fail "gate should pass after masking the file"
  fi
}

###############################################################################
# .git/config — a credential in the repo's git config is readable in the pod
# (the mount includes .git, which the mask cannot empty) and betterleaks skips
# .git in a directory walk, so it must be scanned explicitly and gated.
###############################################################################
test_gitconfig_secret() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  info "Testing .git/config secret detection..."

  # A clean repo (no planted .env/nested secrets) whose only secret is a
  # credential embedded in a remote URL inside .git/config.
  local repo="${TEST_DIR}/gitcfg"
  mkdir -p "${repo}"
  git -C "${repo}" init -q
  git -C "${repo}" config user.email "test@sandbox"
  git -C "${repo}" config user.name "Test"
  git -C "${repo}" remote add origin \
    "https://u:ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z@github.com/x/y.git"

  local out="${TEST_DIR}/gitcfg.out"
  scan_repo_secrets "${repo}" > "${out}"

  grep -q "$(printf '^gitconfig\t.git/config\t')" "${out}" \
    && pass ".git/config secret classified gitconfig" \
    || fail ".git/config secret should be a gitconfig finding"

  # The whole-repo directory scan must not also surface it (betterleaks skips
  # .git), so the only line is the explicit gitconfig one — and it's redacted.
  if grep -q "ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z" "${out}"; then
    fail "raw .git/config secret leaked into scan output (should be redacted)"
  fi
  pass ".git/config secret value redacted"

  # The gate refuses on it...
  if ( secret_gate_repos "false" "false" "${repo}" >/dev/null 2>&1 ); then
    fail "gate should refuse on a .git/config secret"
  fi
  pass "gate refuses on .git/config secret"

  # ...the override proceeds...
  if ( secret_gate_repos "true" "false" "${repo}" >/dev/null 2>&1 ); then
    pass "override proceeds despite .git/config secret"
  else
    fail "override should proceed"
  fi

  # ...and masking does NOT help (an empty .git/config overlay would break git,
  # so the gitconfig scan ignores masked_paths and the gate still refuses).
  config_add_masked_path "${repo}/.sandbox/config.yaml" ".git/config"
  if ( secret_gate_repos "false" "false" "${repo}" >/dev/null 2>&1 ); then
    fail "masking .git/config must not bypass the gate"
  fi
  pass "masking .git/config does not bypass the gate"
}

###############################################################################
# .git/config never honors inline allow comments. Honoring is the workspace-scan
# default (parity with the team's other betterleaks runs), but those runs never
# scan .git/config and it is the unmaskable, credential-dense finding class — so
# a trailing `# gitleaks:allow` on a credential line in .git/config must NOT
# suppress the finding, whatever leakscan_inline_allow says.
###############################################################################
test_gitconfig_inline_allow_not_honored() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  info "Testing that .git/config ignores inline allow comments..."

  local repo="${TEST_DIR}/gitcfg-allow"
  mkdir -p "${repo}"
  git -C "${repo}" init -q
  git -C "${repo}" config user.email "test@sandbox"
  git -C "${repo}" config user.name "Test"
  local tok='ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z'
  # Write the remote URL straight into .git/config with a trailing allow comment
  # (git treats a ` #` after the value as a comment, so the URL stays valid).
  printf '[remote "origin"]\n\turl = https://u:%s@github.com/x/y.git # gitleaks:allow\n' \
    "${tok}" >> "${repo}/.git/config"

  # Default (honoring on for the workspace scan): the annotation must NOT help.
  scan_repo_secrets "${repo}" > "${TEST_DIR}/gitcfg-allow.out"
  grep -q "$(printf '^gitconfig\t.git/config\t')" "${TEST_DIR}/gitcfg-allow.out" \
    && pass "inline gitleaks:allow does not suppress a .git/config secret (default)" \
    || fail ".git/config allow comment bypassed the gate, got: $(cat "${TEST_DIR}/gitcfg-allow.out")"

  # Even with honoring explicitly ON via the overlay, .git/config is unaffected.
  local overlay="${TEST_DIR}/gitcfg-allow-overlay"
  mkdir -p "${overlay}"
  printf 'leakscan_inline_allow: on\n' > "${overlay}/config.yaml"
  ( export SANDBOX_OVERLAY="${overlay}"; scan_repo_secrets "${repo}" ) \
    > "${TEST_DIR}/gitcfg-allow-on.out"
  grep -q "$(printf '^gitconfig\t.git/config\t')" "${TEST_DIR}/gitcfg-allow-on.out" \
    && pass "overlay leakscan_inline_allow: on still flags .git/config" \
    || fail "overlay on should not reach .git/config, got: $(cat "${TEST_DIR}/gitcfg-allow-on.out")"

  # And the gate refuses on it.
  if ( secret_gate_repos "false" "false" "${repo}" >/dev/null 2>&1 ); then
    fail "gate should refuse on an annotated .git/config secret"
  fi
  pass "gate refuses on annotated .git/config secret"
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
  if ( PATH="${stub}:${PATH}" secret_gate_repos "false" "false" "${repo}" >/dev/null 2>&1 ); then
    fail "gate should refuse when the scanner fails"
  fi
  pass "gate refuses on scanner failure"

  # ...and the override does NOT bypass a failed scan (it accepts known
  # secrets, not an uninspected workspace).
  if ( PATH="${stub}:${PATH}" secret_gate_repos "true" "false" "${repo}" >/dev/null 2>&1 ); then
    fail "override should not bypass a failed scan"
  fi
  pass "override does not bypass a failed scan"
}

###############################################################################
# finding_is_encrypted — the core encrypted-at-rest classifier, exercised
# directly (no scanner needed): SealedSecret encryptedData and SOPS ENC[...]
# values are exempt; plaintext smuggled into the same file is NOT.
###############################################################################
test_finding_is_encrypted() {
  info "Testing finding_is_encrypted..."
  local d="${TEST_DIR}/enc"
  mkdir -p "${d}"

  # SealedSecret: the encryptedData value (line 8) is exempt.
  fixture_sealedsecret "${d}/sealed.yaml"
  finding_is_encrypted "${d}/sealed.yaml" 8 \
    && pass "SealedSecret encryptedData value exempt" \
    || fail "encryptedData value should be exempt"

  # A plaintext secret in spec.template.data (line 10) is NOT exempt, even
  # though line 7 (encryptedData) in the same doc is.
  fixture_sealed_template_leak "${d}/tmpl.yaml"
  finding_is_encrypted "${d}/tmpl.yaml" 7 \
    && pass "encryptedData value exempt (template fixture)" \
    || fail "line 7 encryptedData should be exempt"
  finding_is_encrypted "${d}/tmpl.yaml" 10 \
    && fail "plaintext in spec.template must NOT be exempt" \
    || pass "plaintext in spec.template not exempt"

  # A plaintext secret under a NESTED spec.template.spec.encryptedData block
  # (line 12) is NOT exempt: only a top-level spec.encryptedData value (line 7)
  # is. Guards against a top-two-of-stack ancestry match.
  fixture_sealed_nested_spec "${d}/nested.yaml"
  finding_is_encrypted "${d}/nested.yaml" 7 \
    && pass "top-level encryptedData exempt (nested fixture)" \
    || fail "line 7 top-level encryptedData should be exempt"
  finding_is_encrypted "${d}/nested.yaml" 11 \
    && fail "plaintext under nested spec.template.spec.encryptedData must NOT be exempt" \
    || pass "nested spec.encryptedData not exempt"

  # Embedded SealedSecret (Helm extraObjects: list element): the encryptedData
  # value (line 8) is exempt even though kind/apiVersion are not at indent 0.
  fixture_sealed_extraobjects "${d}/extra.yaml"
  finding_is_encrypted "${d}/extra.yaml" 8 \
    && pass "embedded (extraObjects) SealedSecret value exempt" \
    || fail "line 8 embedded encryptedData should be exempt"

  # Two list elements: the real SealedSecret's value (line 6) is exempt; a
  # plaintext element reusing the encryptedData shape (line 11) must NOT be — the
  # first element's SealedSecret-ness cannot leak across the element boundary.
  fixture_extraobjects_mixed "${d}/mixed-extra.yaml"
  finding_is_encrypted "${d}/mixed-extra.yaml" 6 \
    && pass "mixed extraObjects: real SealedSecret value exempt" \
    || fail "line 6 SealedSecret element should be exempt"
  finding_is_encrypted "${d}/mixed-extra.yaml" 11 \
    && fail "plaintext element borrowing encryptedData shape must NOT be exempt" \
    || pass "sibling plaintext list element not exempt"

  # Multi-doc: encryptedData in the SealedSecret doc (line 7) is exempt; the
  # sibling plaintext Secret doc's stringData (line 14) is not.
  fixture_sealed_multidoc "${d}/multi.yaml"
  finding_is_encrypted "${d}/multi.yaml" 7 \
    && pass "multi-doc SealedSecret value exempt" \
    || fail "line 7 should be exempt"
  finding_is_encrypted "${d}/multi.yaml" 14 \
    && fail "sibling plaintext Secret doc must NOT be exempt" \
    || pass "sibling plaintext Secret doc not exempt"

  # SOPS: a finding whose span sits inside the ENC[...] envelope (line 6) is
  # exempt. The classifier needs the finding's column span, so feed it the span
  # betterleaks would report for the enclosed token.
  fixture_sops "${d}/sops.yaml"
  finding_is_encrypted "${d}/sops.yaml" 6 $(colspan_of "${d}/sops.yaml" 6 "${SEALED_TOK}") \
    && pass "SOPS ENC[...] value exempt" \
    || fail "SOPS ENC value should be exempt"

  # A SOPS finding with NO column span cannot be proven contained → not exempt.
  finding_is_encrypted "${d}/sops.yaml" 6 \
    && fail "SOPS value with no column span must NOT be exempt" \
    || pass "SOPS value not exempt without a column span"

  # SOPS with an unencrypted key alongside: the ENC value (line 6) is exempt,
  # the plaintext key (line 7) is not.
  fixture_sops_unencrypted_leak "${d}/sopsleak.yaml"
  finding_is_encrypted "${d}/sopsleak.yaml" 6 $(colspan_of "${d}/sopsleak.yaml" 6 "${SEALED_TOK}") \
    && pass "SOPS ENC value exempt (leak fixture)" \
    || fail "line 6 ENC should be exempt"
  finding_is_encrypted "${d}/sopsleak.yaml" 7 $(colspan_of "${d}/sopsleak.yaml" 7 "${PLAIN_TOK}") \
    && fail "unencrypted SOPS key must NOT be exempt" \
    || pass "unencrypted SOPS key not exempt"

  # Containment, not presence: a plaintext secret sharing a line with an
  # ENC[...] envelope (in a trailing comment) is OUTSIDE the envelope span and
  # must NOT be exempt — the reviewer's r3553097254 bypass.
  fixture_sops_sameline_comment "${d}/sameline.yaml"
  finding_is_encrypted "${d}/sameline.yaml" 6 $(colspan_of "${d}/sameline.yaml" 6 "${PLAIN_TOK}") \
    && fail "plaintext on a line with an ENC[...] comment must NOT be exempt" \
    || pass "plaintext outside the envelope not exempt (same-line comment)"

  # ...and the same for a non-YAML file (the SOPS branch is file-type agnostic).
  fixture_sops_nonyaml "${d}/config.py"
  finding_is_encrypted "${d}/config.py" 2 $(colspan_of "${d}/config.py" 2 "${PLAIN_TOK}") \
    && fail "plaintext in a non-YAML file with an ENC[...] comment must NOT be exempt" \
    || pass "plaintext outside the envelope not exempt (non-YAML)"

  # A finding line pointing at nothing / out of range is not exempt.
  finding_is_encrypted "${d}/sealed.yaml" 999 \
    && fail "out-of-range line must NOT be exempt" \
    || pass "out-of-range line not exempt"
}

###############################################################################
# scan_repo_secrets + secret_gate_repos — encrypted-at-rest findings classify
# as `sealed` and pass the gate; plaintext in the same file still blocks.
###############################################################################
test_encrypted_scan_and_gate() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  info "Testing sealed/SOPS classification and gate..."

  # (1) A clean SealedSecret → one `sealed` finding, no `no`; gate passes.
  local repo="${TEST_DIR}/encscan"
  fixture_sealedsecret "${repo}/manifests/sealed.yaml"
  local out="${TEST_DIR}/encscan.out"
  scan_repo_secrets "${repo}" > "${out}"
  grep -q "$(printf '^sealed\tmanifests/sealed.yaml\t')" "${out}" \
    && pass "SealedSecret finding classified sealed" \
    || fail "expected a sealed finding, got: $(cat "${out}")"
  grep -q "$(printf '^no\t')" "${out}" \
    && fail "clean SealedSecret should produce no unmasked finding" \
    || pass "no unmasked finding for clean SealedSecret"
  if ( secret_gate_repos "false" "false" "${repo}" >/dev/null 2>&1 ); then
    pass "gate passes on a clean SealedSecret"
  else
    fail "gate should pass on a clean SealedSecret"
  fi

  # (1b) An embedded SealedSecret (Helm extraObjects:) → sealed, gate passes.
  local erepo="${TEST_DIR}/extrascan"
  fixture_sealed_extraobjects "${erepo}/base/values.yaml"
  scan_repo_secrets "${erepo}" > "${TEST_DIR}/extrascan.out"
  grep -q "$(printf '^sealed\tbase/values.yaml\t')" "${TEST_DIR}/extrascan.out" \
    && pass "embedded SealedSecret finding classified sealed" \
    || fail "expected a sealed finding for extraObjects, got: $(cat "${TEST_DIR}/extrascan.out")"
  grep -q "$(printf '^no\t')" "${TEST_DIR}/extrascan.out" \
    && fail "embedded SealedSecret should produce no unmasked finding" \
    || pass "no unmasked finding for embedded SealedSecret"
  if ( secret_gate_repos "false" "false" "${erepo}" >/dev/null 2>&1 ); then
    pass "gate passes on an embedded SealedSecret"
  else
    fail "gate should pass on an embedded SealedSecret"
  fi

  # (2) A clean SOPS file → sealed, gate passes.
  local srepo="${TEST_DIR}/sopsscan"
  fixture_sops "${srepo}/manifests/sops.yaml"
  scan_repo_secrets "${srepo}" > "${TEST_DIR}/sopsscan.out"
  grep -q "$(printf '^sealed\tmanifests/sops.yaml\t')" "${TEST_DIR}/sopsscan.out" \
    && pass "SOPS finding classified sealed" \
    || fail "expected a sealed SOPS finding, got: $(cat "${TEST_DIR}/sopsscan.out")"
  if ( secret_gate_repos "false" "false" "${srepo}" >/dev/null 2>&1 ); then
    pass "gate passes on a clean SOPS file"
  else
    fail "gate should pass on a clean SOPS file"
  fi
}

test_encrypted_leaks_still_block() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  info "Testing plaintext-in-encrypted-file still blocks..."

  # Multi-doc: the plaintext Secret sibling must still block the gate.
  local repo="${TEST_DIR}/multiblock"
  fixture_sealed_multidoc "${repo}/manifests/mixed.yaml"
  local out="${TEST_DIR}/multiblock.out"
  scan_repo_secrets "${repo}" > "${out}"
  grep -q "$(printf '^sealed\tmanifests/mixed.yaml\t')" "${out}" \
    && pass "multi-doc: SealedSecret value classified sealed" \
    || fail "expected a sealed finding in multi-doc, got: $(cat "${out}")"
  grep -q "$(printf '^no\tmanifests/mixed.yaml\t')" "${out}" \
    && pass "multi-doc: plaintext sibling classified unmasked" \
    || fail "expected an unmasked finding in multi-doc, got: $(cat "${out}")"
  if ( secret_gate_repos "false" "false" "${repo}" >/dev/null 2>&1 ); then
    fail "gate must refuse when a plaintext secret sits beside a SealedSecret"
  fi
  pass "gate refuses on plaintext sibling of a SealedSecret"

  # Mixed extraObjects: the plaintext list element beside a real SealedSecret
  # element must still block (element boundary holds under real betterleaks).
  local erepo="${TEST_DIR}/extrablock"
  fixture_extraobjects_mixed "${erepo}/base/values.yaml"
  scan_repo_secrets "${erepo}" > "${TEST_DIR}/extrablock.out"
  grep -q "$(printf '^sealed\tbase/values.yaml\t')" "${TEST_DIR}/extrablock.out" \
    && pass "mixed extraObjects: SealedSecret element classified sealed" \
    || fail "expected a sealed finding in mixed extraObjects, got: $(cat "${TEST_DIR}/extrablock.out")"
  grep -q "$(printf '^no\tbase/values.yaml\t')" "${TEST_DIR}/extrablock.out" \
    && pass "mixed extraObjects: plaintext element classified unmasked" \
    || fail "expected an unmasked finding in mixed extraObjects, got: $(cat "${TEST_DIR}/extrablock.out")"
  if ( secret_gate_repos "false" "false" "${erepo}" >/dev/null 2>&1 ); then
    fail "gate must refuse on a plaintext element beside a SealedSecret element"
  fi
  pass "gate refuses on plaintext sibling list element"

  # SOPS file with an unencrypted key alongside ENC values must still block.
  local srepo="${TEST_DIR}/sopsblock"
  fixture_sops_unencrypted_leak "${srepo}/manifests/leak.yaml"
  scan_repo_secrets "${srepo}" > "${TEST_DIR}/sopsblock.out"
  grep -q "$(printf '^no\tmanifests/leak.yaml\t')" "${TEST_DIR}/sopsblock.out" \
    && pass "SOPS: unencrypted key classified unmasked" \
    || fail "expected an unmasked SOPS finding, got: $(cat "${TEST_DIR}/sopsblock.out")"
  if ( secret_gate_repos "false" "false" "${srepo}" >/dev/null 2>&1 ); then
    fail "gate must refuse on an unencrypted key in a SOPS file"
  fi
  pass "gate refuses on unencrypted key in a SOPS file"

  # A plaintext secret sharing a line with an ENC[...] comment must still block
  # end-to-end (real betterleaks) — presence of the envelope is not containment.
  local crepo="${TEST_DIR}/sopscomment"
  fixture_sops_sameline_comment "${crepo}/manifests/sneaky.yaml"
  scan_repo_secrets "${crepo}" > "${TEST_DIR}/sopscomment.out"
  grep -q "$(printf '^sealed\t')" "${TEST_DIR}/sopscomment.out" \
    && fail "plaintext beside an ENC[...] comment must NOT classify sealed, got: $(cat "${TEST_DIR}/sopscomment.out")" \
    || pass "same-line ENC comment: plaintext not classified sealed"
  grep -q "$(printf '^no\tmanifests/sneaky.yaml\t')" "${TEST_DIR}/sopscomment.out" \
    && pass "same-line ENC comment: plaintext classified unmasked" \
    || fail "expected an unmasked finding, got: $(cat "${TEST_DIR}/sopscomment.out")"
  if ( secret_gate_repos "false" "false" "${crepo}" >/dev/null 2>&1 ); then
    fail "gate must refuse plaintext sharing a line with an ENC[...] comment"
  fi
  pass "gate refuses plaintext sharing a line with an ENC[...] comment"
}

###############################################################################
# scan_repo_secrets accept-list — a `no` finding whose fingerprint is in the
# accept-file is downgraded to `accepted`, BUT only for a git-tracked file; a
# gitignored/untracked file is never accepted (not in the signed tree). A
# fingerprint for a different location does not match.
###############################################################################
test_scan_acceptance() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  info "Testing scan_repo_secrets accept-list downgrade + tracked-file guard..."

  local repo="${TEST_DIR}/accept"
  mkdir -p "${repo}/deploy"
  git -C "${repo}" init -q
  git -C "${repo}" config user.email "test@sandbox"
  git -C "${repo}" config user.name "Test"
  printf 'api_key: %s\n' "${PLAIN_TOK}" > "${repo}/deploy/values.yaml"
  # A gitignored local file with its own secret — present at scan time but NOT
  # part of the tracked/signed tree.
  printf 'untracked.txt\n' > "${repo}/.gitignore"
  printf 'SECRET=%s\n' "${SEALED_TOK}" > "${repo}/untracked.txt"
  git -C "${repo}" add -A 2>/dev/null   # tracks deploy/values.yaml + .gitignore

  # Resolve real fingerprints (Phase 1 resolver) for both files.
  local rule ln grule gln
  IFS=$'\t' read -r _ _ rule ln _ < <(scan_repo_secrets "${repo}" | grep "^no	deploy/values.yaml	" | head -n1)
  IFS=$'\t' read -r _ _ grule gln _ < <(scan_repo_secrets "${repo}" | grep "^no	untracked.txt	" | head -n1)
  local fp_tracked fp_ignored
  fp_tracked="$(leakscan_fingerprints_for "${repo}" "deploy/values.yaml" "${rule}" "${ln}")"
  fp_ignored="$(leakscan_fingerprints_for "${repo}" "untracked.txt" "${grule}" "${gln}")"
  [[ -n "${fp_tracked}" && -n "${fp_ignored}" ]] || fail "could not resolve fingerprints"

  local accept="${TEST_DIR}/accept.list" out="${TEST_DIR}/accept.out"
  printf '%s\n%s\n' "${fp_tracked}" "${fp_ignored}" > "${accept}"
  scan_repo_secrets "${repo}" "${accept}" > "${out}"

  grep -q "$(printf '^accepted\tdeploy/values.yaml\t')" "${out}" \
    && pass "tracked finding with matching fingerprint → accepted" \
    || fail "tracked finding should be accepted, got: $(cat "${out}")"

  # SECURITY: gitignored file is not in the signed tree; a matching fingerprint
  # must NOT accept it.
  grep -q "$(printf '^accepted\tuntracked.txt\t')" "${out}" \
    && fail "gitignored file must NOT be accepted (not tracked): $(cat "${out}")" \
    || pass "gitignored file stays blocking despite an accept-list entry"
  grep -q "$(printf '^no\tuntracked.txt\t')" "${out}" \
    && pass "gitignored file classified unmasked" \
    || fail "expected gitignored file to remain 'no'"

  # A fingerprint for a different location (wrong line) does not match, and a
  # legacy 4-field `path:rule:line:hash` entry matches nothing (exact compare).
  printf 'deploy/values.yaml:%s:999\ndeploy/values.yaml:%s:%s:deadbeefdeadbeef\n' \
    "${rule}" "${rule}" "${ln}" > "${accept}"
  scan_repo_secrets "${repo}" "${accept}" > "${out}"
  grep -q "$(printf '^no\tdeploy/values.yaml\t')" "${out}" \
    && pass "wrong-location and legacy 4-field entries do not accept" \
    || fail "non-matching fingerprints should not be accepted, got: $(cat "${out}")"

  # No accept-file → unchanged behavior.
  scan_repo_secrets "${repo}" > "${out}"
  grep -q "$(printf '^no\tdeploy/values.yaml\t')" "${out}" \
    && pass "no accept-file → finding stays 'no'" \
    || fail "without an accept-file the finding should be 'no'"
}

###############################################################################
# scan_repo_secrets — a repo-root ignore file is safe to coexist with the scan:
# relative fingerprints (the sanctioned, committed form) do not suppress the
# gate's absolute-target scan, and an ABSOLUTE fingerprint — which betterleaks'
# unconditional root-file auto-read WOULD honor, silently blinding the gate —
# fails the scan closed until removed.
###############################################################################
test_root_ignore_file_guard() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  info "Testing root ignore-file guard (relative inert, absolute fails closed)..."

  local repo="${TEST_DIR}/rootign"
  mkdir -p "${repo}/deploy"
  git -C "${repo}" init -q
  git -C "${repo}" config user.email "test@sandbox"
  git -C "${repo}" config user.name "Test"
  printf 'api_key: %s\n' "${PLAIN_TOK}" > "${repo}/deploy/values.yaml"
  git -C "${repo}" add -A 2>/dev/null

  # Learn the real rule/line, then commit a RELATIVE fingerprint for it in the
  # root ignore file — exactly what `sandbox exceptions add` records.
  local rule ln out="${TEST_DIR}/rootign.out"
  IFS=$'\t' read -r _ _ rule ln _ < <(scan_repo_secrets "${repo}" | grep "^no	deploy/values.yaml	" | head -n1)
  [[ -n "${rule}" ]] || fail "expected a finding to resolve"
  printf '# reviewed FP\ndeploy/values.yaml:%s:%s\n' "${rule}" "${ln}" > "${repo}/.betterleaksignore"
  git -C "${repo}" add -A 2>/dev/null

  # Unvetted (no accept-file): the committed relative fingerprint must NOT
  # suppress the finding inside betterleaks — the gate still sees and blocks it.
  scan_repo_secrets "${repo}" > "${out}"
  grep -q "$(printf '^no\tdeploy/values.yaml\t')" "${out}" \
    && pass "relative root-ignore fingerprint is inert to the gate's scan" \
    || fail "finding vanished — root ignore file suppressed the scan: $(cat "${out}")"

  # An absolute fingerprint would be honored by the auto-read → fail closed.
  printf '%s/deploy/values.yaml:%s:%s\n' "$(realpath "${repo}")" "${rule}" "${ln}" \
    > "${repo}/.betterleaksignore"
  scan_repo_secrets "${repo}" > "${out}"
  grep -q "$(printf '^error\t')" "${out}" \
    && pass "absolute root-ignore fingerprint fails the scan closed" \
    || fail "expected an error sentinel for an absolute fingerprint, got: $(cat "${out}")"
  if ( secret_gate_repos "false" "false" "${repo}" >/dev/null 2>&1 ); then
    fail "gate must refuse while the root ignore file carries an absolute entry"
  fi
  pass "gate refuses on an absolute root-ignore fingerprint"

  # Same guard for a .gitleaksignore (betterleaks auto-reads it too).
  rm -f "${repo}/.betterleaksignore"
  printf '/etc/passwd:%s:1\n' "${rule}" > "${repo}/.gitleaksignore"
  scan_repo_secrets "${repo}" > "${out}"
  grep -q "$(printf '^error\t')" "${out}" \
    && pass ".gitleaksignore absolute entry also fails closed" \
    || fail "expected an error sentinel for .gitleaksignore, got: $(cat "${out}")"
}

###############################################################################
# secret_gate_repos — the exceptions list is honored ONLY when the repo is
# vetted (a signed attestation verifies at HEAD). End-to-end with real SSH
# signing; skips gracefully where signing is unavailable.
###############################################################################
test_exceptions_gate_vetted() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  command -v ssh-keygen &>/dev/null || skip "ssh-keygen not installed"
  info "Testing exceptions honored only when vetted..."

  local signer="reviewer@sandbox.test"
  local trust_root="${TEST_DIR}/vet-allowed_signers"
  ssh-keygen -q -t ed25519 -f "${TEST_DIR}/vet-id" -N "" -C "${signer}" 2>/dev/null || skip "ssh-keygen failed"
  printf '%s %s\n' "${signer}" "$(awk '{print $1" "$2}' "${TEST_DIR}/vet-id.pub")" > "${trust_root}"
  printf 'x' | ssh-keygen -Y sign -f "${TEST_DIR}/vet-id" -n git >/dev/null 2>&1 || skip "SSH signing unavailable"

  local _saved_user="${USER_SANDBOX_CONFIG}"
  USER_SANDBOX_CONFIG="${TEST_DIR}/vet-user.yaml"
  cat > "${USER_SANDBOX_CONFIG}" <<EOF
vetting_trust_root: ${trust_root}
vetting_trust_format: ssh
EOF

  local repo="${TEST_DIR}/vetgate"
  mkdir -p "${repo}/deploy"
  git -C "${repo}" init -q
  git -C "${repo}" config user.email "${signer}"
  git -C "${repo}" config user.name "Reviewer"
  printf 'api_key: %s\n' "${PLAIN_TOK}" > "${repo}/deploy/values.yaml"
  git -C "${repo}" add -A 2>/dev/null; git -C "${repo}" commit -q -m init

  # Record an exception for every unmasked finding (one planted token can trip
  # more than one betterleaks rule; the gate only passes when all are accepted —
  # exactly what a reviewer would do from the gate's printed list). Commit them.
  local frel frule fln fp one recorded=0
  while IFS=$'\t' read -r _ frel frule fln _; do
    [[ -z "${frel}" ]] && continue
    fp="$(leakscan_fingerprints_for "${repo}" "${frel}" "${frule}" "${fln}")"
    while IFS= read -r one; do
      [[ -z "${one}" ]] && continue
      ignorefile_add_fingerprint "$(repo_ignore_file "${repo}")" "${one}" "reviewed FP"
      recorded=$((recorded + 1))
    done <<<"${fp}"
  done < <(scan_repo_secrets "${repo}" | grep "^no	" || true)
  [[ "${recorded}" -gt 0 ]] || fail "expected at least one finding to record"
  git -C "${repo}" add -A 2>/dev/null; git -C "${repo}" commit -q -m "record exceptions"

  # UNVETTED (no tag yet): the committed list carries no weight → gate refuses.
  if ( secret_gate_repos "false" "false" "${repo}" >/dev/null 2>&1 ); then
    fail "unvetted repo must not honor the exceptions list"
  fi
  pass "unvetted repo: exception ignored, gate refuses"

  # Attest HEAD with the trusted key → vetted → exception honored → gate passes.
  local sha; sha="$(git -C "${repo}" rev-parse HEAD)"
  git -C "${repo}" -c gpg.format=ssh -c user.signingkey="${TEST_DIR}/vet-id" \
    tag -s "agent-vetted/${sha}" -m "vetted" 2>/dev/null || { USER_SANDBOX_CONFIG="${_saved_user}"; skip "tag signing failed"; }
  if ( secret_gate_repos "false" "false" "${repo}" >/dev/null 2>&1 ); then
    pass "vetted repo: exception honored, gate passes"
  else
    fail "vetted repo should honor the exception and pass"
  fi

  USER_SANDBOX_CONFIG="${_saved_user}"
}

###############################################################################
# secret_gate_repos — exception SOURCE. By default the gate reads the WORKING-COPY
# ignore file (tracked or not), so a vetted repo honors it even when the file is
# uncommitted/gitignored — parity with the team's CI. The
# vetting_exceptions_from_commit knob restores the strict "committed-blob only"
# source, which closes the unsigned working-tree accept-list bypass. Either way,
# an unvetted repo honors nothing (covered by test_exceptions_gate_vetted).
###############################################################################
test_exceptions_gate_source() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  command -v ssh-keygen &>/dev/null || skip "ssh-keygen not installed"
  info "Testing exception source: working-copy default vs. from_commit strict..."

  local signer="reviewer@sandbox.test"
  local trust_root="${TEST_DIR}/vc-allowed_signers"
  ssh-keygen -q -t ed25519 -f "${TEST_DIR}/vc-id" -N "" -C "${signer}" 2>/dev/null || skip "ssh-keygen failed"
  printf '%s %s\n' "${signer}" "$(awk '{print $1" "$2}' "${TEST_DIR}/vc-id.pub")" > "${trust_root}"
  printf 'x' | ssh-keygen -Y sign -f "${TEST_DIR}/vc-id" -n git >/dev/null 2>&1 || skip "SSH signing unavailable"

  local _saved_user="${USER_SANDBOX_CONFIG}"
  USER_SANDBOX_CONFIG="${TEST_DIR}/vc-user.yaml"
  local base_cfg="vetting_trust_root: ${trust_root}
vetting_trust_format: ssh"
  printf '%s\n' "${base_cfg}" > "${USER_SANDBOX_CONFIG}"

  local repo="${TEST_DIR}/vetcommitted"
  mkdir -p "${repo}/deploy"
  git -C "${repo}" init -q
  git -C "${repo}" config user.email "${signer}"; git -C "${repo}" config user.name "Reviewer"
  git -C "${repo}" config gpg.format ssh; git -C "${repo}" config user.signingkey "${TEST_DIR}/vc-id"
  printf 'api_key: %s\n' "${PLAIN_TOK}" > "${repo}/deploy/values.yaml"
  git -C "${repo}" add -A 2>/dev/null; git -C "${repo}" commit -q -m init

  # Resolve the finding fingerprints (what goes in the accept-list).
  local frel frule fln fp specs=""
  while IFS=$'\t' read -r _ frel frule fln _; do
    [[ -z "${frel}" ]] && continue
    while IFS= read -r fp; do [[ -n "${fp}" ]] && specs+="${fp}"$'\n'; done \
      < <(leakscan_fingerprints_for "${repo}" "${frel}" "${frule}" "${fln}")
  done < <(scan_repo_secrets "${repo}" | grep "^no	" || true)
  [[ -n "${specs}" ]] || fail "expected findings to fingerprint"

  # Vet HEAD with NO committed exceptions, then confirm the secret blocks.
  git -C "${repo}" -c gpg.format=ssh -c user.signingkey="${TEST_DIR}/vc-id" \
    tag -s "agent-vetted/$(git -C "${repo}" rev-parse HEAD)" -m vetted 2>/dev/null \
    || { USER_SANDBOX_CONFIG="${_saved_user}"; skip "tag signing failed"; }
  local vstat _vf
  IFS=$'\t' read -r vstat _vf < <(vetting_status_repo "${repo}")
  eq "repo is vetted (baseline)" "vetted" "${vstat}"
  if ( secret_gate_repos "false" "false" "${repo}" >/dev/null 2>&1 ); then
    fail "vetted repo with a tracked secret and no exception should block"
  fi
  pass "vetted repo blocks the secret with no exception at all"

  # Drop an UNCOMMITTED root ignore file, hidden via the local .git/info/exclude
  # so HEAD is unchanged and the tree stays clean (repo stays vetted).
  while IFS= read -r fp; do [[ -n "${fp}" ]] && printf '%s\n' "${fp}" >> "${repo}/.betterleaksignore"; done <<<"${specs}"
  printf '.betterleaksignore\n' >> "${repo}/.git/info/exclude"
  eq "tree still clean (gitignored list invisible to porcelain)" "" \
     "$(git -C "${repo}" status --porcelain)"
  IFS=$'\t' read -r vstat _vf < <(vetting_status_repo "${repo}")
  eq "repo still reports vetted with the working-copy list present" "vetted" "${vstat}"

  # DEFAULT (working-copy source): the working-copy list is honored on the vetted
  # repo, exactly as CI would — the file you edit is the file that counts.
  if ( secret_gate_repos "false" "false" "${repo}" >/dev/null 2>&1 ); then
    pass "default honors the working-copy accept-list (gate passes)"
  else
    fail "default should honor the working-copy accept-list on a vetted repo"
  fi

  # STRICT (vetting_exceptions_from_commit: true): the list is not in the signed
  # commit, so it is NOT honored — the working-tree bypass is closed.
  printf '%s\nvetting_exceptions_from_commit: true\n' "${base_cfg}" > "${USER_SANDBOX_CONFIG}"
  if ( secret_gate_repos "false" "false" "${repo}" >/dev/null 2>&1 ); then
    fail "SECURITY: from_commit must NOT honor an uncommitted/gitignored accept-list"
  fi
  pass "from_commit ignores the uncommitted/gitignored list; gate blocks"

  # Committing the same list (into the signed tree) and re-vetting DOES honor it
  # even under the strict source — proving the boundary is committed-vs-not.
  git -C "${repo}" config --unset-all core.excludesFile 2>/dev/null || true
  : > "${repo}/.git/info/exclude"
  git -C "${repo}" add -A 2>/dev/null; git -C "${repo}" commit -q -m "record exceptions"
  git -C "${repo}" -c gpg.format=ssh -c user.signingkey="${TEST_DIR}/vc-id" \
    tag -s "agent-vetted/$(git -C "${repo}" rev-parse HEAD)" -m vetted 2>/dev/null
  if ( secret_gate_repos "false" "false" "${repo}" >/dev/null 2>&1 ); then
    pass "committing the list and re-vetting honors it under from_commit too"
  else
    fail "a committed, vetted exceptions list should be honored under from_commit"
  fi

  USER_SANDBOX_CONFIG="${_saved_user}"
}

###############################################################################
# sandbox exceptions migrate — converts a legacy accepted_secrets: list to the
# repo-root ignore file: hash dropped, reasons carried over as comments, the
# YAML key removed, other config keys untouched. Driven through the real CLI.
###############################################################################
test_exceptions_migrate() {
  info "Testing 'sandbox exceptions migrate'..."
  local SB="${SANDBOX_ROOT}/bin/sandbox"
  local repo="${TEST_DIR}/migrate"
  mkdir -p "${repo}/.sandbox"
  git -C "${repo}" init -q
  printf 'masked_paths:\n  - "creds.json"\naccepted_secrets:\n  - "deploy/values.yaml:generic-api-key:155:3cd3c4be828647be"  # sealed, reviewed AH\n  - "config/app.env:github-pat:3:0011223344556677"\n' \
    > "${repo}/.sandbox/config.yaml"

  "${SB}" exceptions migrate --repo "${repo}" >/dev/null 2>&1 \
    || fail "exceptions migrate failed"

  # Entries land in .betterleaksignore in native 3-field form.
  eq "hash dropped on migrate" \
     "deploy/values.yaml:generic-api-key:155
config/app.env:github-pat:3" \
     "$(load_repo_ignore_fingerprints "${repo}")"
  grep -q '^# sealed, reviewed AH$' "${repo}/.betterleaksignore" \
    && pass "reason carried over as a comment" || fail "reason comment lost in migration"

  # The legacy key is gone; unrelated keys survive.
  eq "accepted_secrets removed from config" "" "$(load_repo_accepted_secrets "${repo}")"
  eq "masked_paths untouched" "creds.json" "$(load_repo_masked_paths "${repo}")"

  # Idempotent-ish: a second run reports nothing to migrate and changes nothing.
  "${SB}" exceptions migrate --repo "${repo}" 2>/dev/null | grep -q "nothing to migrate" \
    && pass "re-running migrate is a no-op" || fail "second migrate should find nothing"
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

# resolve_inference_endpoint + inference_endpoint_is_trusted — endpoint identity
# extraction and the overlay-owned trust list that gates the secret-gate
# downgrade.
test_inference_endpoint_trust() {
  info "Testing resolve_inference_endpoint + inference_endpoint_is_trusted..."

  # Scheme, path, and port are stripped to a bare host.
  eq "opencode endpoint host extracted" "vllm.internal" \
     "$(OPENCODE_BASE_URL='https://vllm.internal:8000/v1' resolve_inference_endpoint opencode)"
  eq "opencode endpoint empty when unset" "" \
     "$(unset OPENCODE_BASE_URL; resolve_inference_endpoint opencode)"
  eq "claude has no caller-chosen endpoint" "" \
     "$(resolve_inference_endpoint claude)"

  # Userinfo must not spoof the host: the real host after '@' is what resolves,
  # never the userinfo before it, so a crafted URL cannot match a trusted host
  # while routing elsewhere.
  eq "userinfo does not spoof the host" "evil.com" \
     "$(OPENCODE_BASE_URL='https://vllm.internal:x@evil.com/v1' resolve_inference_endpoint opencode)"
  eq "legit userinfo resolves to real host" "vllm.internal" \
     "$(OPENCODE_BASE_URL='https://user:pass@vllm.internal:8000/v1' resolve_inference_endpoint opencode)"
  eq "path-embedded @ does not truncate host" "api.openai.com" \
     "$(OPENCODE_BASE_URL='https://api.openai.com/v1/@model' resolve_inference_endpoint opencode)"
  eq "userinfo with empty host resolves empty (fail closed)" "" \
     "$(OPENCODE_BASE_URL='https://user@/v1' resolve_inference_endpoint opencode)"

  # Overlay trust list: exact-match membership.
  local overlay="${TEST_DIR}/trust-overlay"
  mkdir -p "${overlay}"
  cat > "${overlay}/config.yaml" <<'YAML'
trusted_inference_endpoints:
  - vllm.internal
  - llm.corp.example.org
YAML

  ( export SANDBOX_OVERLAY="${overlay}"; inference_endpoint_is_trusted "vllm.internal" ) \
    && pass "listed endpoint is trusted" \
    || fail "vllm.internal should be trusted"
  ( export SANDBOX_OVERLAY="${overlay}"; inference_endpoint_is_trusted "api.openai.com" ) \
    && fail "unlisted endpoint must not be trusted" \
    || pass "unlisted endpoint is not trusted"
  ( export SANDBOX_OVERLAY="${overlay}"; inference_endpoint_is_trusted "" ) \
    && fail "empty host must not be trusted" \
    || pass "empty host is not trusted"

  # No overlay → nothing trusted (feature off by default).
  ( unset SANDBOX_OVERLAY; USER_SANDBOX_CONFIG="${TEST_DIR}/no-such.yaml"; \
    inference_endpoint_is_trusted "vllm.internal" ) \
    && fail "no overlay must trust nothing" \
    || pass "no overlay → nothing trusted"

  # Overlay present but no list → nothing trusted.
  local overlay2="${TEST_DIR}/trust-overlay-empty"
  mkdir -p "${overlay2}"
  printf 'vetting: advisory\n' > "${overlay2}/config.yaml"
  ( export SANDBOX_OVERLAY="${overlay2}"; inference_endpoint_is_trusted "vllm.internal" ) \
    && fail "absent list must trust nothing" \
    || pass "absent list → nothing trusted"
}

# secret_gate_repos — the trusted-endpoint downgrade. Deterministic branches
# (no pty needed): untrusted still hard-blocks; trusted with no TTY fails closed;
# the accept flag proceeds regardless. The interactive y/N branch is exercised
# separately under a pty (test_gate_trusted_interactive).
test_gate_trusted_endpoint() {
  command -v betterleaks >/dev/null 2>&1 || { info "betterleaks absent; skipping trusted-endpoint gate"; return; }
  info "Testing secret_gate_repos trusted-endpoint downgrade (deterministic branches)..."

  local repo="${TEST_DIR}/trust-gate-repo"
  make_repo "${repo}"

  # (a) Untrusted endpoint → today's hard block (regression). stdin closed so
  # the trusted-interactive branch could never fire even by accident.
  if ( secret_gate_repos "false" "false" "${repo}" </dev/null >/dev/null 2>&1 ); then
    fail "untrusted endpoint should hard-block an unmasked secret"
  else
    pass "untrusted endpoint hard-blocks (regression)"
  fi

  # (b) Trusted endpoint but NO terminal → fail closed (no human to prompt).
  if ( secret_gate_repos "false" "true" "${repo}" </dev/null >/dev/null 2>&1 ); then
    fail "trusted endpoint with no TTY should refuse"
  else
    pass "trusted endpoint + no TTY fails closed"
  fi

  # (c) The explicit consent flag proceeds regardless of endpoint/TTY.
  if ( secret_gate_repos "true" "true" "${repo}" </dev/null >/dev/null 2>&1 ); then
    pass "trusted endpoint + --i-accept-unmasked-secrets proceeds"
  else
    fail "accept flag should proceed even with no TTY"
  fi
}

# The interactive y/N branch: requires a pty so `-t 0` is true inside the gate.
# Uses util-linux `script` to allocate one; skips gracefully where it is absent
# (e.g. BSD/macOS `script`, which has different semantics). A generated helper
# re-sources the libs because `script` spawns a fresh shell.
test_gate_trusted_interactive() {
  command -v betterleaks >/dev/null 2>&1 || { info "betterleaks absent; skipping interactive gate"; return; }
  if ! command -v script >/dev/null 2>&1 || ! script --version 2>/dev/null | grep -qi util-linux; then
    info "util-linux 'script' unavailable; skipping interactive pty cases"
    return
  fi
  info "Testing secret_gate_repos interactive confirm (pty)..."

  local repo="${TEST_DIR}/trust-int-repo"
  make_repo "${repo}"

  local helper="${TEST_DIR}/gate-helper.sh"
  cat > "${helper}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
SANDBOX_ROOT="${SANDBOX_ROOT}"
USER_SANDBOX_CONFIG="${TEST_DIR}/no-such.yaml"
source "\${SANDBOX_ROOT}/lib/platform.sh"
source "\${SANDBOX_ROOT}/lib/config.sh"
source "\${SANDBOX_ROOT}/lib/profile.sh"
source "\${SANDBOX_ROOT}/lib/vetting.sh"
source "\${SANDBOX_ROOT}/lib/filesystem.sh"
secret_gate_repos "false" "true" "${repo}"
EOF

  if printf 'y\n' | script -qec "bash ${helper}" /dev/null >/dev/null 2>&1; then
    pass "trusted endpoint + TTY + 'y' proceeds"
  else
    fail "trusted endpoint + TTY + 'y' should proceed"
  fi
  if printf 'n\n' | script -qec "bash ${helper}" /dev/null >/dev/null 2>&1; then
    fail "trusted endpoint + TTY + 'n' should refuse"
  else
    pass "trusted endpoint + TTY + 'n' refuses"
  fi
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""
  echo "Test directory: ${TEST_DIR}"
  echo ""

  test_inference_endpoint_trust
  test_gate_trusted_endpoint
  test_gate_trusted_interactive

  test_is_path_masked
  test_config_add_masked_path
  test_exceptions_accept_list
  test_fingerprint_resolver
  test_manifest_mount
  test_finding_is_encrypted
  test_scan_classification
  test_dep_dir_exclusion
  test_known_safe_paths
  test_dep_dir_config
  test_inline_allow_default_honored
  test_inline_allow_overlay_disallow
  test_operator_ignore_baseline
  test_gate
  test_gitconfig_secret
  test_gitconfig_inline_allow_not_honored
  test_scan_failure_fails_closed
  test_encrypted_scan_and_gate
  test_encrypted_leaks_still_block
  test_scan_acceptance
  test_root_ignore_file_guard
  test_exceptions_gate_vetted
  test_exceptions_gate_source
  test_exceptions_migrate

  echo ""
  echo "All secret-gate tests passed."
}

main "$@"
