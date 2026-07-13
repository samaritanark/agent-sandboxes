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
# Inline allow comments do not bypass the gate. An untrusted workspace could
# annotate its own secret line with `# gitleaks:allow` / `# betterleaks:allow`
# to have the scanner skip it; --ignore-gitleaks-allow (in _betterleaks_run)
# neutralizes that, the same bypass class owning -c closes for .gitleaks.toml.
###############################################################################
test_inline_allow_ignored() {
  command -v betterleaks &>/dev/null || skip "betterleaks not installed"
  command -v jq &>/dev/null || skip "jq not installed"
  info "Testing that inline allow comments do not bypass the gate..."

  local repo="${TEST_DIR}/inlineallow"
  mkdir -p "${repo}"
  git -C "${repo}" init -q
  git -C "${repo}" config user.email "test@sandbox"
  git -C "${repo}" config user.name "Test"
  local tok='ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z'
  printf 'token = "%s" # gitleaks:allow\n' "${tok}" > "${repo}/allow.txt"
  printf 'token = "%s" # betterleaks:allow\n' "${tok}" > "${repo}/allow2.txt"
  git -C "${repo}" add -A 2>/dev/null

  scan_repo_secrets "${repo}" > "${TEST_DIR}/inlineallow.out"
  grep -q "$(printf '^no\tallow.txt\t')" "${TEST_DIR}/inlineallow.out" \
    && pass "inline gitleaks:allow does not hide the secret" \
    || fail "gitleaks:allow must not bypass the gate, got: $(cat "${TEST_DIR}/inlineallow.out")"
  grep -q "$(printf '^no\tallow2.txt\t')" "${TEST_DIR}/inlineallow.out" \
    && pass "inline betterleaks:allow does not hide the secret" \
    || fail "betterleaks:allow must not bypass the gate, got: $(cat "${TEST_DIR}/inlineallow.out")"
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
  if ( secret_gate_repos "false" "${repo}" >/dev/null 2>&1 ); then
    fail "gate should refuse on a .git/config secret"
  fi
  pass "gate refuses on .git/config secret"

  # ...the override proceeds...
  if ( secret_gate_repos "true" "${repo}" >/dev/null 2>&1 ); then
    pass "override proceeds despite .git/config secret"
  else
    fail "override should proceed"
  fi

  # ...and masking does NOT help (an empty .git/config overlay would break git,
  # so the gitconfig scan ignores masked_paths and the gate still refuses).
  config_add_masked_path "${repo}/.sandbox/config.yaml" ".git/config"
  if ( secret_gate_repos "false" "${repo}" >/dev/null 2>&1 ); then
    fail "masking .git/config must not bypass the gate"
  fi
  pass "masking .git/config does not bypass the gate"
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
  finding_is_encrypted "${d}/nested.yaml" 12 \
    && fail "plaintext under nested spec.encryptedData must NOT be exempt" \
    || pass "nested spec.encryptedData not exempt"

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
  if ( secret_gate_repos "false" "${repo}" >/dev/null 2>&1 ); then
    pass "gate passes on a clean SealedSecret"
  else
    fail "gate should pass on a clean SealedSecret"
  fi

  # (2) A clean SOPS file → sealed, gate passes.
  local srepo="${TEST_DIR}/sopsscan"
  fixture_sops "${srepo}/manifests/sops.yaml"
  scan_repo_secrets "${srepo}" > "${TEST_DIR}/sopsscan.out"
  grep -q "$(printf '^sealed\tmanifests/sops.yaml\t')" "${TEST_DIR}/sopsscan.out" \
    && pass "SOPS finding classified sealed" \
    || fail "expected a sealed SOPS finding, got: $(cat "${TEST_DIR}/sopsscan.out")"
  if ( secret_gate_repos "false" "${srepo}" >/dev/null 2>&1 ); then
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
  if ( secret_gate_repos "false" "${repo}" >/dev/null 2>&1 ); then
    fail "gate must refuse when a plaintext secret sits beside a SealedSecret"
  fi
  pass "gate refuses on plaintext sibling of a SealedSecret"

  # SOPS file with an unencrypted key alongside ENC values must still block.
  local srepo="${TEST_DIR}/sopsblock"
  fixture_sops_unencrypted_leak "${srepo}/manifests/leak.yaml"
  scan_repo_secrets "${srepo}" > "${TEST_DIR}/sopsblock.out"
  grep -q "$(printf '^no\tmanifests/leak.yaml\t')" "${TEST_DIR}/sopsblock.out" \
    && pass "SOPS: unencrypted key classified unmasked" \
    || fail "expected an unmasked SOPS finding, got: $(cat "${TEST_DIR}/sopsblock.out")"
  if ( secret_gate_repos "false" "${srepo}" >/dev/null 2>&1 ); then
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
  if ( secret_gate_repos "false" "${crepo}" >/dev/null 2>&1 ); then
    fail "gate must refuse plaintext sharing a line with an ENC[...] comment"
  fi
  pass "gate refuses plaintext sharing a line with an ENC[...] comment"
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
  test_finding_is_encrypted
  test_scan_classification
  test_dep_dir_exclusion
  test_known_safe_paths
  test_dep_dir_config
  test_inline_allow_ignored
  test_operator_ignore_baseline
  test_gate
  test_gitconfig_secret
  test_scan_failure_fails_closed
  test_encrypted_scan_and_gate
  test_encrypted_leaks_still_block

  echo ""
  echo "All secret-gate tests passed."
}

main "$@"
