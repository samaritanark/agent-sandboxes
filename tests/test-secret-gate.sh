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

  # Multi-doc: encryptedData in the SealedSecret doc (line 7) is exempt; the
  # sibling plaintext Secret doc's stringData (line 14) is not.
  fixture_sealed_multidoc "${d}/multi.yaml"
  finding_is_encrypted "${d}/multi.yaml" 7 \
    && pass "multi-doc SealedSecret value exempt" \
    || fail "line 7 should be exempt"
  finding_is_encrypted "${d}/multi.yaml" 14 \
    && fail "sibling plaintext Secret doc must NOT be exempt" \
    || pass "sibling plaintext Secret doc not exempt"

  # SOPS: the ENC[...] envelope (line 6) is exempt.
  fixture_sops "${d}/sops.yaml"
  finding_is_encrypted "${d}/sops.yaml" 6 \
    && pass "SOPS ENC[...] value exempt" \
    || fail "SOPS ENC value should be exempt"

  # SOPS with an unencrypted key alongside: the ENC value (line 6) is exempt,
  # the plaintext key (line 7) is not.
  fixture_sops_unencrypted_leak "${d}/sopsleak.yaml"
  finding_is_encrypted "${d}/sopsleak.yaml" 6 \
    && pass "SOPS ENC value exempt (leak fixture)" \
    || fail "line 6 ENC should be exempt"
  finding_is_encrypted "${d}/sopsleak.yaml" 7 \
    && fail "unencrypted SOPS key must NOT be exempt" \
    || pass "unencrypted SOPS key not exempt"

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
  test_gate
  test_gitconfig_secret
  test_scan_failure_fails_closed
  test_encrypted_scan_and_gate
  test_encrypted_leaks_still_block

  echo ""
  echo "All secret-gate tests passed."
}

main "$@"
