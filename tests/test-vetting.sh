#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-vetting.sh — Repo vetting gate tests
# Verifies: resolve_vetting_posture layering (user baseline + advisory default,
# overlay ratchets up only); vetting_status_repo classification (not-git, dirty,
# unvetted, vetted); vetting_gate_repos posture behavior (off skips, advisory
# proceeds with a notice, required refuses, --i-accept-unvetted-repo overrides,
# a missing trust root fails closed under required regardless of override). The
# signature-dependent cases skip gracefully when SSH commit signing is
# unavailable. Cluster-free.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-vetting"
TEST_DIR="$(mktemp -d /tmp/sandbox-vetting-XXXXXX)"

cleanup() { rm -rf "${TEST_DIR}"; }
trap cleanup EXIT

# Point the config loader at a throwaway user config, and clear any inherited
# overlay before sourcing so the layering tests start from a known state.
export USER_SANDBOX_CONFIG="${TEST_DIR}/user-config.yaml"
unset SANDBOX_OVERLAY

source "${SANDBOX_ROOT}/lib/platform.sh"
source "${SANDBOX_ROOT}/lib/config.sh"
source "${SANDBOX_ROOT}/lib/profile.sh"
source "${SANDBOX_ROOT}/lib/vetting.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }

# eq <label> <expected> <actual>
eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    pass "${label}"
  else
    fail "${label}: expected '${expected}', got '${actual}'"
  fi
}

SIGNER_EMAIL="reviewer@sandbox.test"
TRUST_ROOT="${TEST_DIR}/allowed_signers"
SSH_SIGNING=0

setup_signer() {
  command -v ssh-keygen >/dev/null 2>&1 || return 0
  ssh-keygen -q -t ed25519 -f "${TEST_DIR}/id" -N "" -C "${SIGNER_EMAIL}" 2>/dev/null || return 0
  # allowed_signers: "<principal> <keytype> <key>"
  printf '%s %s\n' "${SIGNER_EMAIL}" "$(awk '{print $1" "$2}' "${TEST_DIR}/id.pub")" > "${TRUST_ROOT}"
  # A second key that is NOT in the trust root (the "wrong signer" case).
  ssh-keygen -q -t ed25519 -f "${TEST_DIR}/id-untrusted" -N "" -C "untrusted@sandbox.test" 2>/dev/null || return 0
  # Smoke-test that SSH signing actually works in this environment.
  if printf 'x' | ssh-keygen -Y sign -f "${TEST_DIR}/id" -n git >/dev/null 2>&1; then
    SSH_SIGNING=1
  fi
}

# Write the user config that points the gate at our SSH trust root.
write_trust_config() {
  cat > "${USER_SANDBOX_CONFIG}" <<EOF
vetting_trust_root: ${TRUST_ROOT}
vetting_trust_format: ssh
EOF
}

make_repo() {
  local repo="$1"
  mkdir -p "${repo}"
  git -C "${repo}" init -q
  git -C "${repo}" config user.email "${SIGNER_EMAIL}"
  git -C "${repo}" config user.name "Reviewer"
  echo "hello" > "${repo}/README.md"
  git -C "${repo}" add -A
  git -C "${repo}" commit -q -m "init"
}

# attest_repo <repo> <keyfile> — sign an agent-vetted/<sha> tag at HEAD.
attest_repo() {
  local repo="$1" keyfile="$2" sha
  sha="$(git -C "${repo}" rev-parse HEAD)"
  git -C "${repo}" -c gpg.format=ssh -c user.signingkey="${keyfile}" \
    tag -s "agent-vetted/${sha}" -m "vetted for agent use" 2>/dev/null
}

###############################################################################
# resolve_vetting_posture — user baseline (else advisory default), overlay up.
###############################################################################
test_posture_layering() {
  info "Testing resolve_vetting_posture layering..."

  : > "${USER_SANDBOX_CONFIG}"
  unset SANDBOX_OVERLAY
  eq "default is advisory" "advisory" "$(resolve_vetting_posture)"

  printf 'vetting: off\n' > "${USER_SANDBOX_CONFIG}"
  eq "user can set off" "off" "$(resolve_vetting_posture)"

  printf 'vetting: required\n' > "${USER_SANDBOX_CONFIG}"
  eq "user can set required" "required" "$(resolve_vetting_posture)"

  # An overlay ratchets UP: user off + overlay required => required.
  local overlay="${TEST_DIR}/overlay"
  mkdir -p "${overlay}"
  printf 'vetting: required\n' > "${overlay}/config.yaml"
  printf 'vetting: off\n' > "${USER_SANDBOX_CONFIG}"
  export SANDBOX_OVERLAY="${overlay}"
  eq "overlay ratchets off->required" "required" "$(resolve_vetting_posture)"

  # An overlay never ratchets DOWN: user required + overlay advisory => required.
  printf 'vetting: advisory\n' > "${overlay}/config.yaml"
  printf 'vetting: required\n' > "${USER_SANDBOX_CONFIG}"
  eq "overlay cannot lower required" "required" "$(resolve_vetting_posture)"

  # Unrecognized value normalizes to advisory (fail safe, not off).
  printf 'vetting: bogus\n' > "${USER_SANDBOX_CONFIG}"
  eq "bad value -> advisory" "advisory" "$(resolve_vetting_posture 2>/dev/null)"

  unset SANDBOX_OVERLAY
}

###############################################################################
# vetting_status_repo — not-git / dirty / unvetted classification.
###############################################################################
test_status_classification() {
  info "Testing vetting_status_repo classification..."
  write_trust_config

  # not-git: a plain directory.
  local plain="${TEST_DIR}/plain"
  mkdir -p "${plain}"
  eq "plain dir -> not-git" "not-git" "$(vetting_status_repo "${plain}" | cut -f1)"

  # unvetted: a clean git repo with no attestation tag.
  local repo="${TEST_DIR}/repo-unvetted"
  make_repo "${repo}"
  eq "clean repo, no tag -> unvetted" "unvetted" "$(vetting_status_repo "${repo}" | cut -f1)"

  # dirty: uncommitted change.
  echo "change" >> "${repo}/README.md"
  eq "uncommitted change -> dirty" "dirty" "$(vetting_status_repo "${repo}" | cut -f1)"
}

###############################################################################
# vetting_status_repo — verified attestation (needs SSH signing).
###############################################################################
test_status_vetted() {
  info "Testing vetting_status_repo verified/rejected attestation..."
  write_trust_config

  local repo="${TEST_DIR}/repo-vetted"
  make_repo "${repo}"
  attest_repo "${repo}" "${TEST_DIR}/id" || { warn "git SSH tag signing failed; skipping"; return 0; }
  eq "trusted signature -> vetted" "vetted" "$(vetting_status_repo "${repo}" | cut -f1)"

  # A new commit invalidates the attestation (tag no longer points at HEAD).
  echo "more" >> "${repo}/README.md"
  git -C "${repo}" add -A
  git -C "${repo}" commit -q -m "second"
  eq "new commit -> unvetted (stale)" "unvetted" "$(vetting_status_repo "${repo}" | cut -f1)"

  # A signature by a key NOT in the trust root does not count.
  local repo2="${TEST_DIR}/repo-untrusted"
  make_repo "${repo2}"
  attest_repo "${repo2}" "${TEST_DIR}/id-untrusted" || { warn "signing failed; skipping"; return 0; }
  eq "untrusted signer -> unvetted" "unvetted" "$(vetting_status_repo "${repo2}" | cut -f1)"
}

###############################################################################
# vetting_gate_repos — posture behavior.
###############################################################################
test_gate_posture() {
  info "Testing vetting_gate_repos posture behavior..."
  write_trust_config

  local repo="${TEST_DIR}/gate-repo"
  make_repo "${repo}"

  # off: always proceeds (no verification at all).
  ( vetting_gate_repos "off" "false" "${repo}" >/dev/null 2>&1 ) \
    && pass "off proceeds" || fail "off should proceed"

  # advisory: proceeds despite the repo being unvetted.
  ( vetting_gate_repos "advisory" "false" "${repo}" >/dev/null 2>&1 ) \
    && pass "advisory proceeds on unvetted" || fail "advisory should proceed"

  # required: refuses an unvetted repo.
  if ( vetting_gate_repos "required" "false" "${repo}" >/dev/null 2>&1 ); then
    fail "required should refuse an unvetted repo"
  fi
  pass "required refuses unvetted repo"

  # required + override: proceeds.
  ( vetting_gate_repos "required" "true" "${repo}" >/dev/null 2>&1 ) \
    && pass "override proceeds despite unvetted" || fail "override should proceed"
}

###############################################################################
# vetting_gate_repos — a verified repo passes 'required' (needs SSH signing).
###############################################################################
test_gate_required_passes_when_vetted() {
  info "Testing required posture passes on a vetted repo..."
  write_trust_config

  local repo="${TEST_DIR}/gate-vetted"
  make_repo "${repo}"
  attest_repo "${repo}" "${TEST_DIR}/id" || { warn "signing failed; skipping"; return 0; }

  ( vetting_gate_repos "required" "false" "${repo}" >/dev/null 2>&1 ) \
    && pass "required proceeds on a vetted repo" || fail "required should pass a vetted repo"
}

###############################################################################
# Hermetic verification — a repo-local gpg.ssh.program must NOT be able to (a)
# forge a 'vetted' verdict or (b) execute on the host. This is the trust
# boundary the gate exists to hold. Needs SSH signing to produce the tag.
###############################################################################
test_verify_hermetic_against_program_hijack() {
  info "Testing verification is hermetic against repo-local gpg.ssh.program..."
  write_trust_config

  local repo="${TEST_DIR}/hijack-prog"
  make_repo "${repo}"
  # Commit the fake verifier so the tree stays CLEAN (otherwise the dirty-check
  # short-circuits before verification and this test wouldn't exercise it). It
  # always "succeeds" and records that it ran.
  local sentinel="${TEST_DIR}/hijack-prog-RAN"
  local evil="${repo}/evil-verify.sh"
  cat > "${evil}" <<EOF
#!/usr/bin/env bash
: > "${sentinel}"
echo 'Good "git" signature for ${SIGNER_EMAIL}'
exit 0
EOF
  chmod +x "${evil}"
  git -C "${repo}" add evil-verify.sh
  git -C "${repo}" commit -q -m "evil"
  # Attacker signs an attestation tag at (the now-clean) HEAD with a key NOT in
  # the trust root, and points repo-local git config at the planted verifier —
  # a vulnerable gate would run it (host RCE) and trust its output (forged).
  attest_repo "${repo}" "${TEST_DIR}/id-untrusted" || { warn "signing failed; skipping"; return 0; }
  git -C "${repo}" config gpg.ssh.program "${evil}"

  local status
  status="$(vetting_status_repo "${repo}" | cut -f1)"
  [[ "${status}" != "vetted" ]] \
    && pass "planted verifier cannot forge a 'vetted' verdict (got ${status})" \
    || fail "SECURITY: repo-local gpg.ssh.program forged a 'vetted' verdict"
  [[ ! -e "${sentinel}" ]] \
    && pass "planted verifier program was never executed (no host RCE)" \
    || fail "SECURITY: repo-local gpg.ssh.program executed on the host"
}

###############################################################################
# Hermetic status — a repo-local core.fsmonitor must NOT be executed during the
# dirty-tree check. Differential: only meaningful where this git execs it.
###############################################################################
test_status_hermetic_against_fsmonitor() {
  info "Testing dirty-check neutralizes repo-local core.fsmonitor..."
  write_trust_config

  local repo="${TEST_DIR}/hijack-fsmon"
  make_repo "${repo}"
  local sentinel="${TEST_DIR}/fsmon-RAN"
  local evil="${repo}/evil-fsmon.sh"
  cat > "${evil}" <<EOF
#!/usr/bin/env bash
: > "${sentinel}"
exit 1
EOF
  chmod +x "${evil}"
  git -C "${repo}" config core.fsmonitor "${evil}"

  # Confirm the vector is real for this git build: an unhardened status runs it.
  ( cd "${repo}" && git status --porcelain >/dev/null 2>&1 || true )
  if [[ ! -e "${sentinel}" ]]; then
    warn "this git does not exec core.fsmonitor on status; vector N/A, skipping"
    return 0
  fi
  pass "confirmed: unhardened git status executes core.fsmonitor"

  rm -f "${sentinel}"
  # The hardened wrapper (as used by the gate) must NOT execute it.
  _vetting_git "${repo}" status --porcelain >/dev/null 2>&1 || true
  [[ ! -e "${sentinel}" ]] \
    && pass "hardened status does not execute core.fsmonitor (no host RCE)" \
    || fail "SECURITY: core.fsmonitor executed via the hardened status check"
}

###############################################################################
# Missing trust root — fails closed under 'required', regardless of override.
###############################################################################
test_missing_trust_root_fails_closed() {
  info "Testing missing trust root fails closed under required..."

  # Point at a trust root that does not exist.
  cat > "${USER_SANDBOX_CONFIG}" <<EOF
vetting_trust_root: ${TEST_DIR}/does-not-exist
vetting_trust_format: ssh
EOF
  local repo="${TEST_DIR}/gate-notrust"
  make_repo "${repo}"

  # required, no override -> refuse.
  if ( vetting_gate_repos "required" "false" "${repo}" >/dev/null 2>&1 ); then
    fail "required with missing trust root should refuse"
  fi
  pass "required refuses when trust root is missing"

  # required + override -> STILL refuses (config error, not an accepted risk).
  if ( vetting_gate_repos "required" "true" "${repo}" >/dev/null 2>&1 ); then
    fail "override must not bypass a missing trust root"
  fi
  pass "override does not bypass a missing trust root"

  # advisory -> proceeds (can't verify, but doesn't block).
  ( vetting_gate_repos "advisory" "false" "${repo}" >/dev/null 2>&1 ) \
    && pass "advisory proceeds without a trust root" || fail "advisory should proceed"
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""
  echo "Test directory: ${TEST_DIR}"
  echo ""

  setup_signer
  [[ "${SSH_SIGNING}" -eq 1 ]] && info "SSH signing available — running signature cases" \
                               || warn "SSH signing unavailable — signature cases will skip"

  test_posture_layering
  test_status_classification
  test_gate_posture
  test_missing_trust_root_fails_closed
  test_status_hermetic_against_fsmonitor
  if [[ "${SSH_SIGNING}" -eq 1 ]]; then
    test_status_vetted
    test_gate_required_passes_when_vetted
    test_verify_hermetic_against_program_hijack
  else
    echo "SKIP: signature cases (test_status_vetted, test_gate_required_passes_when_vetted, test_verify_hermetic_against_program_hijack) — SSH signing unavailable"
  fi

  echo ""
  echo "All vetting tests passed."
}

main "$@"
