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
# Hermetic status — a repo-local content filter (clean/process) must NOT be
# executed during the dirty check. The driver lives in git config and the path
# mapping in in-tree .gitattributes — both attacker-controlled. Three declaration
# styles are exercised because the neutralization must survive all: a plain
# name, a name containing '=' (which `git -c name=value` would mis-split), and a
# driver hidden behind `[include]` (invisible to `config --local`).
###############################################################################

# _filter_neutralization_check <label> <repo> <sentinel> — reset the index so
# status re-hashes the worktree (independent of racy-git), confirm an unhardened
# `git status` runs the planted driver (else skip: vector N/A on this git), then
# assert the hardened `_vetting_git status` does not.
_filter_neutralization_check() {
  local label="$1" repo="$2" sentinel="$3"
  rm -f "${repo}/.git/index"; git -C "${repo}" read-tree HEAD
  rm -f "${sentinel}"
  ( cd "${repo}" && git status --porcelain >/dev/null 2>&1 || true )
  if [[ ! -e "${sentinel}" ]]; then
    warn "this git does not run the ${label} filter on status; vector N/A, skipping"
    return 0
  fi
  pass "confirmed: unhardened git status runs the ${label} filter"

  rm -f "${repo}/.git/index"; git -C "${repo}" read-tree HEAD
  rm -f "${sentinel}"
  _vetting_git "${repo}" status --porcelain >/dev/null 2>&1 || true
  [[ ! -e "${sentinel}" ]] \
    && pass "hardened status neutralizes the ${label} filter (no host RCE)" \
    || fail "SECURITY: ${label} filter executed via the hardened status check"
}

test_status_hermetic_against_filter() {
  info "Testing dirty-check neutralizes a plain repo-local content filter..."
  write_trust_config
  local repo="${TEST_DIR}/hijack-filter"
  make_repo "${repo}"
  local sentinel="${TEST_DIR}/filter-RAN"
  printf '* filter=pwn\n' > "${repo}/.gitattributes"
  git -C "${repo}" add .gitattributes; git -C "${repo}" commit -q -m attrs
  git -C "${repo}" config filter.pwn.clean "touch ${sentinel}; cat"
  git -C "${repo}" config filter.pwn.required true
  _filter_neutralization_check "plain" "${repo}" "${sentinel}"
}

# A filter subsection name containing '=' — `git -c filter.x=y.clean=cat` would
# mis-split on the first '=' and never override the real driver. The env-based
# GIT_CONFIG_KEY pinning takes the key verbatim and must hold.
test_status_hermetic_against_equals_named_filter() {
  info "Testing dirty-check neutralizes an '='-named filter..."
  write_trust_config
  local repo="${TEST_DIR}/hijack-eqfilter"
  make_repo "${repo}"
  local sentinel="${TEST_DIR}/eqfilter-RAN"
  printf '* filter=x=y\n' > "${repo}/.gitattributes"
  git -C "${repo}" add .gitattributes; git -C "${repo}" commit -q -m attrs
  git -C "${repo}" config 'filter.x=y.clean' "touch ${sentinel}; cat"
  git -C "${repo}" config 'filter.x=y.required' true
  _filter_neutralization_check "=-named" "${repo}" "${sentinel}"
}

# A filter driver defined in a file pulled in via `[include]` — invisible to
# `config --local` but honored when the filter runs. Enumeration must follow
# includes (no --local) so it is discovered and pinned.
test_status_hermetic_against_included_filter() {
  info "Testing dirty-check neutralizes an include-defined filter..."
  write_trust_config
  local repo="${TEST_DIR}/hijack-incfilter"
  make_repo "${repo}"
  local sentinel="${TEST_DIR}/incfilter-RAN"
  printf '* filter=inc\n' > "${repo}/.gitattributes"
  git -C "${repo}" add .gitattributes; git -C "${repo}" commit -q -m attrs
  printf '[filter "inc"]\n\tclean = touch %s; cat\n\trequired = true\n' "${sentinel}" \
    > "${repo}/.git/extra.cfg"
  git -C "${repo}" config --add include.path extra.cfg
  _filter_neutralization_check "include-defined" "${repo}" "${sentinel}"
}

# An empty filter subsection: `[filter ""]` with `.gitattributes` `* filter=`.
# The enumeration emits a blank name — the neutralization must pin it, not skip
# it as if it were empty pipeline output.
test_status_hermetic_against_empty_named_filter() {
  info "Testing dirty-check neutralizes an empty-named filter..."
  write_trust_config
  local repo="${TEST_DIR}/hijack-emptyfilter"
  make_repo "${repo}"
  local sentinel="${TEST_DIR}/emptyfilter-RAN"
  printf '* filter=\n' > "${repo}/.gitattributes"
  git -C "${repo}" add .gitattributes; git -C "${repo}" commit -q -m attrs
  # `[filter ""]` can't be set via `git config <key>`; write it to .git/config.
  printf '[filter ""]\n\tclean = touch %s; cat\n\trequired = true\n' "${sentinel}" \
    >> "${repo}/.git/config"
  _filter_neutralization_check "empty-named" "${repo}" "${sentinel}"
}

###############################################################################
# Hermetic verify — a repo-local gpg.x509.program must NOT execute when git
# auto-detects an X.509-armored tag on the verify path.
###############################################################################
test_verify_hermetic_against_x509_program() {
  info "Testing verification is hermetic against repo-local gpg.x509.program..."
  write_trust_config

  local repo="${TEST_DIR}/hijack-x509"
  make_repo "${repo}"
  local sentinel="${TEST_DIR}/x509-RAN"
  local evil="${TEST_DIR}/evil-x509.sh"   # outside the repo, so the tree stays clean
  cat > "${evil}" <<EOF
#!/usr/bin/env bash
: > "${sentinel}"
exit 1
EOF
  chmod +x "${evil}"
  git -C "${repo}" config gpg.x509.program "${evil}"

  # Plant an annotated tag at HEAD whose message carries the X.509 armor header,
  # so 'git tag -v' auto-detects an X.509 signature and routes to gpg.x509.program.
  local sha; sha="$(git -C "${repo}" rev-parse HEAD)"
  git -C "${repo}" tag -a "agent-vetted/${sha}" \
    -m "$(printf -- '-----BEGIN SIGNED MESSAGE-----\nAAAA\n-----END SIGNED MESSAGE-----\n')"

  # Confirm the vector: verify with the ssh/openpgp pins but WITHOUT the x509
  # pin (as the pre-fix code did) executes the planted program.
  local kg; kg="$(command -v ssh-keygen 2>/dev/null || echo /bin/false)"
  rm -f "${sentinel}"
  ( GNUPGHOME="$(mktemp -d "${TEST_DIR}/gh-XXXXXX")" git -C "${repo}" \
      -c gpg.ssh.program="${kg}" -c gpg.format=ssh \
      -c gpg.ssh.allowedSignersFile="${TRUST_ROOT}" \
      tag -v "agent-vetted/${sha}" >/dev/null 2>&1 || true )
  if [[ ! -e "${sentinel}" ]]; then
    warn "this git does not route to gpg.x509.program for this tag; vector N/A, skipping"
    return 0
  fi
  pass "confirmed: unpinned gpg.x509.program runs during verify"

  rm -f "${sentinel}"
  _vetting_verify_tag "${repo}" "agent-vetted/${sha}" "${TRUST_ROOT}" "ssh" >/dev/null 2>&1 || true
  [[ ! -e "${sentinel}" ]] \
    && pass "hardened verify does not execute gpg.x509.program (no host RCE)" \
    || fail "SECURITY: repo-local gpg.x509.program executed during verify"
}

###############################################################################
# Hermetic attest — `git tag -s` on the attest path must NOT run a repo-local
# gpg.ssh.defaultKeyCommand (git invokes it to obtain a key when user.signingkey
# is unset). Globals are nulled so user.signingkey is unset for the test.
###############################################################################
test_attest_hermetic_against_defaultkeycommand() {
  info "Testing attest neutralizes repo-local gpg.ssh.defaultKeyCommand..."
  write_trust_config

  local repo="${TEST_DIR}/hijack-keycmd"
  make_repo "${repo}"
  local sentinel="${TEST_DIR}/keycmd-RAN"
  local evil="${repo}/evil-keycmd.sh"
  cat > "${evil}" <<EOF
#!/usr/bin/env bash
: > "${sentinel}"
exit 1
EOF
  chmod +x "${evil}"
  git -C "${repo}" add evil-keycmd.sh; git -C "${repo}" commit -q -m keycmd
  git -C "${repo}" config gpg.ssh.defaultKeyCommand "${evil}"

  local fb kg gpgb
  fb="$(command -v false 2>/dev/null || echo /bin/false)"
  kg="$(command -v ssh-keygen 2>/dev/null || echo "${fb}")"
  gpgb="$(command -v gpg 2>/dev/null || echo "${fb}")"

  # Confirm the vector: ssh-sign with the pre-fix pins (no defaultKeyCommand pin)
  # and no user.signingkey (globals nulled) runs the planted key command.
  rm -f "${sentinel}"
  ( GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null git -C "${repo}" \
      -c gpg.format=ssh -c "gpg.ssh.program=${kg}" -c "gpg.program=${gpgb}" \
      -c "gpg.x509.program=${fb}" tag -s "probe-$$" -m x >/dev/null 2>&1 || true )
  git -C "${repo}" tag -d "probe-$$" >/dev/null 2>&1 || true
  if [[ ! -e "${sentinel}" ]]; then
    warn "this git does not run gpg.ssh.defaultKeyCommand here; vector N/A, skipping"
    return 0
  fi
  pass "confirmed: unpinned gpg.ssh.defaultKeyCommand runs during ssh sign"

  # The hardened attest path must NOT run it (globals nulled → user.signingkey
  # unset, so the defaultKeyCommand fallback is what git would reach for).
  rm -f "${sentinel}"
  ( GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
    vetting_attest_repo "${repo}" "vetted" >/dev/null 2>&1 || true )
  [[ ! -e "${sentinel}" ]] \
    && pass "hardened attest does not execute gpg.ssh.defaultKeyCommand (no host RCE)" \
    || fail "SECURITY: gpg.ssh.defaultKeyCommand executed during attest"
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
  test_status_hermetic_against_filter
  test_status_hermetic_against_equals_named_filter
  test_status_hermetic_against_included_filter
  test_status_hermetic_against_empty_named_filter
  test_verify_hermetic_against_x509_program
  test_attest_hermetic_against_defaultkeycommand
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
