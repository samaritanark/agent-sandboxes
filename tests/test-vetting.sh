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
# Attest now surfaces a repo's secret exceptions before signing (Phase 2b), which
# scans via the secret gate, so filesystem.sh is in scope here too.
source "${SANDBOX_ROOT}/lib/filesystem.sh"
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
  local line status behind
  line="$(vetting_status_repo "${repo}")"
  status="$(cut -f1 <<<"${line}")"; behind="$(cut -f5 <<<"${line}")"
  eq "trusted signature -> vetted" "vetted" "${status}"
  eq "attestation at HEAD -> behind 0" "0" "${behind}"

  # A new commit no longer invalidates the attestation: the tag is now a verified
  # ANCESTOR of HEAD, so the repo stays vetted and the drift count rises to 1.
  echo "more" >> "${repo}/README.md"
  git -C "${repo}" add -A
  git -C "${repo}" commit -q -m "second"
  line="$(vetting_status_repo "${repo}")"
  status="$(cut -f1 <<<"${line}")"; behind="$(cut -f5 <<<"${line}")"
  eq "new commit -> still vetted (ancestor)" "vetted" "${status}"
  eq "new commit -> behind 1" "1" "${behind}"

  # A second commit deepens the drift to 2.
  echo "yet more" >> "${repo}/README.md"
  git -C "${repo}" add -A
  git -C "${repo}" commit -q -m "third"
  eq "two commits -> behind 2" "2" "$(vetting_status_repo "${repo}" | cut -f5)"

  # A tag on a DIVERGENT line (not an ancestor of HEAD) does not count.
  local repo3="${TEST_DIR}/repo-divergent"
  make_repo "${repo3}"
  git -C "${repo3}" checkout -q -b sidebranch
  echo "side" >> "${repo3}/side.txt"
  git -C "${repo3}" add -A
  git -C "${repo3}" commit -q -m "side commit"
  attest_repo "${repo3}" "${TEST_DIR}/id" || { warn "signing failed; skipping"; return 0; }
  # Back on the mainline, the side-branch attestation is not reachable from HEAD.
  git -C "${repo3}" checkout -q "$(git -C "${repo3}" rev-list --max-parents=0 HEAD)"
  git -C "${repo3}" checkout -q -B main
  eq "divergent-line tag -> unvetted" "unvetted" "$(vetting_status_repo "${repo3}" | cut -f1)"

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
  ( vetting_gate_repos "off" "false" "false" "${repo}" >/dev/null 2>&1 ) \
    && pass "off proceeds" || fail "off should proceed"

  # advisory: proceeds despite the repo being unvetted.
  ( vetting_gate_repos "advisory" "false" "false" "${repo}" >/dev/null 2>&1 ) \
    && pass "advisory proceeds on unvetted" || fail "advisory should proceed"

  # required: refuses an unvetted repo.
  if ( vetting_gate_repos "required" "false" "false" "${repo}" >/dev/null 2>&1 ); then
    fail "required should refuse an unvetted repo"
  fi
  pass "required refuses unvetted repo"

  # required + override: proceeds.
  ( vetting_gate_repos "required" "true" "false" "${repo}" >/dev/null 2>&1 ) \
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

  ( vetting_gate_repos "required" "false" "false" "${repo}" >/dev/null 2>&1 ) \
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
# Exceptions acknowledgment (Phase 2b) — attest surfaces a repo's recorded
# secret exceptions and refuses to sign them off unattended; --yes acknowledges.
###############################################################################
test_attest_acknowledges_exceptions() {
  [[ "${SSH_SIGNING}" -eq 1 ]] || { info "SSH signing unavailable — skipping exceptions-ack test"; return 0; }
  command -v betterleaks >/dev/null 2>&1 || { info "betterleaks not installed — skipping exceptions-ack test"; return 0; }
  command -v jq >/dev/null 2>&1 || { info "jq not installed — skipping exceptions-ack test"; return 0; }
  info "Testing attest surfaces + gates on recorded secret exceptions..."
  write_trust_config

  local repo="${TEST_DIR}/ack-exceptions"
  make_repo "${repo}"
  mkdir -p "${repo}/deploy"
  printf 'api_key: ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5z\n' > "${repo}/deploy/values.yaml"
  git -C "${repo}" add -A; git -C "${repo}" commit -q -m "add config"
  # Sign with the trusted key (attest inherits user.signingkey from repo config).
  git -C "${repo}" config gpg.format ssh
  git -C "${repo}" config user.signingkey "${TEST_DIR}/id"

  # Record an exception for every unmasked finding, then commit (clean tree).
  local frel frule fln one recorded=0
  while IFS=$'\t' read -r _ frel frule fln _; do
    [[ -z "${frel}" ]] && continue
    while IFS= read -r one; do
      [[ -z "${one}" ]] && continue
      ignorefile_add_fingerprint "$(repo_ignore_file "${repo}")" "${one}" "reviewed FP"
      recorded=$((recorded + 1))
    done < <(leakscan_fingerprints_for "${repo}" "${frel}" "${frule}" "${fln}")
  done < <(scan_repo_secrets "${repo}" | grep "^no	" || true)
  [[ "${recorded}" -gt 0 ]] || fail "expected at least one finding to record as an exception"
  git -C "${repo}" add -A; git -C "${repo}" commit -q -m "record exceptions"

  local sha; sha="$(git -C "${repo}" rev-parse HEAD)"

  # (1) Non-interactive, no --yes → refuse to sign off unattended; no tag.
  if ( vetting_attest_repo "${repo}" "vetted" "false" </dev/null >/dev/null 2>&1 ); then
    fail "attest must refuse to bless exceptions unattended (no --yes)"
  fi
  git -C "${repo}" rev-parse -q --verify "refs/tags/agent-vetted/${sha}" >/dev/null 2>&1 \
    && fail "no tag should exist after a refused acknowledgment" \
    || pass "attest refuses exceptions unattended; no tag created"

  # (2) --yes acknowledges → tag created and the repo verifies as vetted.
  if ( vetting_attest_repo "${repo}" "vetted" "true" </dev/null >/dev/null 2>&1 ); then
    pass "attest --yes acknowledges exceptions and signs"
  else
    fail "attest --yes should create the attestation"
  fi
  local status _f
  IFS=$'\t' read -r status _f < <(vetting_status_repo "${repo}")
  eq "repo is vetted after --yes attest" "vetted" "${status}"

  # (3) A repo with NO exceptions attests without prompting, even unattended.
  local clean="${TEST_DIR}/ack-clean"
  make_repo "${clean}"
  git -C "${clean}" config gpg.format ssh
  git -C "${clean}" config user.signingkey "${TEST_DIR}/id"
  if ( vetting_attest_repo "${clean}" "vetted" "false" </dev/null >/dev/null 2>&1 ); then
    pass "attest proceeds unattended when there are no exceptions"
  else
    fail "attest should not prompt/refuse when there are no exceptions"
  fi
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
  if ( vetting_gate_repos "required" "false" "false" "${repo}" >/dev/null 2>&1 ); then
    fail "required with missing trust root should refuse"
  fi
  pass "required refuses when trust root is missing"

  # required + override -> STILL refuses (config error, not an accepted risk).
  if ( vetting_gate_repos "required" "true" "false" "${repo}" >/dev/null 2>&1 ); then
    fail "override must not bypass a missing trust root"
  fi
  pass "override does not bypass a missing trust root"

  # advisory -> proceeds (can't verify, but doesn't block).
  ( vetting_gate_repos "advisory" "false" "false" "${repo}" >/dev/null 2>&1 ) \
    && pass "advisory proceeds without a trust root" || fail "advisory should proceed"
}

###############################################################################
# Trust roots — overlay-shipped root (relative path resolves against the
# overlay), union with the operator's local root, and none-at-all fails closed.
###############################################################################
test_trust_roots_overlay_and_union() {
  [[ "${SSH_SIGNING}" -eq 1 ]] || { info "SSH signing unavailable — skipping trust-roots union test"; return 0; }
  info "Testing overlay-shipped trust root and union semantics..."

  # Overlay ships its reviewer list as a plain file in its own tree, referenced
  # by a RELATIVE path — it must resolve against the overlay root.
  local overlay="${TEST_DIR}/overlay-roots"
  mkdir -p "${overlay}"
  printf '%s %s\n' "${SIGNER_EMAIL}" "$(awk '{print $1" "$2}' "${TEST_DIR}/id.pub")" \
    > "${overlay}/allowed_signers"
  printf 'vetting_trust_root: allowed_signers\n' > "${overlay}/config.yaml"

  # Local/user root: points at a file that does not exist.
  cat > "${USER_SANDBOX_CONFIG}" <<EOF
vetting_trust_root: ${TEST_DIR}/no-such-root
vetting_trust_format: ssh
EOF
  export SANDBOX_OVERLAY="${overlay}"

  local repo="${TEST_DIR}/roots-overlay"
  make_repo "${repo}"
  attest_repo "${repo}" "${TEST_DIR}/id" || { warn "signing failed; skipping"; unset SANDBOX_OVERLAY; return 0; }
  eq "overlay-relative trust root verifies" "vetted" "$(vetting_status_repo "${repo}" | cut -f1)"

  # Union: a signer only in the LOCAL root must also count while the overlay
  # root is active (the local file adds to the team list, not replaced by it).
  printf 'untrusted@sandbox.test %s\n' "$(awk '{print $1" "$2}' "${TEST_DIR}/id-untrusted.pub")" \
    > "${TEST_DIR}/local-extra-signers"
  cat > "${USER_SANDBOX_CONFIG}" <<EOF
vetting_trust_root: ${TEST_DIR}/local-extra-signers
vetting_trust_format: ssh
EOF
  local repo2="${TEST_DIR}/roots-local"
  make_repo "${repo2}"
  attest_repo "${repo2}" "${TEST_DIR}/id-untrusted" || { warn "signing failed; skipping"; unset SANDBOX_OVERLAY; return 0; }
  eq "local-root signer counts alongside overlay" "vetted" "$(vetting_status_repo "${repo2}" | cut -f1)"
  eq "overlay-root signer still counts too" "vetted" "$(vetting_status_repo "${repo}" | cut -f1)"

  # No root ANYWHERE (overlay ships none, local missing): required fails closed
  # even with the override.
  local overlay2="${TEST_DIR}/overlay-norootskey"
  mkdir -p "${overlay2}"
  printf 'vetting: required\n' > "${overlay2}/config.yaml"
  cat > "${USER_SANDBOX_CONFIG}" <<EOF
vetting_trust_root: ${TEST_DIR}/no-such-root
vetting_trust_format: ssh
EOF
  export SANDBOX_OVERLAY="${overlay2}"
  if ( vetting_gate_repos "required" "true" "false" "${repo}" >/dev/null 2>&1 ); then
    fail "no trust root anywhere must fail closed despite override"
  fi
  pass "no trust root anywhere fails closed despite override"

  unset SANDBOX_OVERLAY
}

###############################################################################
# Inline attest offer — non-TTY launches never prompt (straight refusal); on a
# TTY, decline refuses with no tag, accept attests+verifies and the gate passes.
# The TTY cases need script(1) with GNU-style -qec; skip gracefully without it.
###############################################################################
test_gate_inline_attest() {
  [[ "${SSH_SIGNING}" -eq 1 ]] || { info "SSH signing unavailable — skipping inline-attest test"; return 0; }
  info "Testing inline attest offer at the gate..."
  write_trust_config

  local repo="${TEST_DIR}/inline-repo"
  make_repo "${repo}"
  git -C "${repo}" config gpg.format ssh
  git -C "${repo}" config user.signingkey "${TEST_DIR}/id"
  local sha; sha="$(git -C "${repo}" rev-parse HEAD)"

  # Non-TTY: no prompt text, straight refusal, no tag.
  local out=""
  out="$( ( vetting_gate_repos "required" "false" "false" "${repo}" </dev/null 2>&1 ) || true )"
  case "${out}" in
    *"Attest HEAD"*) fail "non-TTY launch must not offer an inline attest" ;;
    *) pass "non-TTY launch does not prompt" ;;
  esac
  git -C "${repo}" rev-parse -q --verify "refs/tags/agent-vetted/${sha}" >/dev/null 2>&1 \
    && fail "non-TTY refusal must not create a tag" \
    || pass "non-TTY refusal leaves no tag"

  # TTY cases need a pty.
  if ! command -v script >/dev/null 2>&1 || ! script -qec true /dev/null >/dev/null 2>&1; then
    warn "script(1) with -qec unavailable — skipping interactive inline-attest cases"
    return 0
  fi

  local runner="${TEST_DIR}/gate-runner.sh"
  cat > "${runner}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
export USER_SANDBOX_CONFIG="${USER_SANDBOX_CONFIG}"
unset SANDBOX_OVERLAY
source "${SANDBOX_ROOT}/lib/platform.sh"
source "${SANDBOX_ROOT}/lib/config.sh"
source "${SANDBOX_ROOT}/lib/profile.sh"
source "${SANDBOX_ROOT}/lib/filesystem.sh"
source "${SANDBOX_ROOT}/lib/vetting.sh"
vetting_gate_repos "required" "false" "false" "\$1"
EOF

  # Decline: refusal (non-zero), no tag.
  if printf 'n\n' | script -qec "bash ${runner} ${repo}" /dev/null >/dev/null 2>&1; then
    fail "declining the inline attest must still refuse the launch"
  fi
  git -C "${repo}" rev-parse -q --verify "refs/tags/agent-vetted/${sha}" >/dev/null 2>&1 \
    && fail "declined offer must not create a tag" \
    || pass "declined inline attest refuses and leaves no tag"

  # Accept: gate passes, verified tag exists.
  if printf 'y\n' | script -qec "bash ${runner} ${repo}" /dev/null >/dev/null 2>&1; then
    pass "accepted inline attest passes the gate"
  else
    fail "accepting the inline attest should pass the gate"
  fi
  eq "repo is vetted after inline attest" "vetted" "$(vetting_status_repo "${repo}" | cut -f1)"

  # Not-enrolled signer: attest succeeds but cannot verify → tag rolled back,
  # launch refused. Point the trust root at a list without our key.
  local repo3="${TEST_DIR}/inline-notenrolled"
  make_repo "${repo3}"
  git -C "${repo3}" config gpg.format ssh
  git -C "${repo3}" config user.signingkey "${TEST_DIR}/id"
  local sha3; sha3="$(git -C "${repo3}" rev-parse HEAD)"
  printf 'someone-else@sandbox.test %s\n' "$(awk '{print $1" "$2}' "${TEST_DIR}/id-untrusted.pub")" \
    > "${TEST_DIR}/other-signers"
  cat > "${USER_SANDBOX_CONFIG}" <<EOF
vetting_trust_root: ${TEST_DIR}/other-signers
vetting_trust_format: ssh
EOF
  if printf 'y\n' | script -qec "bash ${runner} ${repo3}" /dev/null >/dev/null 2>&1; then
    fail "an unenrolled signer's inline attest must not pass the gate"
  fi
  git -C "${repo3}" rev-parse -q --verify "refs/tags/agent-vetted/${sha3}" >/dev/null 2>&1 \
    && fail "unverifiable inline attestation must be rolled back" \
    || pass "unenrolled signer: attest rolled back, launch refused"

  write_trust_config
}

###############################################################################
# SSH signing-key mismatch — a GPG key id left in user.signingkey (the classic
# legacy-config case) must be classified, must produce the targeted hint on a
# failed attest, and must suppress the inline attest offer.
###############################################################################
test_ssh_signingkey_mismatch() {
  info "Testing GPG-keyid-in-user.signingkey detection..."
  write_trust_config

  # Null the global/system git scopes so the developer's own signing config
  # can't leak into the classification under test (repo-local config only).
  # An env prefix on the function call propagates to the git children it runs.
  state_of() {
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
      _vetting_ssh_signingkey_state "$1"
  }

  local repo="${TEST_DIR}/mismatch-repo"
  make_repo "${repo}"

  eq "no signingkey -> unconfigured" "unconfigured" "$(state_of "${repo}")"

  git -C "${repo}" config user.signingkey "DAC1371AD9A4D709"
  eq "GPG key id -> mismatch" "mismatch" "$(state_of "${repo}")"

  git -C "${repo}" config user.signingkey "${TEST_DIR}/id.pub"
  eq "existing key file -> ok" "ok" "$(state_of "${repo}")"

  git -C "${repo}" config user.signingkey "ssh-ed25519 AAAATESTLITERALKEY comment"
  eq "literal ssh key -> ok" "ok" "$(state_of "${repo}")"

  # Failed attest with a mismatched key prints the targeted hint.
  git -C "${repo}" config user.signingkey "DAC1371AD9A4D709"
  local out=""
  out="$( ( GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
            vetting_attest_repo "${repo}" "vetted" "false" </dev/null 2>&1 ) || true )"
  case "${out}" in
    *"looks like a GPG key id"*) pass "failed attest names the GPG-keyid cause" ;;
    *) fail "failed attest should include the GPG-keyid hint (got: ${out})" ;;
  esac

  # The inline-offer gate condition is false for a mismatched key (an offer
  # would just fail after 'y') and true again once the key is usable.
  if GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null _vetting_signing_configured "${repo}"; then
    fail "signing_configured must be false for an unusable (GPG id) key in ssh mode"
  fi
  pass "inline offer condition false for an unusable signing key"
  git -C "${repo}" config user.signingkey "${TEST_DIR}/id.pub"
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null _vetting_signing_configured "${repo}" \
    && pass "inline offer condition true for a usable key file" \
    || fail "signing_configured should be true for an existing key file"
}

###############################################################################
# vetting_signing_key — an attestation-only SSH key that overrides git's
# user.signingkey for vet (the GPG-commit-signer escape hatch). It must win
# over a mismatched git key, be validated itself, and produce a verifiable
# attestation without touching git config.
###############################################################################
test_vetting_signing_key_knob() {
  [[ "${SSH_SIGNING}" -eq 1 ]] || { info "SSH signing unavailable — skipping signing-key knob test"; return 0; }
  info "Testing vetting_signing_key (attestation-only key)..."
  write_trust_config

  state_of() {
    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
      _vetting_ssh_signingkey_state "$1"
  }

  local repo="${TEST_DIR}/knob-repo"
  make_repo "${repo}"
  # The Brian scenario: an OpenPGP key id in git config...
  git -C "${repo}" config user.signingkey "DAC1371AD9A4D709"
  eq "git GPG id alone -> mismatch" "mismatch" "$(state_of "${repo}")"

  # ...and the knob pointing at a real SSH key wins without touching git.
  printf 'vetting_signing_key: %s\n' "${TEST_DIR}/id.pub" >> "${USER_SANDBOX_CONFIG}"
  eq "knob overrides mismatched git key" "ok" "$(state_of "${repo}")"

  if ( GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
       vetting_attest_repo "${repo}" "vetted" "false" </dev/null >/dev/null 2>&1 ); then
    pass "attest signs with the knob key despite the GPG git config"
  else
    fail "attest should succeed using vetting_signing_key"
  fi
  eq "knob-signed attestation verifies as vetted" "vetted" "$(vetting_status_repo "${repo}" | cut -f1)"
  eq "git user.signingkey untouched" "DAC1371AD9A4D709" "$(git -C "${repo}" config user.signingkey)"

  # A bad knob value is its own state and a targeted attest hint.
  write_trust_config
  printf 'vetting_signing_key: %s/no-such-key.pub\n' "${TEST_DIR}" >> "${USER_SANDBOX_CONFIG}"
  eq "bad knob -> knob-bad" "knob-bad" "$(state_of "${repo}")"
  local repo2="${TEST_DIR}/knob-bad-repo"
  make_repo "${repo2}"
  local out=""
  out="$( ( GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
            vetting_attest_repo "${repo2}" "vetted" "false" </dev/null 2>&1 ) || true )"
  case "${out}" in
    *"vetting_signing_key"*) pass "failed attest names the bad knob" ;;
    *) fail "failed attest should name vetting_signing_key (got: ${out})" ;;
  esac

  write_trust_config
}

###############################################################################
# vetting_max_commits_behind — user + overlay layering, most-restrictive wins.
###############################################################################
test_max_commits_behind_config() {
  info "Testing vetting_max_commits_behind layering..."
  : > "${USER_SANDBOX_CONFIG}"
  unset SANDBOX_OVERLAY
  eq "unset -> no cap (empty)" "" "$(vetting_max_commits_behind)"

  printf 'vetting_max_commits_behind: 5\n' > "${USER_SANDBOX_CONFIG}"
  eq "user sets a cap" "5" "$(vetting_max_commits_behind)"

  local overlay="${TEST_DIR}/cap-overlay"
  mkdir -p "${overlay}"
  # Most restrictive (smallest) wins, in both directions.
  printf 'vetting_max_commits_behind: 20\n' > "${overlay}/config.yaml"
  printf 'vetting_max_commits_behind: 5\n'  > "${USER_SANDBOX_CONFIG}"
  export SANDBOX_OVERLAY="${overlay}"
  eq "user tighter than overlay wins" "5" "$(vetting_max_commits_behind)"

  printf 'vetting_max_commits_behind: 3\n'  > "${overlay}/config.yaml"
  printf 'vetting_max_commits_behind: 50\n' > "${USER_SANDBOX_CONFIG}"
  eq "overlay tighter than user wins" "3" "$(vetting_max_commits_behind)"

  : > "${USER_SANDBOX_CONFIG}"
  printf 'vetting_max_commits_behind: 7\n' > "${overlay}/config.yaml"
  eq "overlay-only cap applies" "7" "$(vetting_max_commits_behind)"

  # A non-integer value is ignored (fails toward no cap, not a nonsense bound).
  printf 'vetting_max_commits_behind: lots\n' > "${USER_SANDBOX_CONFIG}"
  rm -f "${overlay}/config.yaml"
  unset SANDBOX_OVERLAY
  eq "non-integer -> no cap" "" "$(vetting_max_commits_behind)"

  : > "${USER_SANDBOX_CONFIG}"
}

###############################################################################
# vetting_gate_repos — drift acceptance and the overlay cap (needs SSH signing).
###############################################################################
test_gate_drift() {
  info "Testing required-posture drift acceptance and cap..."
  write_trust_config
  unset SANDBOX_OVERLAY

  local repo="${TEST_DIR}/gate-drift"
  make_repo "${repo}"
  attest_repo "${repo}" "${TEST_DIR}/id" || { warn "signing failed; skipping"; return 0; }
  local i
  for i in 1 2; do
    echo "c${i}" >> "${repo}/README.md"
    git -C "${repo}" add -A
    git -C "${repo}" commit -q -m "c${i}"
  done
  eq "drift repo reports behind 2" "2" "$(vetting_status_repo "${repo}" | cut -f5)"

  # No cap, no TTY, no flag: nothing can accept the drift, so required refuses.
  if ( vetting_gate_repos "required" "false" "false" "${repo}" </dev/null >/dev/null 2>&1 ); then
    fail "required should refuse un-accepted drift with no TTY/flag"
  fi
  pass "required refuses drift without acceptance"

  # --i-accept-vetting-drift accepts it non-interactively.
  ( vetting_gate_repos "required" "false" "true" "${repo}" </dev/null >/dev/null 2>&1 ) \
    && pass "--i-accept-vetting-drift accepts drift" || fail "drift flag should proceed"

  # The broad override covers drift too.
  ( vetting_gate_repos "required" "true" "false" "${repo}" </dev/null >/dev/null 2>&1 ) \
    && pass "--i-accept-unvetted-repo accepts drift" || fail "override should proceed on drift"

  # advisory proceeds and never blocks on drift.
  ( vetting_gate_repos "advisory" "false" "false" "${repo}" </dev/null >/dev/null 2>&1 ) \
    && pass "advisory proceeds on drift" || fail "advisory should proceed on drift"

  # A cap that tolerates the drift auto-proceeds, no flag or TTY needed.
  printf 'vetting_trust_root: %s\nvetting_trust_format: ssh\nvetting_max_commits_behind: 5\n' \
    "${TRUST_ROOT}" > "${USER_SANDBOX_CONFIG}"
  ( vetting_gate_repos "required" "false" "false" "${repo}" </dev/null >/dev/null 2>&1 ) \
    && pass "within-cap drift auto-proceeds" || fail "within-cap drift should proceed"

  # An exceeded cap refuses — and the drift flag does NOT bypass the cap.
  printf 'vetting_trust_root: %s\nvetting_trust_format: ssh\nvetting_max_commits_behind: 1\n' \
    "${TRUST_ROOT}" > "${USER_SANDBOX_CONFIG}"
  if ( vetting_gate_repos "required" "false" "true" "${repo}" </dev/null >/dev/null 2>&1 ); then
    fail "over-cap drift should refuse even with --i-accept-vetting-drift"
  fi
  pass "over-cap drift refuses despite the drift flag"

  # Only the full override clears over-cap drift.
  ( vetting_gate_repos "required" "true" "false" "${repo}" </dev/null >/dev/null 2>&1 ) \
    && pass "override clears over-cap drift" || fail "override should clear over-cap drift"

  # cap 0 restores strict "must be at HEAD": even one commit behind refuses.
  printf 'vetting_trust_root: %s\nvetting_trust_format: ssh\nvetting_max_commits_behind: 0\n' \
    "${TRUST_ROOT}" > "${USER_SANDBOX_CONFIG}"
  if ( vetting_gate_repos "required" "false" "false" "${repo}" </dev/null >/dev/null 2>&1 ); then
    fail "cap 0 should refuse any drift"
  fi
  pass "cap 0 refuses any drift (strict at-HEAD)"

  write_trust_config
}

###############################################################################
# vetting_exceptions_require_head — user + overlay layering, tightening-only
# (strict wins if set anywhere; default is the permissive "false").
###############################################################################
test_exceptions_require_head_config() {
  info "Testing vetting_exceptions_require_head layering..."
  : > "${USER_SANDBOX_CONFIG}"
  unset SANDBOX_OVERLAY
  eq "unset -> permissive (false)" "false" "$(vetting_exceptions_require_head)"

  printf 'vetting_exceptions_require_head: false\n' > "${USER_SANDBOX_CONFIG}"
  eq "explicit false stays false" "false" "$(vetting_exceptions_require_head)"

  printf 'vetting_exceptions_require_head: true\n' > "${USER_SANDBOX_CONFIG}"
  eq "user opts into strict" "true" "$(vetting_exceptions_require_head)"

  local overlay="${TEST_DIR}/reqhead-overlay"
  mkdir -p "${overlay}"
  export SANDBOX_OVERLAY="${overlay}"

  # Tightening-only: strict wins if set anywhere, never relaxed by the other.
  printf 'vetting_exceptions_require_head: false\n' > "${overlay}/config.yaml"
  printf 'vetting_exceptions_require_head: true\n'  > "${USER_SANDBOX_CONFIG}"
  eq "overlay false cannot relax user true" "true" "$(vetting_exceptions_require_head)"

  printf 'vetting_exceptions_require_head: true\n'  > "${overlay}/config.yaml"
  printf 'vetting_exceptions_require_head: false\n' > "${USER_SANDBOX_CONFIG}"
  eq "overlay ratchets false->true" "true" "$(vetting_exceptions_require_head)"

  : > "${USER_SANDBOX_CONFIG}"
  printf 'vetting_exceptions_require_head: true\n' > "${overlay}/config.yaml"
  eq "overlay-only strict applies" "true" "$(vetting_exceptions_require_head)"

  # Anything but a literal `true` is not strict — leave the permissive default.
  printf 'vetting_exceptions_require_head: yes\n' > "${USER_SANDBOX_CONFIG}"
  rm -f "${overlay}/config.yaml"
  unset SANDBOX_OVERLAY
  eq "non-true value -> permissive" "false" "$(vetting_exceptions_require_head)"

  : > "${USER_SANDBOX_CONFIG}"
}

###############################################################################
# vetted_accepted_fingerprints under drift — the default honors HEAD's list, the
# strict knob honors it only at HEAD (needs SSH signing).
###############################################################################
test_exceptions_require_head_gate() {
  info "Testing exception honoring under drift (default vs require-head)..."
  write_trust_config
  unset SANDBOX_OVERLAY

  local repo="${TEST_DIR}/exc-drift"
  make_repo "${repo}"
  config_add_accepted_secret "${repo}/.sandbox/config.yaml" \
    "deploy/values.yaml:generic-api-key:155:aaaa1111" "reviewed FP"
  git -C "${repo}" add -A; git -C "${repo}" commit -q -m "base with one exception"
  attest_repo "${repo}" "${TEST_DIR}/id" || { warn "signing failed; skipping"; return 0; }

  # At HEAD (behind 0) the signature covers the list, so it is honored under BOTH
  # the default and the strict knob.
  case "$(vetted_accepted_fingerprints "${repo}")" in
    *aaaa1111*) pass "at HEAD, default honors the signed exception" ;;
    *) fail "at HEAD, default should honor the signed exception" ;;
  esac
  printf 'vetting_trust_root: %s\nvetting_trust_format: ssh\nvetting_exceptions_require_head: true\n' \
    "${TRUST_ROOT}" > "${USER_SANDBOX_CONFIG}"
  case "$(vetted_accepted_fingerprints "${repo}")" in
    *aaaa1111*) pass "at HEAD, strict still honors it (behind 0)" ;;
    *) fail "at HEAD, strict should honor the signed exception (behind 0)" ;;
  esac

  # A drift commit records a brand-new exception no signer ever acknowledged.
  config_add_accepted_secret "${repo}/.sandbox/config.yaml" \
    "deploy/secret.yaml:generic-api-key:9:bbbb2222" "smuggled"
  git -C "${repo}" add -A; git -C "${repo}" commit -q -m "drift adds an exception"
  eq "drift repo reports behind 1" "1" "$(vetting_status_repo "${repo}" | cut -f5)"

  # Strict (config still set): behind != 0 -> honor NOTHING, so neither the
  # smuggled entry nor the originally-signed one clears. Re-attest to restore.
  eq "strict + drift honors nothing" "" "$(vetted_accepted_fingerprints "${repo}")"

  # Default (permissive): HEAD's whole list is honored, smuggled entry included —
  # the accepted risk the team chose.
  write_trust_config
  case "$(vetted_accepted_fingerprints "${repo}")" in
    *bbbb2222*) pass "default + drift honors HEAD's list (accepted risk)" ;;
    *) fail "default should honor HEAD's drift-added exception" ;;
  esac

  write_trust_config
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
  test_max_commits_behind_config
  test_exceptions_require_head_config
  test_status_classification
  test_gate_posture
  test_missing_trust_root_fails_closed
  test_ssh_signingkey_mismatch
  test_vetting_signing_key_knob
  test_status_hermetic_against_fsmonitor
  test_status_hermetic_against_filter
  test_status_hermetic_against_equals_named_filter
  test_status_hermetic_against_included_filter
  test_status_hermetic_against_empty_named_filter
  test_verify_hermetic_against_x509_program
  test_attest_hermetic_against_defaultkeycommand
  test_attest_acknowledges_exceptions
  if [[ "${SSH_SIGNING}" -eq 1 ]]; then
    test_status_vetted
    test_gate_required_passes_when_vetted
    test_gate_drift
    test_exceptions_require_head_gate
    test_verify_hermetic_against_program_hijack
    test_trust_roots_overlay_and_union
    test_gate_inline_attest
  else
    echo "SKIP: signature cases (test_status_vetted, test_gate_required_passes_when_vetted, test_verify_hermetic_against_program_hijack) — SSH signing unavailable"
  fi

  echo ""
  echo "All vetting tests passed."
}

main "$@"
