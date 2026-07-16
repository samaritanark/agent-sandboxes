#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/vetting.sh — Repo vetting gate (Tier 2/3)
#
# A launch-time gate that decides whether a workspace has been vetted for use
# with an AI agent. It answers a different question than the secret gate: not
# "does this repo leak a secret?" but "has a trusted human reviewed *this exact
# tree* and attested that it is cleared for agent use?" — the compliance /
# prompt-injection axis, orthogonal to (and additive to) sandbox isolation.
# A vetted repo is NOT thereby trusted to run outside a sandbox; see PRINCIPLES.
#
# TRUST MODEL. The repo carries only the *artifact* — a signed git tag at HEAD,
# named `<prefix><sha>` (default prefix `agent-vetted/`). The *requirement* and
# the *trust root* live operator-side, so nothing a workspace author can write
# weakens the decision:
#
#   - Trust roots: SSH allowed_signers files (default) or a GnuPG home listing
#     the public keys of authorized reviewers. Two may exist side by side — the
#     operator's own (~/.sandbox/vetting/allowed_signers, or vetting_trust_root:
#     in the user config) and one a linked team overlay ships (its config.yaml
#     vetting_trust_root:, resolved relative to the overlay root). A signature
#     verifying against EITHER counts: the overlay distributes the org's
#     reviewer list via `sandbox link`, and a local file can add to it. Both are
#     operator-side inputs — the overlay is operator-linked, pinned to a commit,
#     and only moved by a deliberate `link sync` — so nothing a WORKSPACE author
#     can write influences whose signature counts. Verification runs host-side,
#     pre-pod, against these roots explicitly — never the ambient keyring.
#   - Freshness is strict: the tag must point at HEAD (annotated tags peel to the
#     commit, so `git tag --points-at HEAD` enforces this by construction). A
#     dirty working tree is refused — an attestation covers a commit, and
#     uncommitted edits would ride along unreviewed.
#
# POSTURE. Operator-controlled, three values:
#   off       — no gate, no banner.
#   advisory  — never refuses; prints the vetting status and proceeds (default).
#   required  — fail closed: refuse launch unless every --repo carries a current,
#               verified attestation. `--i-accept-unvetted-repo` downgrades the
#               refusal to a printed warning (audited).
#
# Posture is resolved from the user's ~/.sandbox/config.yaml (`vetting:` key),
# falling back to the `advisory` org default; a team overlay's `config.yaml` can
# only ratchet the posture UP (additive on the safety side — an overlay can make
# vetting required, never relax it). Trust root / format are read user-first,
# then overlay, then the built-in default.
set -euo pipefail

# Operator-overridable knobs (config keys shadow these; env is an escape hatch).
SANDBOX_VETTING_TAG_PREFIX="${SANDBOX_VETTING_TAG_PREFIX:-agent-vetted/}"
SANDBOX_VETTING_TRUST_ROOT_DEFAULT="${SANDBOX_VETTING_TRUST_ROOT_DEFAULT:-${HOME}/.sandbox/vetting/allowed_signers}"

# _vetting_rank <posture> — total order for the strictest-wins comparison.
_vetting_rank() {
  case "$1" in
    off)      echo 0 ;;
    advisory) echo 1 ;;
    required) echo 2 ;;
    *)        echo 1 ;;  # unknown normalizes to advisory (never below)
  esac
}

# _vetting_normalize <value> — map a raw config value to a known posture,
# warning (once, to stderr) on an unrecognized non-empty value so a typo like
# "requird" fails safe (advisory) but stays visible instead of silently off.
_vetting_normalize() {
  case "$1" in
    off|advisory|required) echo "$1" ;;
    "") echo "" ;;
    *)  echo "WARN: unrecognized vetting posture '$1' — treating as 'advisory'." >&2
        echo "advisory" ;;
  esac
}

# _vetting_config_get <key> — read a scalar from the user config, else the
# overlay config. Empty if neither sets it.
_vetting_config_get() {
  local key="$1" v=""
  [[ -f "${USER_SANDBOX_CONFIG}" ]] && v="$(extract_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" "${key}")"
  if [[ -z "${v}" ]]; then
    local overlay
    overlay="$(resolve_overlay_path 2>/dev/null || true)"
    [[ -n "${overlay}" && -f "${overlay}/config.yaml" ]] && \
      v="$(extract_yaml_scalar_from_file "${overlay}/config.yaml" "${key}")"
  fi
  echo "${v}"
}

# resolve_vetting_posture — effective posture. User choice (else the advisory
# org default) is the baseline; a team overlay can only ratchet it UP.
resolve_vetting_posture() {
  local eff user_p="" overlay_p="" overlay
  [[ -f "${USER_SANDBOX_CONFIG}" ]] && user_p="$(extract_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" vetting)"
  user_p="$(_vetting_normalize "${user_p}")"
  eff="${user_p:-advisory}"

  overlay="$(resolve_overlay_path 2>/dev/null || true)"
  if [[ -n "${overlay}" && -f "${overlay}/config.yaml" ]]; then
    overlay_p="$(_vetting_normalize "$(extract_yaml_scalar_from_file "${overlay}/config.yaml" vetting)")"
    if [[ -n "${overlay_p}" && "$(_vetting_rank "${overlay_p}")" -gt "$(_vetting_rank "${eff}")" ]]; then
      eff="${overlay_p}"
    fi
  fi
  echo "${eff}"
}

# vetting_trust_root — path to the operator's OWN signer trust root (user
# config else the built-in default; tilde-expanded). This is where enrollment
# guidance points; verification consults vetting_trust_roots (plural), which
# also includes an overlay-shipped root.
vetting_trust_root() {
  local v=""
  [[ -f "${USER_SANDBOX_CONFIG}" ]] && v="$(extract_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" vetting_trust_root)"
  if [[ -n "${v}" ]]; then echo "${v/#\~/${HOME}}"; else echo "${SANDBOX_VETTING_TRUST_ROOT_DEFAULT}"; fi
}

# vetting_trust_roots — every EXISTING trust root, one per line, operator-local
# first, then the overlay-shipped one. A signature verifying against any listed
# root counts (union): the overlay distributes the team's reviewer list, and the
# operator's local file can hold additional signers. An overlay value that is a
# relative path resolves against the overlay root, so an overlay can ship its
# allowed_signers as a plain file in its own tree. Paths that do not exist are
# omitted; empty output means no trust root is available at all.
vetting_trust_roots() {
  local user_root overlay overlay_v
  user_root="$(vetting_trust_root)"
  [[ -e "${user_root}" ]] && printf '%s\n' "${user_root}"

  overlay="$(resolve_overlay_path 2>/dev/null || true)"
  if [[ -n "${overlay}" && -f "${overlay}/config.yaml" ]]; then
    overlay_v="$(extract_yaml_scalar_from_file "${overlay}/config.yaml" vetting_trust_root)"
    if [[ -n "${overlay_v}" ]]; then
      overlay_v="${overlay_v/#\~/${HOME}}"
      [[ "${overlay_v}" != /* ]] && overlay_v="${overlay}/${overlay_v}"
      [[ -e "${overlay_v}" && "${overlay_v}" != "${user_root}" ]] && printf '%s\n' "${overlay_v}"
    fi
  fi
}

# vetting_trust_format — "ssh" (default) or "gpg".
vetting_trust_format() {
  local v
  v="$(_vetting_config_get vetting_trust_format)"
  case "${v}" in gpg|ssh) echo "${v}" ;; *) echo "ssh" ;; esac
}

# _vetting_extract_signer <verify-output> <format> — pull the signer principal
# out of `git tag -v` output. Best-effort; empty if it can't be parsed.
_vetting_extract_signer() {
  local out="$1" fmt="$2"
  if [[ "${fmt}" == "gpg" ]]; then
    printf '%s\n' "${out}" | sed -n 's/.*Good signature from "\([^"]*\)".*/\1/p' | head -n1
  else
    printf '%s\n' "${out}" | sed -n 's/.*Good "[^"]*" signature for \([^ ]*\).*/\1/p' | head -n1
  fi
}

# _vetting_git <repo> <git-args>... — run git inside an UNTRUSTED workspace with
# repo-local config that could execute an attacker-named program neutralized.
# A workspace author controls the repo's .git/config (and any file it includes)
# and the in-tree .gitattributes, and several innocuous-looking git operations
# will exec a program those name:
#   - core.fsmonitor (spawned on an index refresh) and hooks;
#   - content filter drivers: `git status` re-hashes worktree files through the
#     `filter.<name>.clean` (or `.process`) command to detect modifications. The
#     driver command lives in git config and the path->filter mapping in the
#     in-tree .gitattributes. The attribute can't be overridden from config, so
#     we neutralize the *driver*: enumerate the repo's own filter.* names and
#     pin each driver to a harmless identity (cat) with required=false. An
#     in-tree `filter=<name>` whose driver is thus neutralized is a no-op.
#
# Two subtleties make this security-critical rather than cosmetic:
#   1. The filter name is attacker-chosen and may contain '=', which `git -c
#      name=value` mis-splits (first '=' wins), leaving the real driver
#      un-overridden. So the pins go through GIT_CONFIG_KEY_n/VALUE_n, which take
#      the key verbatim (no '=' split). fsmonitor/hooks have fixed, '='-free
#      names, so a plain `-c` is safe for them.
#   2. A filter defined via `[include]` is invisible to `config --local` but is
#      honored when the filter is applied, so we enumerate WITHOUT --local (so
#      includes are followed) while nulling the global/system scopes, so we see
#      exactly the repo-declared filters and don't disturb the operator's own.
# The GIT_CONFIG_* entries outrank every config file, so the pins hold whatever
# the workspace commits or includes. (Side effect: a repo that legitimately
# relies on a clean filter, e.g. git-LFS, reads as dirty here — conservative for
# the gate, which fails toward "unvetted".) Signature-program and trust-file
# pins are layered on top by _vetting_verify_tag.
_vetting_git() {
  local repo="$1"; shift
  local -a cfgenv=()
  local name n=0 sub
  while IFS= read -r name; do
    # Do NOT skip an empty name: git supports `[filter ""]` (keys filter..clean
    # etc.), and an in-tree `.gitattributes` `* filter=` binds every path to that
    # empty-subsection driver — a real, attacker-usable filter that must be
    # pinned like any other. (When the repo declares no filters the enumeration
    # yields zero lines, so this loop simply doesn't run.)
    for sub in clean smudge process required; do
      cfgenv+=("GIT_CONFIG_KEY_${n}=filter.${name}.${sub}")
      case "${sub}" in
        clean|smudge) cfgenv+=("GIT_CONFIG_VALUE_${n}=cat") ;;
        process)      cfgenv+=("GIT_CONFIG_VALUE_${n}=") ;;
        required)     cfgenv+=("GIT_CONFIG_VALUE_${n}=false") ;;
      esac
      n=$((n + 1))
    done
  done < <(GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
             git -C "${repo}" config --name-only --get-regexp '^filter\.' 2>/dev/null \
             | sed -E 's/^filter\.(.*)\.[^.]+$/\1/' | sort -u || true)
  cfgenv+=("GIT_CONFIG_COUNT=${n}")

  env "${cfgenv[@]}" git -C "${repo}" \
    -c core.fsmonitor= -c core.hooksPath=/dev/null "$@"
}

# _vetting_verify_tag <repo> <tag> <trust_root> <format> — verify one tag's
# signature against the OPERATOR's trust root, hermetically with respect to the
# untrusted repo's own git config. On success prints the signer principal and
# returns 0; otherwise returns non-zero.
#
# `git tag -v` runs inside the repo, so without pinning a workspace author could
# (a) point gpg.ssh.program / gpg.program at a script in the tree — arbitrary
# code execution on the host, as the operator, before the pod exists — and/or
# (b) swap gpg.ssh.allowedSignersFile / the keyring to forge a "Good signature".
# git also AUTO-DETECTS the signature format on the verify path (gpg.format only
# governs signing), so BOTH backends must be locked, not just the configured
# one. We therefore, via command-line `-c` (which beats repo .git/config):
#   - pin ALL THREE verifier programs (ssh, openpgp, x509) to trusted absolute
#     binaries, or to `false` when absent/unsupported, so repo config can never
#     choose the program — git also auto-detects X.509 (armor
#     "-----BEGIN SIGNED MESSAGE-----") and would otherwise run a repo-chosen
#     gpg.x509.program;
#   - pin the selected format's trust source to the operator's trust root and
#     neutralize the other format's (empty GNUPGHOME in ssh mode so a planted
#     OpenPGP tag has no key; empty allowedSignersFile in gpg mode so a planted
#     SSH tag has no signer), so a cross-format planted tag cannot verify.
# Runs in a subshell so the throwaway GNUPGHOME is always cleaned up.
_vetting_verify_tag() (
  local repo="$1" tag="$2" trust_root="$3" fmt="$4"

  local false_bin ssh_keygen gpg_bin
  false_bin="$(command -v false 2>/dev/null || echo /bin/false)"
  ssh_keygen="$(command -v ssh-keygen 2>/dev/null || echo "${false_bin}")"
  gpg_bin="$(command -v gpg 2>/dev/null || command -v gpg2 2>/dev/null || echo "${false_bin}")"

  # A private empty GnuPG home: in ssh mode it denies any OpenPGP-signed tag a
  # trusted key; created even in gpg mode but overridden below.
  local empty_gnupg
  empty_gnupg="$(mktemp -d "${TMPDIR:-/tmp}/sandbox-vet-gnupg-XXXXXX")" || return 2
  chmod 700 "${empty_gnupg}" 2>/dev/null || true
  trap 'rm -rf "${empty_gnupg}"' EXIT

  # X.509 is not a supported attestation format here, so pin its program to
  # `false` — that both denies verification and stops repo config from choosing
  # a program when git auto-detects an X.509-armored tag.
  local -a hard=(
    -c core.fsmonitor= -c core.hooksPath=/dev/null
    -c "gpg.ssh.program=${ssh_keygen}" -c "gpg.program=${gpg_bin}"
    -c "gpg.x509.program=${false_bin}"
  )

  local vout rc
  if [[ "${fmt}" == "gpg" ]]; then
    vout="$(GNUPGHOME="${trust_root}" git -C "${repo}" "${hard[@]}" \
              -c gpg.format=openpgp \
              -c gpg.ssh.allowedSignersFile=/dev/null \
              tag -v "${tag}" 2>&1)" && rc=0 || rc=$?
  else
    vout="$(GNUPGHOME="${empty_gnupg}" git -C "${repo}" "${hard[@]}" \
              -c gpg.format=ssh \
              -c gpg.ssh.allowedSignersFile="${trust_root}" \
              tag -v "${tag}" 2>&1)" && rc=0 || rc=$?
  fi

  [[ "${rc}" -eq 0 ]] && _vetting_extract_signer "${vout}" "${fmt}"
  return "${rc}"
)

# vetting_status_repo <repo> — classify a workspace's vetting state and print a
# single TSV line the gate consumes:
#   vetted<TAB>sha<TAB>tag<TAB>signer
#   unvetted<TAB>sha<TAB>reason
#   dirty<TAB>sha
#   not-git<TAB>reason
#   error<TAB>reason
# Never exits; the caller (vetting_gate_repos) decides what a status means for
# the launch. Verification uses the operator trust root explicitly.
vetting_status_repo() {
  local repo="$1"
  local real_repo
  real_repo="$(cd "${repo}" 2>/dev/null && pwd -P)" || {
    printf 'error\tcannot access %s\n' "${repo}"; return 0; }

  if ! _vetting_git "${real_repo}" rev-parse --git-dir >/dev/null 2>&1; then
    printf 'not-git\t%s is not a git repository\n' "${repo}"; return 0
  fi

  local head_sha
  head_sha="$(_vetting_git "${real_repo}" rev-parse HEAD 2>/dev/null)" || {
    printf 'error\t%s has no HEAD commit (empty repository?)\n' "${repo}"; return 0; }

  if [[ -n "$(_vetting_git "${real_repo}" status --porcelain 2>/dev/null)" ]]; then
    printf 'dirty\t%s\n' "${head_sha}"; return 0
  fi

  local trust_format
  trust_format="$(vetting_trust_format)"
  local -a trust_roots=()
  read_into_array trust_roots < <(vetting_trust_roots)
  if [[ "${#trust_roots[@]}" -eq 0 ]]; then
    printf 'error\tno trust root found (%s; none shipped by the overlay)\n' \
      "$(vetting_trust_root)"; return 0
  fi

  local -a tags=()
  read_into_array tags < <(_vetting_git "${real_repo}" tag --points-at HEAD \
                             --list "${SANDBOX_VETTING_TAG_PREFIX}*" 2>/dev/null || true)
  if [[ "${#tags[@]}" -eq 0 ]]; then
    printf 'unvetted\t%s\tno %s* tag at HEAD\n' "${head_sha}" "${SANDBOX_VETTING_TAG_PREFIX}"
    return 0
  fi

  local tag signer root
  for tag in "${tags[@]}"; do
    [[ -z "${tag}" ]] && continue
    for root in "${trust_roots[@]}"; do
      [[ -z "${root}" ]] && continue
      if signer="$(_vetting_verify_tag "${real_repo}" "${tag}" "${root}" "${trust_format}")"; then
        printf 'vetted\t%s\t%s\t%s\n' "${head_sha}" "${tag}" "${signer:-unknown}"
        return 0
      fi
    done
  done

  printf 'unvetted\t%s\t%s tag(s) at HEAD but none verified against the trust root\n' \
    "${head_sha}" "${#tags[@]}"
}

# _vetting_print_findings <entry>... — render "repo<TAB>status<TAB>f2<TAB>f3"
# entries to stderr as a human-readable list.
_vetting_print_findings() {
  local entry repo status f2 f3
  for entry in "$@"; do
    IFS=$'\t' read -r repo status f2 f3 <<<"${entry}"
    case "${status}" in
      unvetted) echo "    ${repo}: no verified attestation (HEAD ${f2:0:12}; ${f3})" >&2 ;;
      dirty)    echo "    ${repo}: uncommitted changes — commit or stash, then attest (HEAD ${f2:0:12})" >&2 ;;
      not-git)  echo "    ${repo}: not a git repository — cannot carry an attestation" >&2 ;;
      error)    echo "    ${repo}: ${f2}" >&2 ;;
      *)        echo "    ${repo}: ${status} ${f2}" >&2 ;;
    esac
  done
}

# vetting_gate_repos <posture> <accept_flag> <repo>... — the launch gate. In
# `advisory` it prints status and proceeds; in `required` it refuses unless
# every repo is vetted, with --i-accept-unvetted-repo (accept_flag == "true")
# downgrading the refusal to a warning. A missing trust root under `required`
# is an operator misconfiguration and fails closed regardless of the override.
vetting_gate_repos() {
  local posture="$1"; shift
  local accept="$1"; shift
  local -a repos=("$@")
  [[ "${#repos[@]}" -gt 0 ]] || return 0
  # SESSION_VETTING_SUMMARY is read by the audit hook once session.json exists;
  # the gate runs before that, so it records its outcome here for later logging.
  SESSION_VETTING_SUMMARY="posture=${posture}"
  [[ "${posture}" == "off" ]] && return 0

  local -a trust_roots=()
  read_into_array trust_roots < <(vetting_trust_roots)
  if [[ "${#trust_roots[@]}" -eq 0 ]]; then
    if [[ "${posture}" == "required" ]]; then
      echo "" >&2
      echo "ERROR: vetting is required but no signer trust root exists. Provide one:" >&2
      echo "         - link a team overlay that ships its reviewer list" >&2
      echo "           (config.yaml vetting_trust_root:), or" >&2
      echo "         - create $(vetting_trust_root)" >&2
      echo "           (an SSH allowed_signers file, or a GnuPG home if" >&2
      echo "           vetting_trust_format: gpg) with the reviewers' public keys." >&2
      echo "       See docs/how-to/vetting.md. This is a config error, so the" >&2
      echo "       --i-accept-unvetted-repo override does not apply." >&2
      echo "" >&2
      exit 1
    fi
    echo "  Vetting (advisory): no trust root ($(vetting_trust_root), none from the overlay) — cannot verify, skipping."
    SESSION_VETTING_SUMMARY="posture=${posture}; no trust root — not verified"
    return 0
  fi

  echo "  Checking workspace vetting attestation(s) [posture: ${posture}]..."

  local -a unvetted=()
  local repo line status f2 f3 f4
  for repo in "${repos[@]}"; do
    line="$(vetting_status_repo "${repo}")"
    IFS=$'\t' read -r status f2 f3 f4 <<<"${line}"
    if [[ "${status}" == "vetted" ]]; then
      echo "  ✓ ${repo}: vetted at ${f2:0:12} (tag ${f3}, signer ${f4:-unknown})"
    else
      unvetted+=("${repo}"$'\t'"${status}"$'\t'"${f2}"$'\t'"${f3}")
    fi
  done

  if [[ "${#unvetted[@]}" -eq 0 ]]; then
    echo "  All workspace(s) carry a current, verified attestation."
    SESSION_VETTING_SUMMARY="posture=${posture}; all ${#repos[@]} workspace(s) vetted"
    return 0
  fi

  # Compact "repo(status)" detail for the audit log (index-iterate: repo paths
  # may contain spaces, so no word-splitting).
  local i detail="" dr ds
  for (( i=0; i<${#unvetted[@]}; i++ )); do
    IFS=$'\t' read -r dr ds _ _ <<<"${unvetted[$i]}"
    detail="${detail:+${detail}, }${dr}(${ds})"
  done

  if [[ "${posture}" == "advisory" ]]; then
    echo "" >&2
    echo "  NOTICE: ${#unvetted[@]} workspace(s) are not vetted for agent use." >&2
    echo "  Proceeding because posture is advisory (set 'vetting: required' to enforce):" >&2
    _vetting_print_findings "${unvetted[@]}"
    echo "" >&2
    SESSION_VETTING_SUMMARY="posture=advisory; ${#unvetted[@]} unvetted, proceeded: ${detail}"
    return 0
  fi

  # posture == required: before refusing, offer an authorized signer the chance
  # to attest right here. This is the full `sandbox vet` sign-off — the same
  # signed tag, the same secret-exceptions acknowledgment — just without the
  # refuse/vet/re-run round-trip, so the low-friction path and the accountable
  # path are the same path. Only for interactive launches; CI keeps today's
  # refusal. Only offered for repos that are cleanly unvetted (no tag at HEAD):
  # a dirty tree still must be committed first, and an existing-but-unverified
  # tag means someone else's attestation we must not touch.
  if [[ "${accept}" != "true" && -t 0 && -t 1 ]]; then
    local -a remaining=()
    local attested=0 ir is if2 if3
    for (( i=0; i<${#unvetted[@]}; i++ )); do
      IFS=$'\t' read -r ir is if2 if3 <<<"${unvetted[$i]}"
      if [[ "${is}" == "unvetted" && "${if3}" == no\ * ]] \
         && _vetting_signing_configured "${ir}" \
         && _vetting_inline_attest "${ir}" "${if2}"; then
        attested=$((attested + 1))
      else
        remaining+=("${unvetted[$i]}")
      fi
    done
    if [[ "${#remaining[@]}" -eq 0 ]]; then
      echo "  All workspace(s) now carry a current, verified attestation."
      SESSION_VETTING_SUMMARY="posture=required; ${attested} workspace(s) attested at launch; all vetted"
      return 0
    fi
    unvetted=("${remaining[@]}")
    detail=""
    for (( i=0; i<${#unvetted[@]}; i++ )); do
      IFS=$'\t' read -r dr ds _ _ <<<"${unvetted[$i]}"
      detail="${detail:+${detail}, }${dr}(${ds})"
    done
    [[ "${attested}" -gt 0 ]] && detail="${detail} (${attested} other(s) attested at launch)"
  fi

  if [[ "${accept}" == "true" ]]; then
    echo "" >&2
    echo "  NOTICE: proceeding despite ${#unvetted[@]} unvetted workspace(s) because" >&2
    echo "  --i-accept-unvetted-repo was given:" >&2
    _vetting_print_findings "${unvetted[@]}"
    echo "" >&2
    SESSION_VETTING_SUMMARY="posture=required; OVERRIDE accepted ${#unvetted[@]} unvetted: ${detail}"
    return 0
  fi

  echo "" >&2
  echo "ERROR: vetting is required, but the following workspace(s) have no current," >&2
  echo "       verified agent-vetting attestation, so the launch is refused:" >&2
  echo "" >&2
  _vetting_print_findings "${unvetted[@]}"
  echo "" >&2
  echo "  A trusted reviewer must attest the current HEAD:" >&2
  echo "        sandbox vet --repo <PATH>" >&2
  echo "  Override (audited), accepting the risk for this launch:" >&2
  echo "        re-run with --i-accept-unvetted-repo" >&2
  echo "" >&2
  exit 1
}

# _vetting_acknowledge_exceptions <real_repo> <repo> <assume_yes> — the honesty
# gate for `sandbox vet`. A repo's committed accepted_secrets: list (see `sandbox
# exceptions`) only takes effect once THIS attestation signs the tree, so before
# signing we surface which findings that list will expose to the agent and make
# the signer acknowledge them — otherwise a rubber-stamp signature could launder
# a real secret a contributor recorded as an "exception". Uses the same match
# logic the gate will (value-hash + tracked file), so the preview is exactly what
# gets honored. Returns 0 to proceed (nothing recorded, the list is inert, or the
# signer acknowledged), 1 to abort (declined, or cannot preview / cannot prompt).
# vetting_committed_accepted_secrets <repo> — the accepted_secrets: fingerprints
# recorded in the repo's HEAD *commit*, one per line. This deliberately reads the
# COMMITTED blob (`HEAD:.sandbox/config.yaml`), never the working-tree file, and
# that is the security boundary: an attestation signs HEAD's tree, so only a list
# that is actually in that commit is covered by the signature. A gitignored or
# otherwise-uncommitted .sandbox/config.yaml is NOT in HEAD — and, being ignored,
# would not even register as a dirty tree — so it must never be honored. Reading
# it from HEAD closes that gap at the source. Hardened via _vetting_git
# (fsmonitor/hooks/filter drivers neutralized); `git show <rev>:<path>` emits the
# stored blob and applies no smudge filters. Empty if the file is absent at HEAD,
# the repo has no commit, or it is not a git repo.
vetting_committed_accepted_secrets() {
  local repo="$1" tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/sandbox-accept-src-XXXXXX")" || return 0
  _vetting_git "${repo}" show "HEAD:${SANDBOX_REPO_CONFIG_NAME}" > "${tmp}" 2>/dev/null || true
  extract_yaml_list_from_file "${tmp}" "accepted_secrets"
  rm -f "${tmp}"
}

_vetting_acknowledge_exceptions() {
  local real_repo="$1" repo="$2" assume_yes="$3"

  # Read the list from the commit about to be signed (HEAD), not the working
  # tree — the signer must acknowledge exactly what the signature will cover and
  # the gate will later honor. See vetting_committed_accepted_secrets.
  local -a entries=()
  read_into_array entries < <(vetting_committed_accepted_secrets "${repo}")
  [[ "${#entries[@]}" -gt 0 ]] || return 0

  if ! command -v betterleaks >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: ${repo} has an accepted_secrets: list, but betterleaks/jq are not" >&2
    echo "       available to show what signing it would let the agent read. Install" >&2
    echo "       them and re-run so the attestation is not a blind sign-off." >&2
    return 1
  fi

  local accept_file; accept_file="$(mktemp "${TMPDIR:-/tmp}/sandbox-vet-accept-XXXXXX")"
  printf '%s\n' "${entries[@]}" > "${accept_file}"
  local -a accepted=()
  local m rel rule ln _rest
  while IFS=$'\t' read -r m rel rule ln _rest; do
    [[ "${m}" == "accepted" ]] || continue
    accepted+=("${rel}:${rule}:${ln}")
  done < <(scan_repo_secrets "${real_repo}" "${accept_file}")
  rm -f "${accept_file}"

  # A list that currently matches nothing (stale entries) exposes nothing.
  [[ "${#accepted[@]}" -gt 0 ]] || return 0

  echo "" >&2
  echo "  This repo records ${#accepted[@]} secret exception(s). Signing this attestation" >&2
  echo "  vouches that they are reviewed false positives — the agent WILL be able to" >&2
  echo "  read these values once the repo is vetted:" >&2
  local a
  for a in "${accepted[@]}"; do echo "      ${a}" >&2; done
  echo "" >&2

  if [[ "${assume_yes}" == "true" ]]; then
    echo "  Acknowledged via --yes." >&2
    return 0
  fi
  if [[ ! -t 0 ]]; then
    echo "ERROR: not an interactive terminal, so these cannot be acknowledged" >&2
    echo "       interactively. Re-run with --yes to sign off on them explicitly." >&2
    return 1
  fi
  local reply=""
  printf '  Acknowledge and sign? [y/N] ' >&2
  read -r reply || true
  [[ "${reply}" =~ ^[Yy] ]] && return 0
  echo "  Aborted; no attestation created." >&2
  return 1
}

# vetting_attest_repo <repo> [message] [assume_yes] — create a signed attestation
# tag at HEAD using the operator's own signing key. Refuses a dirty tree (the tag
# must describe exactly what a reviewer looked at) and, when the repo records
# secret exceptions, requires the signer to acknowledge them first (assume_yes
# skips the interactive prompt — see _vetting_acknowledge_exceptions). Idempotent:
# a pre-existing tag at HEAD is left in place. Backs `sandbox vet --repo`.
vetting_attest_repo() {
  local repo="$1"; local msg="${2:-vetted for agent use}"; local assume_yes="${3:-false}"
  local real_repo
  real_repo="$(cd "${repo}" 2>/dev/null && pwd -P)" || { echo "ERROR: cannot access ${repo}" >&2; return 1; }

  if ! _vetting_git "${real_repo}" rev-parse --git-dir >/dev/null 2>&1; then
    echo "ERROR: ${repo} is not a git repository — nothing to attest." >&2; return 1
  fi
  if [[ -n "$(_vetting_git "${real_repo}" status --porcelain 2>/dev/null)" ]]; then
    echo "ERROR: ${repo} has uncommitted changes. Commit or stash first — an" >&2
    echo "       attestation covers a specific commit, not a dirty tree." >&2
    return 1
  fi

  local head_sha tag fmt
  head_sha="$(_vetting_git "${real_repo}" rev-parse HEAD)"
  tag="${SANDBOX_VETTING_TAG_PREFIX}${head_sha}"
  if _vetting_git "${real_repo}" rev-parse -q --verify "refs/tags/${tag}" >/dev/null 2>&1; then
    echo "  ${repo}: already attested — tag ${tag} exists."
    return 0
  fi

  # Honesty gate: surface any secret exceptions this signature would bless.
  _vetting_acknowledge_exceptions "${real_repo}" "${repo}" "${assume_yes}" || return 1

  # Sign inside a repo whose .git/config is not yet reviewed, so pin every knob
  # that lets config choose a program git will exec: the signer programs
  # (gpg.ssh.program / gpg.program / gpg.x509.program) and, for SSH signing when
  # user.signingkey is unset, gpg.ssh.defaultKeyCommand (git runs it to obtain a
  # key). A repo-local value for any of these would otherwise run an attacker
  # script on the operator's host — see _vetting_verify_tag. The signing key
  # stays the operator's own.
  fmt="$(vetting_trust_format)"
  local false_bin ssh_keygen gpg_bin
  false_bin="$(command -v false 2>/dev/null || echo /bin/false)"
  ssh_keygen="$(command -v ssh-keygen 2>/dev/null || echo "${false_bin}")"
  gpg_bin="$(command -v gpg 2>/dev/null || command -v gpg2 2>/dev/null || echo "${false_bin}")"
  local -a gitopts=(-c "gpg.ssh.program=${ssh_keygen}" -c "gpg.program=${gpg_bin}" \
                    -c "gpg.x509.program=${false_bin}" -c gpg.ssh.defaultKeyCommand=)
  [[ "${fmt}" == "ssh" ]] && gitopts+=(-c gpg.format=ssh)

  if _vetting_git "${real_repo}" "${gitopts[@]}" tag -s "${tag}" -m "${msg}"; then
    echo "  ${repo}: created signed attestation tag ${tag}"
    echo "  Push it so other operators can verify:"
    echo "        git -C ${repo} push origin ${tag}"
  else
    echo "ERROR: failed to create the signed tag. Check that your signing key is" >&2
    echo "       configured (git config user.signingkey; gpg.format matches your" >&2
    echo "       key type) and that its public key is in the trust root." >&2
    if [[ "${fmt}" == "ssh" && "$(_vetting_ssh_signingkey_state "${real_repo}")" == "mismatch" ]]; then
      local badkey
      badkey="$(_vetting_git "${real_repo}" config user.signingkey 2>/dev/null || true)"
      echo "" >&2
      echo "       Likely cause: user.signingkey ('${badkey}') is not an SSH key or" >&2
      echo "       key file — it looks like a GPG key id from OpenPGP commit signing." >&2
      echo "       Attestations are SSH-signed here (ssh trust root). Fix it with:" >&2
      echo "             git config --global gpg.format ssh" >&2
      echo "             git config --global user.signingkey ~/.ssh/id_ed25519.pub" >&2
      echo "       (or set both per-repo to leave global commit signing alone), or" >&2
      echo "       run 'sandbox vet' interactively and let it fix this for you." >&2
    fi
    return 1
  fi
}

# _vetting_ssh_signingkey_state <repo> — classify user.signingkey for SSH
# signing, which treats the value as a literal SSH public key or a path to a
# key file. Prints one of:
#   ok            usable for gpg.format=ssh
#   unconfigured  no user.signingkey at all
#   mismatch      set, but neither a literal SSH key nor an existing file —
#                 typically a GPG key id left over from OpenPGP commit signing
#                 (the exact shape of "Couldn't load public key <id>").
_vetting_ssh_signingkey_state() {
  local repo="$1" real key
  real="$(cd "${repo}" 2>/dev/null && pwd -P)" || { echo unconfigured; return 0; }
  key="$(_vetting_git "${real}" config user.signingkey 2>/dev/null || true)"
  if [[ -z "${key}" ]]; then echo unconfigured; return 0; fi
  case "${key}" in
    ssh-*|sk-ssh-*|ecdsa-sha2-*|key::*) echo ok; return 0 ;;
  esac
  key="${key/#\~/${HOME}}"
  if [[ -f "${key}" ]]; then echo ok; else echo mismatch; fi
}

# _vetting_signing_configured <repo> — cheap heuristic for whether the operator
# has a signing identity git could actually use, gating whether the inline
# attest offer is worth making. In ssh mode the key must be USABLE for ssh
# signing (a GPG key id left in user.signingkey would just fail after the
# operator says yes); in gpg mode git can fall back to the committer identity,
# so the offer stands. Never a security decision — the signature is verified
# against the trust roots after signing regardless.
_vetting_signing_configured() {
  local repo="$1"
  if [[ "$(vetting_trust_format)" == "gpg" ]]; then return 0; fi
  [[ "$(_vetting_ssh_signingkey_state "${repo}")" == "ok" ]]
}

# _vetting_inline_attest <repo> <head_sha> — the launch-time attest offer. Asks,
# signs via vetting_attest_repo (which surfaces any secret exceptions for
# acknowledgment), then RE-VERIFIES against the trust roots: a signature that
# does not verify (signer not enrolled as a reviewer) is removed again and the
# offer fails, so saying "y" can never manufacture authority the trust root does
# not grant. Caller guarantees an interactive TTY and that no attestation tag
# already exists at HEAD (we must never delete a tag we did not just create).
_vetting_inline_attest() {
  local repo="$1" head_sha="$2" reply=""
  echo "" >&2
  echo "  ${repo} is not vetted at HEAD ${head_sha:0:12}." >&2
  echo "  Your git signing key can attest it right now — the same signed sign-off" >&2
  echo "  as 'sandbox vet', honored only if your key is in the trust root. Attest" >&2
  echo "  only if you have reviewed what is at this HEAD." >&2
  printf '  Attest HEAD %s... continue? [y/N] ' "${head_sha:0:12}" >&2
  read -r reply || true
  if [[ ! "${reply}" =~ ^[Yy] ]]; then
    echo "  Not attested." >&2
    return 1
  fi

  vetting_attest_repo "${repo}" "vetted for agent use (attested at launch)" "false" || return 1

  local line status f2 f3 f4
  line="$(vetting_status_repo "${repo}")"
  IFS=$'\t' read -r status f2 f3 f4 <<<"${line}"
  if [[ "${status}" == "vetted" ]]; then
    echo "  ✓ ${repo}: attested and verified (signer ${f4:-unknown})" >&2
    return 0
  fi

  local real_repo
  real_repo="$(cd "${repo}" 2>/dev/null && pwd -P)" || return 1
  _vetting_git "${real_repo}" tag -d "${SANDBOX_VETTING_TAG_PREFIX}${head_sha}" >/dev/null 2>&1 || true
  echo "  ERROR: the attestation you just signed does not verify against the trust" >&2
  echo "         root(s), so it was removed. Your signing key is likely not enrolled" >&2
  echo "         as a reviewer — ask your overlay maintainer to add your public key," >&2
  echo "         or add it to $(vetting_trust_root)." >&2
  return 1
}

# vetting_signing_setup_assist <repo> — one-time signing setup for `sandbox
# vet`. When no signing identity is configured (ssh trust format, interactive
# terminal), offer to wire the operator's existing SSH public key into git's
# global config, then print the allowed_signers line a trust-root maintainer
# needs to enroll them. Returns 0 when signing is (now) configured or when the
# situation was left for vetting_attest_repo's own error path (non-TTY, gpg
# format); returns 1 when the operator declined or no key exists.
vetting_signing_setup_assist() {
  local repo="$1" real state key=""
  real="$(cd "${repo}" 2>/dev/null && pwd -P)" || return 0
  [[ "$(vetting_trust_format)" == "gpg" ]] && return 0
  state="$(_vetting_ssh_signingkey_state "${repo}")"
  [[ "${state}" == "ok" ]] && return 0
  [[ -t 0 && -t 1 ]] || return 0

  local -a candidates=()
  local k
  for k in "${HOME}/.ssh/id_ed25519.pub" "${HOME}/.ssh/id_ecdsa.pub" "${HOME}/.ssh/id_rsa.pub"; do
    [[ -f "${k}" ]] && candidates+=("${k}")
  done
  if [[ "${#candidates[@]}" -eq 0 ]]; then
    echo "  git signing is not usable for SSH attestations, and no SSH public key was" >&2
    echo "  found under ~/.ssh. Create one (ssh-keygen -t ed25519), then re-run" >&2
    echo "  'sandbox vet'." >&2
    return 1
  fi

  local pick="${candidates[0]}" reply=""
  echo "" >&2
  if [[ "${state}" == "mismatch" ]]; then
    key="$(_vetting_git "${real}" config user.signingkey 2>/dev/null || true)"
    echo "  Your git user.signingkey ('${key}') is not an SSH key or key file — it" >&2
    echo "  looks like a GPG key id from OpenPGP commit signing. Attestations here are" >&2
    echo "  SSH-signed (the trust root is an allowed_signers file), and SSH signing" >&2
    echo "  reads user.signingkey as a key file path, so signing would fail with" >&2
    echo "  \"Couldn't load public key ${key}\"." >&2
    echo "" >&2
    echo "  NOTE: switching is global git config — if you still GPG-sign commits with" >&2
    echo "  that key, answer no and set the two keys per-repo instead (shown below)." >&2
  else
    echo "  git signing is not configured. Attestations are signed with your own SSH" >&2
    echo "  key — nothing is shared or fetched; verification uses public keys only." >&2
  fi
  printf '  Configure git (globally) to sign with %s? [y/N] ' "${pick}" >&2
  read -r reply || true
  if [[ ! "${reply}" =~ ^[Yy] ]]; then
    echo "  Skipped. Configure it manually to attest — globally:" >&2
    echo "        git config --global gpg.format ssh" >&2
    echo "        git config --global user.signingkey <path-to-your-key.pub>" >&2
    echo "  or scoped to one repo (leaves your global commit signing alone):" >&2
    echo "        git -C <repo> config gpg.format ssh" >&2
    echo "        git -C <repo> config user.signingkey <path-to-your-key.pub>" >&2
    return 1
  fi
  git config --global gpg.format ssh
  git config --global user.signingkey "${pick}"
  echo "  Configured: gpg.format=ssh, user.signingkey=${pick}" >&2

  local email keyline
  email="$(_vetting_git "${real}" config user.email 2>/dev/null || true)"
  keyline="$(awk '{print $1" "$2; exit}' "${pick}" 2>/dev/null || true)"
  if [[ -n "${email}" && -n "${keyline}" ]]; then
    echo "" >&2
    echo "  To be enrolled as a reviewer, your public key must be in the trust root." >&2
    echo "  Your allowed_signers line (send it to your overlay maintainer, or append" >&2
    echo "  it to $(vetting_trust_root)):" >&2
    echo "" >&2
    echo "      ${email} ${keyline}" >&2
    echo "" >&2
  fi
  return 0
}
