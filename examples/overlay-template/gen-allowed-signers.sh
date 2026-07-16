#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# examples/overlay-template/gen-allowed-signers.sh — regenerate the overlay's
# allowed_signers file (the team's vetting trust root) from a git forge's
# public-key endpoints.
#
# Gitea, GitHub, and GitLab all expose each user's public SSH keys at
#     <FORGE_URL>/<username>.keys
# so enrollment reduces to keeping signers.txt current — one reviewer per line:
#     <principal-email> <forge-username>
# The principal must be the email the reviewer tags with (git hands the tagger
# email to ssh-keygen as the signature principal), which is why it is listed
# explicitly rather than guessed from the forge.
#
# Run this from the overlay root, review the diff, and commit. The forge is
# consulted at ENROLLMENT time, by a human; launch-time verification stays
# offline against the committed file. Keep the run deliberate for the same
# reason `sandbox link sync` is deliberate: this file decides whose vetting
# signatures count.
#
# Usage:
#   FORGE_URL=https://git.example.org ./gen-allowed-signers.sh [signers.txt] [allowed_signers]
set -euo pipefail

FORGE_URL="${FORGE_URL:?set FORGE_URL, e.g. FORGE_URL=https://git.example.org}"
SIGNERS_TXT="${1:-signers.txt}"
OUT="${2:-allowed_signers}"

[[ -f "${SIGNERS_TXT}" ]] || { echo "ERROR: ${SIGNERS_TXT} not found" >&2; exit 1; }

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT

while read -r email user _; do
  case "${email}" in ''|\#*) continue ;; esac
  if [[ -z "${user:-}" ]]; then
    echo "WARN: malformed line (need '<email> <username>'): ${email} — skipped" >&2
    continue
  fi
  keys="$(curl -sfL --max-time 15 "${FORGE_URL%/}/${user}.keys")" || {
    echo "WARN: could not fetch keys for '${user}' from ${FORGE_URL%/}/${user}.keys — skipped" >&2
    continue
  }
  if [[ -z "${keys}" ]]; then
    echo "WARN: '${user}' has no public keys on the forge — skipped" >&2
    continue
  fi
  while read -r keytype blob _; do
    [[ -n "${blob:-}" ]] || continue
    printf '%s %s %s\n' "${email}" "${keytype}" "${blob}" >> "${tmp}"
  done <<< "${keys}"
done < "${SIGNERS_TXT}"

sort -u "${tmp}" > "${OUT}"
echo ">> Wrote $(wc -l < "${OUT}" | tr -d ' ') signer line(s) to ${OUT}."
echo ">> Review the diff, then commit — this file decides whose signatures count."
