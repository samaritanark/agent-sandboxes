#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/config.sh — Per-user / per-environment / per-repo configuration loading
#
# Operators can pre-approve extra egress domains so 'sandbox run' doesn't
# need a --allow-domain flag on every invocation. Three sources are read on
# every run; the union (after de-duplication by the caller) is merged into
# the per-invocation --allow-domain list and then validated against the
# blocked-destinations list like any other allowed domain.
#
#   1. ~/.sandbox/config.yaml — YAML file with:
#        extra_allowed_domains:
#          - git.example.com
#          - artifactory.example.com
#
#   2. SANDBOX_EXTRA_ALLOWED_DOMAINS — comma-separated list in the shell env:
#        export SANDBOX_EXTRA_ALLOWED_DOMAINS="git.example.com,artifactory.example.com"
#
#   3. <repo>/.sandbox/config.yaml — same schema as (1), loaded for each
#      --repo path. Lets a team ship per-project allow-list additions
#      (e.g. a repo that pulls Go modules from a private proxy) without
#      every operator having to add them to their personal config. The
#      caller prints a "this repo contributed X, Y, Z" banner so the
#      additions stay visible on every session start.
#
# None of the three sources bypass lib/checks.sh:check_domain_not_blocked.
#
# This file also exposes two generic YAML helpers used by lib/profile.sh and
# anywhere else we need to read a flat key from a sandbox config file:
#   extract_yaml_list_from_file <path> <key>
#   extract_yaml_scalar_from_file <path> <key>
set -euo pipefail

USER_SANDBOX_CONFIG="${USER_SANDBOX_CONFIG:-${HOME}/.sandbox/config.yaml}"

# extract_yaml_list_from_file <path> <key> — print the list items under
# "<key>:" in a YAML file, one per line. Bounded extraction stops at the
# next top-level key, so fields later in the file don't bleed in. Strips
# quoting, leading "- ", and inline comments.
extract_yaml_list_from_file() {
  local path="$1" key="$2"
  [[ -f "${path}" ]] || return 0

  local line item
  while IFS= read -r line; do
    item="$(echo "${line}" | sed 's/^[[:space:]]*-[[:space:]]*//' | tr -d '"'"'")"
    # Drop inline " # comment" tails so `- foo  # note` becomes `foo`.
    item="${item%%[[:space:]]#*}"
    item="${item%"${item##*[![:space:]]}"}"
    [[ -z "${item}" ]] && continue
    [[ "${item:0:1}" == "#" ]] && continue
    echo "${item}"
  done < <(awk -v key="${key}" '
    $0 ~ "^"key":"            { flag = 1; next }
    flag && /^[A-Za-z_]/      { flag = 0 }
    flag && /^[[:space:]]*-/  { print }
  ' "${path}" 2>/dev/null || true)
}

# extract_yaml_scalar_from_file <path> <key> — print the value of a
# top-level "<key>: value" line. Strips quoting and inline comments.
# Empty output if the key is absent or the file does not exist.
extract_yaml_scalar_from_file() {
  local path="$1" key="$2"
  [[ -f "${path}" ]] || return 0

  awk -v key="${key}" '
    $0 ~ "^"key":[[:space:]]*" {
      sub("^"key":[[:space:]]*", "")
      sub(/[[:space:]]+#.*$/, "")    # strip trailing comments
      gsub(/["'\'']/, "")            # strip surrounding quotes
      sub(/^[[:space:]]+/, "")
      sub(/[[:space:]]+$/, "")
      print; exit
    }
  ' "${path}" 2>/dev/null || true
}

# upsert_yaml_scalar_in_file <path> <key> <value> — set a top-level
# "<key>: <value>" line in a flat YAML config file. Replaces the first
# ACTIVE (uncommented) "<key>:" line if present, otherwise appends. Commented
# example lines ("# key: ...") are left untouched — they don't match "^key:"
# and the reader (extract_yaml_scalar_from_file) skips them too, so appending
# a live line beside a commented example is correct. Creates the parent dir
# and file if absent. bash 3.2 safe (no mapfile / declare -g). The file is
# rewritten atomically via a temp file in the same dir.
upsert_yaml_scalar_in_file() {
  local path="$1" key="$2" value="$3"
  mkdir -p "$(dirname "${path}")"
  [[ -f "${path}" ]] || : > "${path}"

  local tmp="${path}.tmp.$$"
  if grep -q "^${key}:" "${path}" 2>/dev/null; then
    awk -v key="${key}" -v val="${value}" '
      !done && $0 ~ "^"key":" { print key": "val; done=1; next }
      { print }
    ' "${path}" > "${tmp}"
  else
    cat "${path}" > "${tmp}"
    printf '%s: %s\n' "${key}" "${value}" >> "${tmp}"
  fi
  # Preserve the original file's mode where possible; new files get 0600 since
  # ~/.sandbox/config.yaml can carry an overlay path / link URL.
  mv "${tmp}" "${path}"
  chmod 0600 "${path}" 2>/dev/null || true
}

# remove_yaml_scalar_from_file <path> <key> — delete every top-level ACTIVE
# "<key>:" line from a flat YAML config file. Commented lines are left as-is.
# No-op if the file or key is absent. bash 3.2 safe.
remove_yaml_scalar_from_file() {
  local path="$1" key="$2"
  [[ -f "${path}" ]] || return 0
  local tmp="${path}.tmp.$$"
  awk -v key="${key}" '$0 ~ "^"key":" { next } { print }' "${path}" > "${tmp}"
  mv "${tmp}" "${path}"
  chmod 0600 "${path}" 2>/dev/null || true
}

# load_extra_allowed_domains_from_file <path> — print the
# `extra_allowed_domains:` list from a YAML file, one domain per line.
load_extra_allowed_domains_from_file() {
  extract_yaml_list_from_file "$1" "extra_allowed_domains"
}

# honor_repo_allowed_domains — "true" when the active team overlay opts in to
# honoring a per-repo <repo>/.sandbox/config.yaml `extra_allowed_domains:` list,
# else "false" (the default). Widening egress LOOSENS containment, and a repo's
# tree is writable by the in-sandbox agent (and any workspace author), so by
# default a repo cannot grant itself an egress destination — the agent could
# otherwise self-add an exfil host just by committing a domain and having the
# operator relaunch. Restoring the convenience is therefore an operator decision
# confined to the OVERLAY, exactly like leakscan_extra_dep_dirs (lib/filesystem.sh):
# the key is read ONLY from the overlay's config.yaml; a per-repo or per-user
# setting is ignored. Absent, non-`true`, or no overlay ⇒ "false". (Overlay
# resolution via resolve_overlay_path — lib/profile.sh — so this is called after
# the libs are loaded, as everything in the run path is.)
honor_repo_allowed_domains() {
  local overlay v=""
  overlay="$(resolve_overlay_path 2>/dev/null || true)"
  [[ -n "${overlay}" && -f "${overlay}/config.yaml" ]] || { echo "false"; return 0; }
  v="$(extract_yaml_scalar_from_file "${overlay}/config.yaml" honor_repo_allowed_domains)"
  [[ "${v}" == "true" ]] && echo "true" || echo "false"
}

# SANDBOX_REPO_CONFIG_NAME — the per-repo config file, relative to a repo
# root. Single source of truth so the masked-paths reader, the writer, and
# the secret gate all point at the same file.
SANDBOX_REPO_CONFIG_NAME=".sandbox/config.yaml"

# load_repo_masked_paths <repo> — print the per-repo `masked_paths:` list
# (relative file paths the operator has asked the sandbox to mask, in
# addition to the built-in set in lib/filesystem.sh), one per line. Empty
# if the repo has no config or no masked_paths key.
load_repo_masked_paths() {
  extract_yaml_list_from_file "$1/${SANDBOX_REPO_CONFIG_NAME}" "masked_paths"
}

# config_add_masked_path <config_file> <relpath> — add <relpath> to the
# `masked_paths:` list in a per-repo config file, creating the file (and
# its .sandbox/ parent) if needed. Idempotent: a path already present is a
# no-op. The value is double-quoted so paths containing ':' or '#' survive
# the naive YAML reader. bash 3.2-safe (no mapfile/declare -g).
config_add_masked_path() {
  local config_file="$1" relpath="$2"

  # Already present? extract_yaml_list_from_file strips quoting, so the
  # comparison is against the bare path.
  local existing
  while IFS= read -r existing; do
    [[ "${existing}" == "${relpath}" ]] && return 0
  done < <(extract_yaml_list_from_file "${config_file}" "masked_paths")

  mkdir -p "$(dirname "${config_file}")"

  local item="  - \"${relpath}\""

  if [[ ! -f "${config_file}" ]]; then
    printf 'masked_paths:\n%s\n' "${item}" > "${config_file}"
    return 0
  fi

  # File exists. If it already has a masked_paths: block, insert the new
  # item right after the key line; otherwise append a fresh block at EOF.
  if grep -q '^masked_paths:' "${config_file}"; then
    local tmp="${config_file}.tmp.$$"
    awk -v item="${item}" '
      { print }
      /^masked_paths:/ && !done { print item; done = 1 }
    ' "${config_file}" > "${tmp}" && mv "${tmp}" "${config_file}"
  else
    # Ensure the file ends with a newline before appending the block.
    [[ -n "$(tail -c1 "${config_file}")" ]] && printf '\n' >> "${config_file}"
    printf 'masked_paths:\n%s\n' "${item}" >> "${config_file}"
  fi
}

# SANDBOX_REPO_IGNORE_NAME — the canonical per-repo secret-exception store: a
# betterleaks ignore file at the REPO ROOT, in betterleaks' native fingerprint
# format (`relpath:rule:line`, one per line, `#` full-line comments). One file
# now serves every scanner the team runs — pre-commit hooks and CI call
# `betterleaks dir .` from the repo root and honor it natively, and the sandbox
# launch gate honors it (only once the repo is vetted; see
# vetted_accepted_fingerprints). betterleaks also auto-reads a .gitleaksignore
# at the root, so a repo that already carries one is read as a fallback.
SANDBOX_REPO_IGNORE_NAME=".betterleaksignore"
SANDBOX_REPO_IGNORE_FALLBACK=".gitleaksignore"

# repo_ignore_file <repo> — print the repo-root ignore file to use: an existing
# .betterleaksignore, else an existing .gitleaksignore, else the canonical
# .betterleaksignore path (for a writer creating it). Always prints one path.
repo_ignore_file() {
  local repo="$1" f
  for f in "${SANDBOX_REPO_IGNORE_NAME}" "${SANDBOX_REPO_IGNORE_FALLBACK}"; do
    [[ -f "${repo}/${f}" ]] && { echo "${repo}/${f}"; return 0; }
  done
  echo "${repo}/${SANDBOX_REPO_IGNORE_NAME}"
}

# strip_ignore_file_comments — filter stdin (an ignore file) down to bare
# fingerprint lines: full-line `#` comments and blank lines removed, surrounding
# whitespace trimmed. betterleaks does NOT support trailing inline comments (a
# `fp  # note` line simply matches nothing), so this deliberately does not strip
# them — a malformed line stays visible to the callers that validate.
strip_ignore_file_comments() {
  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | grep -v '^#' | grep -v '^$' || true
}

# load_repo_ignore_fingerprints <repo> — print the working-tree fingerprints
# recorded in the repo-root ignore file, one `relpath:rule:line` per line.
# This is the WORKING-TREE view (for `sandbox exceptions list` and the vet-time
# preview); the launch gate reads the committed blob at HEAD instead
# (vetting_committed_ignore_fingerprints) so only signature-covered entries are
# ever honored. Empty if the repo has no ignore file.
load_repo_ignore_fingerprints() {
  local f
  f="$(repo_ignore_file "$1")"
  [[ -f "${f}" ]] || return 0
  strip_ignore_file_comments < "${f}"
}

# load_repo_accepted_secrets <repo> — LEGACY reader: the retired
# `accepted_secrets:` list (`relpath:rule:line:hash` entries) in
# <repo>/.sandbox/config.yaml. The gate no longer honors it — the store moved
# to the repo-root betterleaks ignore file so one list serves CI, pre-commit,
# and the sandbox. Kept only so `sandbox exceptions migrate` can convert it and
# the gate/vet can warn when a repo still carries one.
load_repo_accepted_secrets() {
  extract_yaml_list_from_file "$1/${SANDBOX_REPO_CONFIG_NAME}" "accepted_secrets"
}

# ignorefile_add_fingerprint <ignore_file> <fingerprint> [reason] — add a
# `relpath:rule:line` fingerprint to a betterleaks ignore file, creating it if
# needed. Idempotent on the fingerprint (a reason change does not re-add). An
# optional reason lands as a full-line `#` comment ABOVE the entry — betterleaks
# treats a trailing inline comment as part of the fingerprint (the line then
# matches nothing), so own-line comments are the only format that keeps the
# file native to every consumer. bash 3.2-safe.
ignorefile_add_fingerprint() {
  local ignore_file="$1" fingerprint="$2" reason="${3:-}"

  local existing
  if [[ -f "${ignore_file}" ]]; then
    while IFS= read -r existing; do
      [[ "${existing}" == "${fingerprint}" ]] && return 0
    done < <(strip_ignore_file_comments < "${ignore_file}")
    # Ensure the file ends with a newline before appending.
    [[ -n "$(tail -c1 "${ignore_file}")" ]] && printf '\n' >> "${ignore_file}"
  fi

  if [[ -n "${reason}" ]]; then
    # One line only: strip CR/LF so the comment cannot wrap into a bogus entry.
    reason="$(printf '%s' "${reason}" | tr -d '\r\n')"
    reason="${reason#\#}"
    printf '# %s\n' "${reason# }" >> "${ignore_file}"
  fi
  printf '%s\n' "${fingerprint}" >> "${ignore_file}"
}

# remove_yaml_list_from_file <file> <key> — remove a `key:` block list (the key
# line and its `- item` lines) from a YAML file. Comment lines inside the block
# (indented `#`) go with it; anything else is preserved byte-for-byte. Used by
# `sandbox exceptions migrate` to retire an accepted_secrets: block after its
# entries move to the repo-root ignore file. No-op when the key is absent.
remove_yaml_list_from_file() {
  local file="$1" key="$2"
  [[ -f "${file}" ]] || return 0
  grep -q "^${key}:" "${file}" || return 0
  local tmp="${file}.tmp.$$"
  awk -v key="${key}" '
    $0 ~ "^"key":" { inblock = 1; next }
    inblock && /^[[:space:]]+(-|#)/ { next }
    inblock && /^[[:space:]]*$/ { next }
    { inblock = 0; print }
  ' "${file}" > "${tmp}" && mv "${tmp}" "${file}"
}

# load_user_blocked_domains / load_user_blocked_cidrs — print the per-user
# block-list additions from ~/.sandbox/config.yaml, one per line. These reuse
# the same keys as config/blocked-destinations.yaml (blocked_domains /
# blocked_cidrs) so there is one schema across the org, overlay, and user
# layers. They are deny-only: lib/checks.sh unions them with the org + overlay
# blocks (it can never weaken a block), giving an operator a personal
# "never let a sandbox reach this" backstop — e.g. so an accidentally-supplied
# production kubeconfig fails fast at create instead of being auto-allowlisted.
load_user_blocked_domains() {
  extract_yaml_list_from_file "${USER_SANDBOX_CONFIG}" "blocked_domains"
}

load_user_blocked_cidrs() {
  extract_yaml_list_from_file "${USER_SANDBOX_CONFIG}" "blocked_cidrs"
}

# load_user_extra_allowed_domains — print newline-separated list of domains
# the operator has pre-approved via the per-user config file and/or the env
# var. Per-repo configs are loaded separately in bin/sandbox so their
# contributions can be banner-printed by source.
load_user_extra_allowed_domains() {
  load_extra_allowed_domains_from_file "${USER_SANDBOX_CONFIG}"

  # SANDBOX_EXTRA_ALLOWED_DOMAINS env var (comma-separated).
  if [[ -n "${SANDBOX_EXTRA_ALLOWED_DOMAINS:-}" ]]; then
    local _ifs="${IFS}"
    IFS=','
    local domain
    for domain in ${SANDBOX_EXTRA_ALLOWED_DOMAINS}; do
      domain="$(echo "${domain}" | tr -d '[:space:]')"
      [[ -n "${domain}" ]] && echo "${domain}"
    done
    IFS="${_ifs}"
  fi
}
