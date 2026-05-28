#!/usr/bin/env bash
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

# load_extra_allowed_domains_from_file <path> — print the
# `extra_allowed_domains:` list from a YAML file, one domain per line.
load_extra_allowed_domains_from_file() {
  extract_yaml_list_from_file "$1" "extra_allowed_domains"
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
