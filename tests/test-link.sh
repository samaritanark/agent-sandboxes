#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-link.sh — Git-backed team overlay ("sandbox link") tests
#
# Cluster-free. Drives the real bin/sandbox binary against a local upstream
# git repo used as the overlay remote, and unit-tests the lib/link.sh + the
# lib/config.sh upsert/remove helpers directly. Covers: name derivation,
# clone + pointer wiring, validation gate (accept/reject), pinned-tag vs
# branch tracking, status ahead/behind, sync (advance + roll-back on bad
# tree + refuse-on-dirty), the run-path notify hook (TTL + behind), and
# unlink.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SB="${SANDBOX_ROOT}/bin/sandbox"
TEST_DIR="$(mktemp -d /tmp/sandbox-link-test-XXXXXX)"

# Isolate everything under a throwaway HOME so we never touch the developer's
# real ~/.sandbox/config.yaml or overlays.
export HOME="${TEST_DIR}/home"
mkdir -p "${HOME}"
export USER_SANDBOX_CONFIG="${HOME}/.sandbox/config.yaml"
export LINK_OVERLAYS_DIR="${HOME}/.sandbox/overlays"
# Deterministic git identity for the fixtures (no dependency on user gitconfig).
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com

command -v git >/dev/null 2>&1 || skip "git not available"

fail() { echo "FAIL: $*" >&2; exit 1; }
cleanup() { rm -rf "${TEST_DIR}"; }
trap cleanup EXIT

eq() {
  local label="$1" expected="$2" actual="$3"
  [[ "${expected}" == "${actual}" ]] && pass "${label}" \
    || fail "${label}: expected '${expected}', got '${actual}'"
}

# make_upstream <dir> — a minimal valid overlay repo on branch main, tagged
# v1.0.0 at the first commit.
make_upstream() {
  local dir="$1"
  mkdir -p "${dir}/profiles" "${dir}/catalogue"
  printf 'profile: dev\ntier: 2\n' > "${dir}/profiles/dev.yaml"
  printf 'name: pg\nkind: service\nimage: example@sha256:%064d\nport: 5432\n' 0 \
    > "${dir}/catalogue/pg.yaml"
  printf '# team overlay\n' > "${dir}/README.md"
  git -c init.defaultBranch=main init -q "${dir}"
  git -C "${dir}" add -A
  git -C "${dir}" commit -qm "v1"
  git -C "${dir}" tag v1.0.0
}

# Source the libs (this file runs under bash, so this is safe) for the unit +
# notify-hook tests. bin/sandbox exercises the same code end-to-end.
source "${SANDBOX_ROOT}/lib/platform.sh"
source "${SANDBOX_ROOT}/lib/config.sh"
source "${SANDBOX_ROOT}/lib/profile.sh"
source "${SANDBOX_ROOT}/lib/link.sh"

###############################################################################
# Unit: name derivation + validation
###############################################################################
test_name_from_url() {
  info "Testing link_name_from_url..."
  eq "ssh scp-style"  "sandbox-overlay" "$(link_name_from_url git@github.com:acme/sandbox-overlay.git)"
  eq "https .git"     "overlay"         "$(link_name_from_url https://github.com/acme/overlay.git)"
  eq "trailing slash" "repo"            "$(link_name_from_url https://x/repo/)"
  eq "no .git"        "plain"           "$(link_name_from_url https://x/plain)"
}

test_valid_name() {
  info "Testing link_is_valid_name..."
  for n in dev-app team.v2 a_b; do
    link_is_valid_name "${n}" || fail "'${n}' should be valid"
  done
  for n in "" "a/b" "../x" ".hidden" "a b"; do
    link_is_valid_name "${n}" && fail "'${n}' should be invalid"
  done
  pass "link_is_valid_name accepts safe names, rejects traversal/empty/space"
}

###############################################################################
# Unit: default_repo sensitivity check canonicalizes before matching
###############################################################################
test_default_repo_sensitivity() {
  info "Testing _link_default_repo_is_sensitive path canonicalization..."

  # Every one of these resolves to $HOME or / or a hidden/system dir. A literal
  # string compare misses them; canonicalization must not. (Regression for the
  # slash/dot-noise bypass: ~/. , ~/./ , ~// , /. , /./ , <home>/. , <home>// .)
  local v
  for v in \
    "~" "~/" "~/." "~/./" "~//" "~/.//" \
    "${HOME}" "${HOME}/" "${HOME}/." "${HOME}//" "${HOME}/./" \
    "/" "/." "/./" "//" \
    "~/.ssh" "~/.ssh/" "~/.ssh/." "~/./.ssh" "${HOME}/.aws" "~/.config/gcloud" \
    ".." "~/.." "~/../.." "~/foo/../.bar" \
    "/etc" "/etc/" "/etc/." "/etc//ssl" "/root/.ssh" "/proc/1" "/sys/kernel" "/boot"; do
    _link_default_repo_is_sensitive "${v}" \
      || fail "sensitive default_repo not flagged: '${v}' (normalized: '$(_link_normalize_path "${v}")')"
  done

  # Legitimate repo paths must still pass — including a benign "." *component*
  # in the middle, which the old glob wrongly flagged (a false positive) because
  # its `?` matched the slash.
  for v in \
    "~/repos/app" "~/./repos/app" "~/repos/./app" "${HOME}/src/project" \
    "/srv/git/app" "/var/lib/repos/x" "/opt/work/app//src" "/mnt/data/repo"; do
    _link_default_repo_is_sensitive "${v}" \
      && fail "benign default_repo wrongly flagged: '${v}' (normalized: '$(_link_normalize_path "${v}")')"
  done

  pass "default_repo sensitivity check canonicalizes slash/dot noise before matching"
}

###############################################################################
# Unit: config upsert / remove helpers
###############################################################################
test_config_helpers() {
  info "Testing upsert_yaml_scalar_in_file / remove_yaml_scalar_from_file..."
  local f="${TEST_DIR}/cfg.yaml"
  printf '# example\n# overlay: ~/x\nother: keep\n' > "${f}"

  upsert_yaml_scalar_in_file "${f}" overlay /a/b
  eq "upsert appends new key"    "/a/b" "$(extract_yaml_scalar_from_file "${f}" overlay)"
  eq "unrelated key preserved"   "keep" "$(extract_yaml_scalar_from_file "${f}" other)"

  upsert_yaml_scalar_in_file "${f}" overlay /c/d
  eq "upsert replaces in place"  "/c/d" "$(extract_yaml_scalar_from_file "${f}" overlay)"
  eq "single overlay line"       "1"    "$(grep -c '^overlay:' "${f}")"

  remove_yaml_scalar_from_file "${f}" overlay
  eq "remove clears active key"  ""     "$(extract_yaml_scalar_from_file "${f}" overlay)"
  eq "commented example intact"  "1"    "$(grep -c '^# overlay:' "${f}")"
}

###############################################################################
# Integration: clone + status + branch tracking + sync
###############################################################################
test_link_and_track_branch() {
  info "Testing link (default branch) + status + sync..."
  local up="${TEST_DIR}/up-branch"
  make_upstream "${up}"

  "${SB}" link "${up}" --name team >/dev/null 2>&1 || fail "link failed"
  eq "pointer set to clone"  "${LINK_OVERLAYS_DIR}/team" \
                             "$(extract_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" overlay)"
  eq "ref recorded"          "main" "$(link_ref_config)"
  [[ -f "${LINK_OVERLAYS_DIR}/team/profiles/dev.yaml" ]] || fail "cloned profile missing"

  # Advance upstream main; status must report behind, sync must catch up.
  echo change > "${up}/README.md"; git -C "${up}" commit -qam v2
  "${SB}" link status 2>&1 | grep -q "behind 'main'" || fail "status did not report behind"
  "${SB}" link sync >/dev/null 2>&1 || fail "sync failed"
  "${SB}" link status 2>&1 | grep -q "up to date" || fail "not up to date after sync"
  pass "branch link tracks main and syncs forward"

  "${SB}" link unlink --yes >/dev/null 2>&1 || fail "unlink failed"
}

###############################################################################
# Integration: a tag pin does NOT move when upstream advances
###############################################################################
test_tag_pin_is_stable() {
  info "Testing tag pinning..."
  local up="${TEST_DIR}/up-tag"
  make_upstream "${up}"
  echo more > "${up}/x"; git -C "${up}" add -A; git -C "${up}" commit -qm v2  # main moves past the tag

  "${SB}" link "${up}" --ref v1.0.0 --name pinned >/dev/null 2>&1 || fail "tag link failed"
  "${SB}" link status 2>&1 | grep -q "up to date with 'v1.0.0'" \
    || fail "tag-pinned link should be up to date despite main advancing"
  pass "tag pin is stable while upstream branch moves"

  "${SB}" link unlink --yes >/dev/null 2>&1 || fail "unlink failed"
}

###############################################################################
# Integration: validation rejects a malformed overlay, nothing is linked
###############################################################################
test_validation_rejects() {
  info "Testing shape validation gate..."
  local bad="${TEST_DIR}/up-bad"
  mkdir -p "${bad}/profiles"
  printf 'profile: x\ntier: 9\n' > "${bad}/profiles/x.yaml"   # invalid tier
  git -c init.defaultBranch=main init -q "${bad}"
  git -C "${bad}" add -A; git -C "${bad}" commit -qm bad

  if "${SB}" link "${bad}" --name rejected >/dev/null 2>&1; then
    fail "link should have failed validation"
  fi
  [[ -d "${LINK_OVERLAYS_DIR}/rejected" ]] && fail "clone left behind after rejected validation"
  [[ -z "$(extract_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" link_url)" ]] \
    || fail "link_url written despite rejected validation"
  pass "invalid overlay is rejected and leaves no trace"

  # A tracked symlink escaping the overlay (absolute target) is also rejected.
  local esc="${TEST_DIR}/up-symlink"
  mkdir -p "${esc}/profiles"
  printf 'profile: ok\ntier: 1\n' > "${esc}/profiles/ok.yaml"
  ln -s /etc/passwd "${esc}/leak"
  git -c init.defaultBranch=main init -q "${esc}"
  git -C "${esc}" add -A; git -C "${esc}" commit -qm sym
  if "${SB}" link "${esc}" --name symlink >/dev/null 2>&1; then
    fail "link should reject an overlay with an escaping symlink"
  fi
  [[ -d "${LINK_OVERLAYS_DIR}/symlink" ]] && fail "clone left behind after symlink rejection"
  pass "overlay with an escaping symlink is rejected"
}

###############################################################################
# Integration: profile value validation — sensitive default_repo is rejected
# (on clone AND sync), and extra_allowed_domains are surfaced for review.
###############################################################################
test_value_validation() {
  info "Testing profile value validation (default_repo + domain surfacing)..."

  # A profile whose default_repo resolves to ~/.ssh is rejected on clone; the
  # shape gate would otherwise pass it (valid name, valid tier, no symlink).
  local danger="${TEST_DIR}/up-danger"
  mkdir -p "${danger}/profiles"
  printf 'profile: eng\ntier: 1\ndefault_repo: ~/.ssh\n' > "${danger}/profiles/eng.yaml"
  git -c init.defaultBranch=main init -q "${danger}"
  git -C "${danger}" add -A; git -C "${danger}" commit -qm danger
  if "${SB}" link "${danger}" --name danger >/dev/null 2>&1; then
    fail "link should reject a profile with a sensitive default_repo"
  fi
  [[ -d "${LINK_OVERLAYS_DIR}/danger" ]] && fail "clone left behind after sensitive default_repo rejection"
  pass "profile with sensitive default_repo (~/.ssh) is rejected on clone"

  # End-to-end: the reported slash/dot-noise bypass ("~/." resolves to $HOME)
  # must be rejected at link time, not just by the unit test above.
  local bypass="${TEST_DIR}/up-bypass"
  mkdir -p "${bypass}/profiles"
  printf 'profile: eng\ntier: 1\ndefault_repo: ~/.\n' > "${bypass}/profiles/eng.yaml"
  git -c init.defaultBranch=main init -q "${bypass}"
  git -C "${bypass}" add -A; git -C "${bypass}" commit -qm bypass
  if "${SB}" link "${bypass}" --name bypass >/dev/null 2>&1; then
    fail "link should reject a default_repo that resolves to \$HOME via slash/dot noise"
  fi
  [[ -d "${LINK_OVERLAYS_DIR}/bypass" ]] && fail "clone left behind after bypass-variant rejection"
  pass "default_repo '~/.' (resolves to \$HOME) is rejected on clone"

  # A benign default_repo links fine, and its extra_allowed_domains are
  # surfaced to the operator for review (non-fatal).
  local ok="${TEST_DIR}/up-domains"
  mkdir -p "${ok}/profiles"
  printf 'profile: eng\ntier: 1\ndefault_repo: ~/repos/app\nextra_allowed_domains:\n  - api.internal.example\n' \
    > "${ok}/profiles/eng.yaml"
  git -c init.defaultBranch=main init -q "${ok}"
  git -C "${ok}" add -A; git -C "${ok}" commit -qm ok
  local out
  out="$("${SB}" link "${ok}" --name domains 2>&1)" || fail "benign overlay should link"
  echo "${out}" | grep -q "api.internal.example" \
    || fail "extra_allowed_domains not surfaced on link, got: ${out}"
  pass "benign default_repo links and extra_allowed_domains are surfaced for review"

  # sync must re-validate values too: advancing upstream into a sensitive
  # default_repo is rejected and the checked-out tree rolls back.
  printf 'profile: eng\ntier: 1\ndefault_repo: ~/.aws\n' > "${ok}/profiles/eng.yaml"
  git -C "${ok}" commit -qam poisoned
  if "${SB}" link sync >/dev/null 2>&1; then
    fail "sync should reject an upstream that adds a sensitive default_repo"
  fi
  # The profile stores the unexpanded tilde form, so match it literally.
  # shellcheck disable=SC2088  # literal string in the YAML, not a path to expand
  grep -q '~/repos/app' "${LINK_OVERLAYS_DIR}/domains/profiles/eng.yaml" \
    || fail "clone did not roll back to the pre-sync tree after failed validation"
  pass "sync re-validates default_repo and rolls back a poisoned tree"

  "${SB}" link unlink --yes >/dev/null 2>&1 || fail "unlink failed"
}

###############################################################################
# Integration: sync refuses to clobber local uncommitted edits
###############################################################################
test_sync_refuses_dirty() {
  info "Testing sync refuse-on-dirty..."
  local up="${TEST_DIR}/up-dirty"
  make_upstream "${up}"
  "${SB}" link "${up}" --name dirtylink >/dev/null 2>&1 || fail "link failed"
  echo local-edit >> "${LINK_OVERLAYS_DIR}/dirtylink/profiles/dev.yaml"
  echo advance > "${up}/z"; git -C "${up}" add -A; git -C "${up}" commit -qm v2

  if "${SB}" link sync >/dev/null 2>&1; then
    fail "sync should refuse when the clone has local changes"
  fi
  pass "sync refuses to overwrite local edits"

  git -C "${LINK_OVERLAYS_DIR}/dirtylink" checkout -- profiles/dev.yaml
  "${SB}" link unlink --yes >/dev/null 2>&1 || fail "unlink failed"
}

###############################################################################
# Unit: run-path notify hook — silent within TTL, warns when behind + expired
###############################################################################
test_notify_hook() {
  info "Testing link_notify_if_behind..."
  local up="${TEST_DIR}/up-notify"
  make_upstream "${up}"
  "${SB}" link "${up}" --name notifylink >/dev/null 2>&1 || fail "link failed"
  local dir="${LINK_OVERLAYS_DIR}/notifylink"
  echo behind > "${up}/n"; git -C "${up}" add -A; git -C "${up}" commit -qm v2

  # Fresh stamp => within TTL => no fetch, no warning even though behind.
  : > "$(_link_fetch_stamp "${dir}")"
  local within; within="$(link_notify_if_behind 2>&1)"
  eq "silent within TTL" "" "${within}"

  # Expire the stamp => fetch => detect behind => single warning line.
  touch -t 200001010000 "$(_link_fetch_stamp "${dir}")"
  local expired; expired="$(link_notify_if_behind 2>&1)"
  echo "${expired}" | grep -q "behind 'main'" || fail "expected behind warning, got: ${expired}"
  pass "notify hook is TTL-gated and warns when behind"

  # Opt-out env var short-circuits entirely.
  touch -t 200001010000 "$(_link_fetch_stamp "${dir}")"
  local off; off="$(SANDBOX_NO_LINK_CHECK=1 link_notify_if_behind 2>&1)"
  eq "SANDBOX_NO_LINK_CHECK silences" "" "${off}"

  "${SB}" link unlink --yes >/dev/null 2>&1 || fail "unlink failed"
}

###############################################################################
# Integration: unlink clears config and removes the clone
###############################################################################
test_unlink() {
  info "Testing unlink..."
  local up="${TEST_DIR}/up-unlink"
  make_upstream "${up}"
  "${SB}" link "${up}" --name gone >/dev/null 2>&1 || fail "link failed"
  "${SB}" link unlink --yes >/dev/null 2>&1 || fail "unlink failed"
  [[ -d "${LINK_OVERLAYS_DIR}/gone" ]] && fail "clone not removed on unlink"
  [[ -z "$(link_url_config)" ]] || fail "link_url not cleared on unlink"
  [[ -z "$(extract_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" overlay)" ]] \
    || fail "overlay pointer not cleared on unlink"
  pass "unlink clears config and removes clone"
}

test_name_from_url
test_valid_name
test_default_repo_sensitivity
test_config_helpers
test_link_and_track_branch
test_tag_pin_is_stable
test_validation_rejects
test_value_validation
test_sync_refuses_dirty
test_notify_hook
test_unlink

echo "All link tests passed."
