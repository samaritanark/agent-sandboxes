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
# tree + refuse-on-dirty), the run-path auto-sync hook (advance, opt-out,
# dirty/invalid fail-safes, min-version hard stop), the min_sandbox_version
# gate, and unlink.
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
# lib code calls die() on hard stops; bin/sandbox defines it. Mirror it here
# for the sourced-lib tests — the run-sync min-version test asserts on the
# exit it causes (inside a subshell, so the suite itself survives).
die() { echo "FATAL: $*" >&2; exit 1; }
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
# Integration: an overlay config.yaml is a recognized, consumed file — not an
# "unrecognized top-level entry", and its vetting posture is surfaced.
###############################################################################
test_config_yaml_recognized() {
  info "Testing overlay config.yaml recognition + posture surfacing..."

  # A valid overlay that also ships config.yaml with `vetting: required`.
  local cfg="${TEST_DIR}/up-config"
  make_upstream "${cfg}"
  printf 'vetting: required\n' > "${cfg}/config.yaml"
  git -C "${cfg}" add -A; git -C "${cfg}" commit -qm config

  local out
  out="$("${SB}" link "${cfg}" --name cfg 2>&1)" || fail "overlay with config.yaml should link"
  echo "${out}" | grep -q "unrecognized top-level entry: config.yaml" \
    && fail "config.yaml wrongly flagged as unrecognized, got: ${out}"
  echo "${out}" | grep -q "vetting: required" \
    || fail "vetting posture not surfaced in summary, got: ${out}"
  pass "config.yaml is recognized and its vetting posture is surfaced on link"

  # resolve_vetting_posture (the consume path) actually honors the overlay file:
  # with no user posture set, the overlay ratchets the baseline up to required.
  local overlay_dir; overlay_dir="$(extract_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" overlay)"
  source "${SANDBOX_ROOT}/lib/vetting.sh"
  eq "overlay ratchets posture to required" "required" "$(SANDBOX_OVERLAY="${overlay_dir}" resolve_vetting_posture)"

  "${SB}" link unlink --yes >/dev/null 2>&1 || fail "unlink failed"

  # An unrecognized posture value warns (visible, fails safe to advisory) but
  # does not block the link.
  local badp="${TEST_DIR}/up-badposture"
  make_upstream "${badp}"
  printf 'vetting: requird\n' > "${badp}/config.yaml"   # typo
  git -C "${badp}" add -A; git -C "${badp}" commit -qm badposture
  out="$("${SB}" link "${badp}" --name badp 2>&1)" || fail "overlay with typo'd posture should still link"
  echo "${out}" | grep -q "unrecognized vetting posture 'requird'" \
    || fail "typo'd vetting posture not warned, got: ${out}"
  pass "unrecognized vetting posture warns but does not block the link"

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
# Unit: min_sandbox_version reader + comparison edge cases
###############################################################################
test_min_version_unit() {
  info "Testing overlay_min_sandbox_version / overlay_min_version_unmet..."
  local d="${TEST_DIR}/minver"; mkdir -p "${d}"

  # No config.yaml / no key → no requirement.
  eq "no config.yaml → met" "" "$(overlay_min_version_unmet "${d}")"
  printf 'vetting: advisory\n' > "${d}/config.yaml"
  eq "no key → met" "" "$(overlay_min_version_unmet "${d}")"

  printf 'min_sandbox_version: 2.12.0\n' > "${d}/config.yaml"
  eq "reader prints the key" "2.12.0" "$(overlay_min_sandbox_version "${d}")"
  eq "older CLI is unmet"    "2.12.0" "$(SANDBOX_VERSION=2.11.3 overlay_min_version_unmet "${d}" 2>/dev/null)"
  eq "equal CLI is met"      ""       "$(SANDBOX_VERSION=2.12.0 overlay_min_version_unmet "${d}" 2>/dev/null)"
  eq "newer CLI is met"      ""       "$(SANDBOX_VERSION=3.0.0  overlay_min_version_unmet "${d}" 2>/dev/null)"
  eq "v-prefixed CLI is met" ""       "$(SANDBOX_VERSION=v2.12.0 overlay_min_version_unmet "${d}" 2>/dev/null)"

  # v-prefixed requirement + short form compare like release tags (2.12 == 2.12.0).
  printf 'min_sandbox_version: v2.12\n' > "${d}/config.yaml"
  eq "v/short requirement met" "" "$(SANDBOX_VERSION=2.12.0 overlay_min_version_unmet "${d}" 2>/dev/null)"

  # Unparseable value → visible warning, gates nothing.
  printf 'min_sandbox_version: latest\n' > "${d}/config.yaml"
  local out; out="$(SANDBOX_VERSION=1.0.0 overlay_min_version_unmet "${d}" 2>&1)"
  echo "${out}" | grep -q "unparseable" || fail "expected unparseable warning, got: ${out}"
  eq "unparseable gates nothing" "" "$(SANDBOX_VERSION=1.0.0 overlay_min_version_unmet "${d}" 2>/dev/null)"

  # A dev (unversioned) build cannot compare → warns and passes.
  printf 'min_sandbox_version: 99.0.0\n' > "${d}/config.yaml"
  out="$(overlay_min_version_unmet "${d}" 2>&1)"   # SANDBOX_VERSION unset here
  echo "${out}" | grep -q "dev checkout" || fail "expected dev-checkout warning, got: ${out}"
  eq "dev build passes" "" "$(overlay_min_version_unmet "${d}" 2>/dev/null)"
  pass "min_sandbox_version comparison and edge cases behave"
}

###############################################################################
# Unit: run-path auto-sync hook — advances to the pinned ref's tip, honors the
# opt-out, fails safe on dirty/invalid trees, hard-stops on min-version
###############################################################################
test_run_sync_hook() {
  info "Testing link_sync_on_run..."
  local up="${TEST_DIR}/up-runsync"
  make_upstream "${up}"
  "${SB}" link "${up}" --name runsync >/dev/null 2>&1 || fail "link failed"
  local dir="${LINK_OVERLAYS_DIR}/runsync"
  echo behind > "${up}/n"; git -C "${up}" add -A; git -C "${up}" commit -qm v2
  local tip; tip="$(git -C "${up}" rev-parse HEAD)"

  # Opt-out env var short-circuits entirely: no output, no advance.
  local off; off="$(SANDBOX_NO_LINK_CHECK=1 link_sync_on_run 2>&1)"
  eq "SANDBOX_NO_LINK_CHECK skips the sync" "" "${off}"
  [[ "$(git -C "${dir}" rev-parse HEAD)" == "${tip}" ]] \
    && fail "opt-out must not advance the clone"

  # Behind + clean → auto-advance to the tip and record the new commit.
  link_sync_on_run >/dev/null 2>&1 || fail "run-path sync failed on a clean, behind clone"
  eq "auto-synced to the ref tip" "${tip}" "$(git -C "${dir}" rev-parse HEAD)"
  eq "link_commit re-recorded"    "${tip}" "$(link_commit_config)"
  pass "run-path sync advances a clean clone to the pinned ref's tip"

  # Local uncommitted edits → warn, no advance, launch path survives.
  echo more > "${up}/m"; git -C "${up}" add -A; git -C "${up}" commit -qm v3
  echo local-edit >> "${dir}/README.md"
  local dirty_out
  dirty_out="$(link_sync_on_run 2>&1)" || fail "dirty clone must not fail the launch path"
  echo "${dirty_out}" | grep -q "local uncommitted edits" \
    || fail "expected dirty-clone warning, got: ${dirty_out}"
  eq "dirty clone not advanced" "${tip}" "$(git -C "${dir}" rev-parse HEAD)"
  git -C "${dir}" checkout -- README.md
  pass "run-path sync refuses to clobber local edits and lets the launch proceed"

  # Upstream turns invalid → advance is rolled back, warn, launch path survives.
  printf 'profile: bad\ntier: 9\n' > "${up}/profiles/bad.yaml"
  git -C "${up}" add -A; git -C "${up}" commit -qm badtree
  local bad_out
  bad_out="$(link_sync_on_run 2>&1)" || fail "invalid new tree must not fail the launch path"
  echo "${bad_out}" | grep -q "failed validation" \
    || fail "expected validation warning, got: ${bad_out}"
  eq "rolled back to previous commit" "${tip}" "$(git -C "${dir}" rev-parse HEAD)"
  pass "run-path sync rolls back an invalid tree and lets the launch proceed"

  # Upstream now requires a newer CLI → roll back + hard stop (die → exit 1).
  git -C "${up}" rm -q profiles/bad.yaml
  printf 'min_sandbox_version: 99.0.0\n' > "${up}/config.yaml"
  git -C "${up}" add -A; git -C "${up}" commit -qm needs-newer
  if ( SANDBOX_VERSION=2.0.0 link_sync_on_run >/dev/null 2>&1 ); then
    fail "run-path sync must hard-stop when the overlay requires a newer CLI"
  fi
  eq "rolled back after min-version stop" "${tip}" "$(git -C "${dir}" rev-parse HEAD)"
  pass "run-path sync blocks the launch (and rolls back) on min_sandbox_version"

  # The same tree on a dev build: warns it cannot compare, then syncs.
  local dev_out
  dev_out="$(link_sync_on_run 2>&1)" || fail "dev build must not hard-stop"
  echo "${dev_out}" | grep -q "dev checkout" \
    || fail "expected cannot-compare warning, got: ${dev_out}"
  eq "dev build synced to tip" "$(git -C "${up}" rev-parse HEAD)" "$(git -C "${dir}" rev-parse HEAD)"
  pass "dev build warns and syncs (nothing to compare)"

  "${SB}" link unlink --yes >/dev/null 2>&1 || fail "unlink failed"
}

###############################################################################
# Integration: min_sandbox_version at link time. This checkout may be stamped
# (a .version file) or not, and both sides of that are worth pinning down: a
# stamped CLI must refuse an overlay demanding 99.0.0; an unstamped (dev) one
# must link it with a cannot-compare warning. Either way the summary line
# surfaces the requirement.
###############################################################################
test_min_version_link_gate() {
  info "Testing min_sandbox_version link gate..."
  local mv="${TEST_DIR}/up-minver"
  make_upstream "${mv}"
  printf 'min_sandbox_version: 99.0.0\n' > "${mv}/config.yaml"
  git -C "${mv}" add -A; git -C "${mv}" commit -qm minver

  local out
  if [[ -f "${SANDBOX_ROOT}/.version" ]]; then
    if "${SB}" link "${mv}" --name minver >/dev/null 2>&1; then
      fail "stamped CLI should refuse an overlay requiring 99.0.0"
    fi
    [[ -d "${LINK_OVERLAYS_DIR}/minver" ]] && fail "clone left behind after min-version refusal"
    [[ -z "$(extract_yaml_scalar_from_file "${USER_SANDBOX_CONFIG}" link_url)" ]] \
      || fail "link_url written despite min-version refusal"
    pass "stamped CLI refuses an overlay requiring a newer version, leaves no trace"
  else
    out="$("${SB}" link "${mv}" --name minver 2>&1)" \
      || fail "dev CLI should link a min-versioned overlay (with a warning), got: ${out}"
    echo "${out}" | grep -q "min CLI: 99.0.0" \
      || fail "min version not surfaced in the link summary, got: ${out}"
    echo "${out}" | grep -q "dev checkout" \
      || fail "expected cannot-compare warning, got: ${out}"
    "${SB}" link unlink --yes >/dev/null 2>&1 || fail "unlink failed"
    pass "dev CLI links a min-versioned overlay, warns, and surfaces the requirement"
  fi
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
test_config_yaml_recognized
test_sync_refuses_dirty
test_min_version_unit
test_run_sync_hook
test_min_version_link_gate
test_unlink

echo "All link tests passed."
