#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-version-stamp.sh — stamp_version_if_git / read_stamped_version
# (lib/platform.sh). Cluster-free.
#
# Issue #67: `sandbox upgrade`'s "HEAD already at the release tag" branch used to
# re-stamp .version via `git describe` and announce success unconditionally. When
# two tags sit on one commit, describe can pick the wrong one; a dirty tree gets
# a `-dirty` label; a swallowed stamp failure leaves .version untouched. The fix
# passes the resolved target verbatim and reads it back. This locks in that the
# explicit-version stamp is deterministic and that the reader round-trips it.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT_REAL="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-version-stamp"

fail() { echo "FAIL: $*" >&2; exit 1; }

# shellcheck disable=SC1091
source "${SANDBOX_ROOT_REAL}/lib/platform.sh"

eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    pass "${label}"
  else
    fail "${label}: expected '${expected}', got '${actual}'"
  fi
}

# Hermetic git (no signing, no reliance on the caller's global config).
tgit() { git -c user.name=t -c user.email=t@t -c commit.gpgsign=false \
             -c tag.gpgsign=false -c advice.detachedHead=false "$@"; }

# A throwaway checkout that carries a copy of the real stamp script, so
# stamp_version_if_git's guard passes and it writes into <tmp>/.version.
make_checkout() {
  local d="$1"
  mkdir -p "${d}/scripts"
  cp "${SANDBOX_ROOT_REAL}/scripts/stamp-version.sh" "${d}/scripts/stamp-version.sh"
  tgit -C "${d}" init -q
  echo one > "${d}/f"; tgit -C "${d}" add .; tgit -C "${d}" commit -qm c1
}

test_read_round_trips() {
  info "Testing read_stamped_version parses VERSION (and empty when absent)..."
  local tmp; tmp="$(mktemp -d "${TMPDIR:-/tmp}/sbx-stamp-XXXXXX")"
  ( SANDBOX_ROOT="${tmp}"; eq "absent .version -> empty" "" "$(read_stamped_version)" )
  printf 'VERSION=v9.9.9\nCOMMIT=abc\n' > "${tmp}/.version"
  ( SANDBOX_ROOT="${tmp}"; eq "reads VERSION line" "v9.9.9" "$(read_stamped_version)" )
  rm -rf "${tmp}"
}

test_explicit_version_beats_describe() {
  info "Testing an explicit version is written verbatim even with two tags on HEAD..."
  local tmp; tmp="$(mktemp -d "${TMPDIR:-/tmp}/sbx-stamp-XXXXXX")"
  make_checkout "${tmp}"
  # Two release tags on the same commit — the exact case where `git describe`
  # and "highest semver" can disagree (#67 finding 3).
  tgit -C "${tmp}" tag v2.16.99
  tgit -C "${tmp}" tag v2.17.0
  ( SANDBOX_ROOT="${tmp}"; stamp_version_if_git "v2.17.0" >/dev/null 2>&1
    eq "stamped to the passed target" "v2.17.0" "$(read_stamped_version)" )
  rm -rf "${tmp}"
}

test_explicit_version_has_no_dirty_suffix() {
  info "Testing an explicit version never gets a -dirty suffix on a dirty tree..."
  local tmp; tmp="$(mktemp -d "${TMPDIR:-/tmp}/sbx-stamp-XXXXXX")"
  make_checkout "${tmp}"
  tgit -C "${tmp}" tag v2.17.0
  echo changed > "${tmp}/f"           # dirty the tree
  ( SANDBOX_ROOT="${tmp}"; stamp_version_if_git "v2.17.0" >/dev/null 2>&1
    eq "verbatim target, no -dirty" "v2.17.0" "$(read_stamped_version)" )
  rm -rf "${tmp}"
}

main() {
  info "Running ${TEST_NAME} tests..."
  test_read_round_trips
  test_explicit_version_beats_describe
  test_explicit_version_has_no_dirty_suffix
  echo "All ${TEST_NAME} tests passed."
}

main "$@"
