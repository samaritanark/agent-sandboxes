#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-upgrade.sh — 'sandbox upgrade' routing + app-phase logic.
# Cluster-free. Verifies: the app phase fast-forwards THIS checkout to the
# latest release tag (never a branch tip), refuses anything that isn't a clean
# fast-forward (dirty tree, divergence), no-ops when already current, targets a
# specific tag via --to, degrades to a warning when a signature can't be
# verified, and returns a soft failure (not a crash) on a non-git install; and
# that cmd_upgrade routes --app/--infra/components/--all correctly, including
# re-executing the freshly updated CLI for the infra phase after an app advance.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Source the CLI; the source-guard keeps main() from running. This defines
# cmd_upgrade, _upgrade_app_phase, _upgrade_infra_phase, warn, die, etc.
# shellcheck disable=SC1090
source "${SANDBOX_ROOT}/bin/sandbox" >/dev/null 2>&1

# Neutralize side-effecting helpers the app phase calls after a real advance.
stamp_version_if_git() { :; }
cmd_rebuild() { echo "[cmd_rebuild ran]"; }

contains() {
  local label="$1" haystack="$2" needle="$3"
  case "${haystack}" in
    *"${needle}"*) pass "${label}" ;;
    *) fail "${label}: '${needle}' not found in:"$'\n'"${haystack}" ;;
  esac
}
not_contains() {
  local label="$1" haystack="$2" needle="$3"
  case "${haystack}" in
    *"${needle}"*) fail "${label}: unexpected '${needle}' in:"$'\n'"${haystack}" ;;
    *) pass "${label}" ;;
  esac
}

# git with a fixed, hermetic identity and NO commit signing (so the environment's
# global commit.gpgsign doesn't make the run slow or non-deterministic).
tgit() {
  git -c user.name=t -c user.email=t@t -c commit.gpgsign=false \
      -c tag.gpgsign=false -c advice.detachedHead=false "$@"
}

# build_remote <dir> — a bare-ish source repo with three tagged releases on a
# linear history: v1.0.0 -> v1.1.0 -> v2.0.0.
build_remote() {
  local d="$1"
  rm -rf "${d}"; mkdir -p "${d}"; tgit -C "${d}" init -q
  echo one   > "${d}/f"; tgit -C "${d}" add .;      tgit -C "${d}" commit -qm c1; tgit -C "${d}" tag v1.0.0
  echo two   > "${d}/f"; tgit -C "${d}" commit -qam c2; tgit -C "${d}" tag v1.1.0
  echo three > "${d}/f"; tgit -C "${d}" commit -qam c3; tgit -C "${d}" tag v2.0.0
}

# clone_at <remote> <dst> <ref> — clone and check out a specific ref.
clone_at() {
  local remote="$1" dst="$2" ref="$3"
  rm -rf "${dst}"; tgit clone -q "${remote}" "${dst}"; tgit -C "${dst}" checkout -q "${ref}"
}

# run_app <root> <version> — drive _upgrade_app_phase with the cmd_upgrade
# locals it reads via dynamic scope, controllable through env: TO, REMOTE_NAME,
# DRY, YES, DO_INFRA, REBUILD. Prints the phase output plus a __RESULT__ trailer
# (rc + whether HEAD advanced). Run under command substitution so a die() inside
# only kills the substitution subshell, not the test.
run_app() {
  local root="$1" ver="$2"
  # These locals (and SANDBOX_VERSION) are read by _upgrade_app_phase via dynamic
  # scope, which shellcheck can't see across the call — hence the disable.
  # shellcheck disable=SC2034
  local to="${TO:-}" remote="${REMOTE_NAME:-origin}"
  # shellcheck disable=SC2034
  local do_rebuild="${REBUILD:-false}" dry_run="${DRY:-false}"
  # shellcheck disable=SC2034
  local assume_yes="${YES:-true}" do_infra="${DO_INFRA:-false}"
  local app_advanced=false rc=0
  # shellcheck disable=SC2034
  SANDBOX_ROOT="${root}" SANDBOX_VERSION="${ver}"
  _upgrade_app_phase </dev/null || rc=$?
  echo "__RESULT__ rc=${rc} advanced=${app_advanced}"
}

###############################################################################
# App phase — fast-forward semantics
###############################################################################
test_app_ff_to_latest() {
  info "Testing app phase fast-forwards to the latest release..."
  local tmp; tmp="$(mktemp -d "${TMPDIR:-/tmp}/sbx-upg-XXXXXX")"
  build_remote "${tmp}/remote"
  clone_at "${tmp}/remote" "${tmp}/co" v1.0.0

  # dry-run: picks the newest tag, changes nothing.
  local out; out="$(DRY=true run_app "${tmp}/co" v1.0.0 2>&1)" || true
  contains "dry-run targets newest tag v2.0.0" "${out}" "Target:  v2.0.0"
  contains "dry-run makes no changes"          "${out}" "(dry run"
  contains "dry-run leaves HEAD put"           "$(tgit -C "${tmp}/co" describe --tags)" "v1.0.0"

  # real apply: fast-forwards and reports it advanced.
  out="$(run_app "${tmp}/co" v1.0.0 2>&1)" || true
  contains "apply reports update"   "${out}" "Updated app to v2.0.0"
  contains "apply set advanced=true" "${out}" "advanced=true"
  contains "HEAD moved to v2.0.0"    "$(tgit -C "${tmp}/co" describe --tags)" "v2.0.0"
  rm -rf "${tmp}"
}

test_app_already_current() {
  info "Testing app phase is a no-op when already at latest..."
  local tmp; tmp="$(mktemp -d "${TMPDIR:-/tmp}/sbx-upg-XXXXXX")"
  build_remote "${tmp}/remote"
  clone_at "${tmp}/remote" "${tmp}/co" v2.0.0
  local out; out="$(run_app "${tmp}/co" v2.0.0 2>&1)" || true
  contains "already-current message"     "${out}" "Already at v2.0.0. Nothing to do."
  contains "already-current not advanced" "${out}" "advanced=false"
  rm -rf "${tmp}"
}

test_app_to_specific_tag() {
  info "Testing app phase honors --to <tag>..."
  local tmp; tmp="$(mktemp -d "${TMPDIR:-/tmp}/sbx-upg-XXXXXX")"
  build_remote "${tmp}/remote"
  clone_at "${tmp}/remote" "${tmp}/co" v1.0.0
  local out; out="$(TO=v1.1.0 run_app "${tmp}/co" v1.0.0 2>&1)" || true
  contains "--to picks v1.1.0 not latest" "${out}" "Updated app to v1.1.0"
  contains "HEAD moved to v1.1.0"          "$(tgit -C "${tmp}/co" describe --tags)" "v1.1.0"
  rm -rf "${tmp}"
}

test_app_refuses_divergence() {
  info "Testing app phase refuses a non-fast-forward (diverged checkout)..."
  local tmp; tmp="$(mktemp -d "${TMPDIR:-/tmp}/sbx-upg-XXXXXX")"
  build_remote "${tmp}/remote"
  clone_at "${tmp}/remote" "${tmp}/co" v1.0.0
  tgit -C "${tmp}/co" checkout -q -b local-work
  echo local > "${tmp}/co/local"; tgit -C "${tmp}/co" add .; tgit -C "${tmp}/co" commit -qm "local work"
  local out; out="$(run_app "${tmp}/co" v1.0.0 2>&1)" || true
  contains "diverged is refused"     "${out}" "diverged"
  # HEAD must be untouched (still the local commit, not v2.0.0).
  local head; head="$(tgit -C "${tmp}/co" rev-parse HEAD)"
  local tgt;  tgt="$(tgit -C "${tmp}/co" rev-parse v2.0.0)"
  [[ "${head}" != "${tgt}" ]] && pass "diverged HEAD left untouched" \
    || fail "diverged HEAD was moved to the release"
  rm -rf "${tmp}"
}

test_app_refuses_dirty() {
  info "Testing app phase refuses a dirty working tree..."
  local tmp; tmp="$(mktemp -d "${TMPDIR:-/tmp}/sbx-upg-XXXXXX")"
  build_remote "${tmp}/remote"
  clone_at "${tmp}/remote" "${tmp}/co" v1.0.0
  echo dirty > "${tmp}/co/f"        # uncommitted edit to a tracked file
  local out; out="$(run_app "${tmp}/co" v1.0.0 2>&1)" || true
  contains "dirty tree is refused" "${out}" "uncommitted changes"
  contains "HEAD still at v1.0.0"  "$(tgit -C "${tmp}/co" describe --tags --dirty)" "v1.0.0"

  # --dry-run stays a read-only preview even on a dirty tree (guard is a mutation
  # guard, checked after the dry-run return — mirrors the infra phase).
  out="$(DRY=true run_app "${tmp}/co" v1.0.0 2>&1)" || true
  contains "dry-run previews despite dirty tree" "${out}" "Target:  v2.0.0"
  not_contains "dry-run doesn't trip the dirty guard" "${out}" "uncommitted changes"
  rm -rf "${tmp}"
}

test_app_warns_unverifiable() {
  info "Testing app phase warns (not fails) when a signature can't be verified..."
  local tmp; tmp="$(mktemp -d "${TMPDIR:-/tmp}/sbx-upg-XXXXXX")"
  build_remote "${tmp}/remote"     # commits are unsigned (tgit disables signing)
  clone_at "${tmp}/remote" "${tmp}/co" v1.0.0
  local out; out="$(DRY=true run_app "${tmp}/co" v1.0.0 2>&1)" || true
  contains "unverifiable signature warns"  "${out}" "Could not verify"
  contains "warned run still proceeds"     "${out}" "(dry run"
  rm -rf "${tmp}"
}

test_app_nongit_soft_fail() {
  info "Testing app phase soft-fails (rc=2) on a non-git install..."
  local tmp; tmp="$(mktemp -d "${TMPDIR:-/tmp}/sbx-upg-XXXXXX")"
  mkdir -p "${tmp}/plain"

  # App-only: point the operator at the download page and the infra-only path.
  local out; out="$(DO_INFRA=false run_app "${tmp}/plain" dev 2>&1)" || true
  contains "non-git returns rc=2"          "${out}" "rc=2"
  contains "non-git names the release page" "${out}" "releases/latest"
  contains "non-git app-only suggests --infra" "${out}" "sandbox upgrade --infra"

  # With infra queued, note it will still run rather than suggesting it.
  out="$(DO_INFRA=true run_app "${tmp}/plain" dev 2>&1)" || true
  contains "non-git with infra queued continues" "${out}" "still be upgraded"
  rm -rf "${tmp}"
}

###############################################################################
# cmd_upgrade — routing between the app and infra phases
###############################################################################
# Each routing case runs in a subshell with the two phases and `exec` stubbed,
# so we observe which phase runs and what the --all re-exec would launch without
# touching git, the cluster, or the process image.
route() {
  shift  # drop the human-readable label; the rest are cmd_upgrade args
  (
    _upgrade_app_phase() {
      echo "APP"
      case "${APP_SIM:-advanced}" in
        advanced) app_advanced=true ;;
        current)  app_advanced=false ;;
        nongit)   app_advanced=false; return 2 ;;
      esac
    }
    # Reads cmd_upgrade's locals via dynamic scope (invisible to shellcheck).
    # shellcheck disable=SC2154
    _upgrade_infra_phase() { echo "INFRA k3s=${do_k3s} cilium=${do_cilium} gvisor=${do_gvisor} to_cilium='${to_cilium}' force=${force} yes=${assume_yes}"; }
    # Real exec() replaces the process and never returns; mimic that with exit
    # so any (unreachable in production) code after the exec call doesn't run.
    # shellcheck disable=SC2317
    exec() { echo "EXEC: $*"; exit 0; }
    cmd_upgrade "$@" 2>&1 || true
  )
}

test_route_default_is_app() {
  info "Testing default (no flags) and --app route to the app phase only..."
  local out
  out="$(route 'default' )";      contains "default runs app"       "${out}" "APP"; not_contains "default skips infra" "${out}" "INFRA"
  out="$(route '--app' --app)";   contains "--app runs app"          "${out}" "APP"; not_contains "--app skips infra"  "${out}" "INFRA"
}

test_route_infra_and_components() {
  info "Testing --infra and component flags route to the infra phase only..."
  local out
  out="$(route '--infra' --infra)"
  contains "--infra runs infra (all three)" "${out}" "INFRA k3s=true cilium=true gvisor=true"
  not_contains "--infra skips app" "${out}" "APP"

  out="$(route '--k3s' --k3s)"
  contains "--k3s selects only k3s" "${out}" "INFRA k3s=true cilium=false gvisor=false"

  out="$(route '--cilium --gvisor' --cilium --gvisor)"
  contains "--cilium --gvisor selects those two" "${out}" "INFRA k3s=false cilium=true gvisor=true"
}

test_route_all_reexecs_after_advance() {
  info "Testing --all updates the app, then re-execs the CLI for infra..."
  local out
  out="$(APP_SIM=advanced route '--all' --all)"
  contains "--all runs app first"          "${out}" "APP"
  contains "--all re-execs for infra"      "${out}" "upgrade --k3s --cilium --gvisor"
  not_contains "--all does not run infra in-process after advance" "${out}" "INFRA k3s="

  # Passthru: infra-relevant flags survive the re-exec; --app-only flags don't.
  out="$(APP_SIM=advanced route '--all passthru' --all --force -y --to-cilium 1.16)"
  contains "re-exec carries the component + override + guards" \
    "${out}" "upgrade --k3s --cilium --gvisor --to-cilium 1.16 --force -y"
}

test_route_all_no_reexec_when_unchanged() {
  info "Testing --all runs infra in-process when the app didn't advance..."
  local out
  # Already current: code unchanged, so infra runs in-process (no re-exec).
  out="$(APP_SIM=current route '--all current' --all)"
  contains "--all/current runs app"        "${out}" "APP"
  contains "--all/current runs infra in-process" "${out}" "INFRA k3s=true cilium=true gvisor=true"
  not_contains "--all/current does not re-exec" "${out}" "EXEC:"

  # Non-git (tarball): app can't self-update but infra still runs in-process.
  out="$(APP_SIM=nongit route '--all nongit' --all)"
  contains "--all/nongit still runs infra" "${out}" "INFRA k3s=true"
  not_contains "--all/nongit does not re-exec" "${out}" "EXEC:"
}

test_app_ff_to_latest
test_app_already_current
test_app_to_specific_tag
test_app_refuses_divergence
test_app_refuses_dirty
test_app_warns_unverifiable
test_app_nongit_soft_fail
test_route_default_is_app
test_route_infra_and_components
test_route_all_reexecs_after_advance
test_route_all_no_reexec_when_unchanged

echo "All upgrade tests passed."
