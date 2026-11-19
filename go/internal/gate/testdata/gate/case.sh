#!/usr/bin/env bash
# Runs ONE secret_gate_repos case with mocked vetting/audit and the stub scanner. All inputs come
# from the environment (set by oracle.sh): FX ROOT CASE_* LOG META.
set -u
export HOME="$FX/home" TMPDIR="$FX/tmp" LEAKSCAN_CACHE_DIR="$FX/cache" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export USER_SANDBOX_CONFIG="$FX/uc/none.yaml"; unset SANDBOX_OVERLAY
export STUB_ROOT="$FX" STUB_LOG="$FX/log/stub-$CASE_ID" STUB_SCEN="$SCEN"
[[ "$CASE_PATH" == stub ]] && export PATH="$STUB_DIR:$PATH"
: > "$STUB_LOG"
source "$ROOT/lib/config.sh"; source "$ROOT/lib/profile.sh"; source "$ROOT/lib/platform.sh"; source "$ROOT/lib/filesystem.sh"
# mocks for the modules that are not part of the gate
vetted_accepted_fingerprints() { echo "vaf $(basename "$1") $2" >> "$LOG"; [[ "$CASE_ACCFIX" != - ]] && cat "$FX/acc/$CASE_ACCFIX"; return 0; }
vetting_exceptions_from_commit() { echo "$CASE_VEC"; }
record_override() { { printf 'override'; printf ' [%s]' "$@"; echo; } >> "$LOG"; }
load_repo_accepted_secrets() { case "$CASE_LEGACY" in yes) echo 'x:y:1:h' ;; nl) printf '\n\n' ;; esac; }
warn() { echo "warn $*" >> "$LOG"; }
trap 'rc=$?; printf "rc=%s\nsummary=%s\n" "$rc" "${SESSION_SECRET_SUMMARY-}" > "$META"' EXIT
SESSION_SECRET_SUMMARY=""
repos=(); if [[ "$CASE_REPOS" != - ]]; then IFS=, read -ra names <<< "$CASE_REPOS"; for n in "${names[@]}"; do repos+=("$FX/$n"); done; fi
set +e
secret_gate_repos "$CASE_ACCEPT" "$CASE_TRUSTED" "$CASE_UNVETTED" "${repos[@]+"${repos[@]}"}"
