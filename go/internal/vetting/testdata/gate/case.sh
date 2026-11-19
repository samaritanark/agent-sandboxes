#!/usr/bin/env bash
# Runs ONE vetting_gate_repos case with a scripted vetting_status_repo and configuration, mocked
# audit/attest, and the real _vetting_age_days (clock shimmed by FAKE_NOW). Inputs: CASE_* env.
set -u
export PATH="$SHIM:$PATH" FAKE_NOW=1800000000 HOME="$FX/home"
export USER_SANDBOX_CONFIG="$FX/none.yaml"; unset SANDBOX_OVERLAY
source "$ROOT/lib/config.sh"; source "$ROOT/lib/profile.sh"; source "$ROOT/lib/platform.sh"; source "$ROOT/lib/vetting.sh"
vetting_status_repo() { cat "$SCEN/$(basename "$1")" 2>/dev/null; }
vetting_trust_roots() { [[ "$CASE_ROOTS" == some ]] && { echo /trust/a; echo /trust/b; }; return 0; }
vetting_trust_root() { echo /trust/default; }
vetting_forbid_unvetted_override() { echo "$CASE_FORBID"; }
vetting_max_commits_behind() { [[ "$CASE_CAP" != - ]] && echo "$CASE_CAP"; return 0; }
vetting_max_age_days() { [[ "$CASE_AGECAP" != - ]] && echo "$CASE_AGECAP"; return 0; }
record_override() { { printf 'override'; printf ' [%s]' "$@"; echo; } >> "$LOG"; }
_in_list() { local x="$1" l=",$2,"; [[ "$l" == *",$x,"* ]]; }
_vetting_signing_configured() { echo "signing? $(basename "$1")" >> "$LOG"; _in_list "$(basename "$1")" "$CASE_SIGN"; }
_vetting_inline_attest() { echo "attest $(basename "$1") $2" >> "$LOG"; _in_list "$(basename "$1")" "$CASE_ATTEST"; }
trap 'rc=$?; printf "rc=%s\nsummary=%s\n" "$rc" "${SESSION_VETTING_SUMMARY-}" > "$META"' EXIT
SESSION_VETTING_SUMMARY=""
repos=(); IFS=, read -ra names <<< "$CASE_REPOS"; for n in "${names[@]}"; do repos+=("/work/$n"); done
posture="$CASE_POSTURE"; [[ "$posture" == EMPTY ]] && posture=""
acc="$CASE_ACCEPT"; [[ "$acc" == EMPTY ]] && acc=""
set +e
vetting_gate_repos "$posture" "$acc" "$CASE_DRIFT" "${repos[@]}"
