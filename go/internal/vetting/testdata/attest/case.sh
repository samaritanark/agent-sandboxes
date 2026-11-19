#!/usr/bin/env bash
# Runs ONE attestation case in $RUN against the template copy. Inputs: CASE_* env set by oracle.sh.
set -u
export HOME="$RUN/home" USER_SANDBOX_CONFIG="$RUN/uc.yaml" GIT_COMMITTER_DATE="@1800000000 +0000"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
[[ "$CASE_FUNC" == assist ]] && export GIT_CONFIG_GLOBAL="$HOME/.gitconfig"
export STUB_ROOT="$FX" STUB_LOG="$FX/stub.log" STUB_SCEN="$SCEN" LC_ALL=C.UTF-8
[[ "$CASE_PATH" == stub ]] && export PATH="$STUB_DIR:$PATH"
unset SANDBOX_OVERLAY SSH_AUTH_SOCK
source "$ROOT/lib/config.sh"; source "$ROOT/lib/profile.sh"; source "$ROOT/lib/platform.sh"; source "$ROOT/lib/filesystem.sh"; source "$ROOT/lib/vetting.sh"
warn() { echo "warn $*" >> "$LOG"; }
trap 'echo "rc=$?" > "$META"' EXIT
set +e
repo="$RUN/$CASE_REPO"
case "$CASE_FUNC" in
  attest) if [[ "$CASE_MSG" == NONE ]]; then vetting_attest_repo "$repo"; elif [[ "$CASE_MSG" == - ]]; then vetting_attest_repo "$repo" "" "$CASE_YES"; else vetting_attest_repo "$repo" "$CASE_MSG" "$CASE_YES"; fi ;;
  ack)    real="$(cd "$repo" 2>/dev/null && pwd -P)"; _vetting_acknowledge_exceptions "$real" "$repo" "$CASE_YES" ;;
  inline) head="$(git -C "$repo" rev-parse HEAD 2>/dev/null)"; _vetting_inline_attest "$repo" "$head" ;;
  assist) vetting_signing_setup_assist "$repo" ;;
esac
