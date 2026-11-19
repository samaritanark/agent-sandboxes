#!/usr/bin/env bash
# Bash oracle for the vetting config helpers. Run on LINUX with LC_ALL=C:
#   LC_ALL=C oracle.sh > golden-config.txt
# Output: per case, one "name=value" line per function (multi-line values joined with '|', stderr
# WARN lines as "name.warn=..."); then the age and signer sections.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
"$here/setup.sh" "$T/fx"; fx="$T/fx"
export FAKE_NOW=1800000000 PATH="$here/shim:$PATH"
us=$'\037'
run() {  # name command...: print name=value and any WARN lines from stderr
  local name="$1"; shift
  local out err
  out="$("$@" 2>"$T/err")" ; err="$(grep '^WARN:' "$T/err" || true)"
  printf '%s=%s\n' "$name" "$(printf '%s' "$out" | tr '\n' '|')"
  [[ -n "$err" ]] && printf '%s.warn=%s\n' "$name" "$err"
  return 0
}
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id u o home; do
  (
    export HOME="$fx/home-$home"
    export USER_SANDBOX_CONFIG="$fx/uc/none.yaml"; [[ "$u" != - ]] && USER_SANDBOX_CONFIG="$fx/uc/$u.yaml"
    unset SANDBOX_OVERLAY; [[ "$o" != - ]] && export SANDBOX_OVERLAY="$fx/ov/$o"
    source "$root/lib/config.sh"; source "$root/lib/profile.sh"; source "$root/lib/vetting.sh"
    set +e +u
    printf '### %s\n' "$id"
    run posture resolve_vetting_posture
    run max_commits vetting_max_commits_behind
    run max_age vetting_max_age_days
    run require_head vetting_exceptions_require_head
    run clean_worktree vetting_require_clean_worktree
    run from_commit vetting_exceptions_from_commit
    run forbid_unvetted vetting_forbid_unvetted_override
    run trust_root vetting_trust_root
    run trust_roots vetting_trust_roots
    run trust_format vetting_trust_format
    run signing_key vetting_signing_key
  )
done | sed "s|$fx|<T>|g"
echo '### ages'
( source "$root/lib/config.sh"; source "$root/lib/profile.sh"; source "$root/lib/vetting.sh"; set +e +u
  for e in "" abc 0 00 010 1 1799999999 1800000000 1800000001 1700000000 1000000000 1.5 -1 18446744073709551616 9223372036854775807 9223372036854775808 1799913600 1799913601 1799827200; do
    printf '%s=%s\n' "[$e]" "$(_vetting_age_days "$e")"
  done )
echo '### signers'
( source "$root/lib/config.sh"; source "$root/lib/profile.sh"; source "$root/lib/vetting.sh"; set +e +u
  while IFS=$'\t' read -r f o; do
    printf '%s %s=%s\n' "$f" "$o" "$(_vetting_extract_signer "$(printf '%b' "$o")" "$f")"
  done < "$here/signer.tsv" )
