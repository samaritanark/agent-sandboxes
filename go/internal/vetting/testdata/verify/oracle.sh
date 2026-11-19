#!/usr/bin/env bash
# Bash oracle for vetting_status_repo. Run on LINUX with LC_ALL=C.UTF-8:
#   LC_ALL=C.UTF-8 oracle.sh > golden-verify.txt
# Per case: the status line, then the marker files that exist afterwards (a marker means a program
# named by the untrusted workspace's config was executed).
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
"$here/setup.sh" "$T/fx"; fx="$T/fx"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
us=$'\037'
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id repo uc ov home; do
  (
    export HOME="$fx/home-$home" USER_SANDBOX_CONFIG="$fx/$uc.yaml"
    unset SANDBOX_OVERLAY; [[ "$ov" != - ]] && export SANDBOX_OVERLAY="$fx/ov/$ov"
    source "$root/lib/config.sh"; source "$root/lib/profile.sh"; source "$root/lib/platform.sh"; source "$root/lib/vetting.sh"
    set +e +u
    rm -f "$fx"/markers/*
    printf '### %s\n' "$id"
    if [[ "$repo" == REL:* ]]; then cd "$fx" && vetting_status_repo "${repo#REL:}"; else vetting_status_repo "$fx/$repo"; fi
    printf 'markers=%s\n' "$(ls "$fx/markers" | tr '\n' ' ')"
  )
done | sed "s|$fx|<T>|g"
