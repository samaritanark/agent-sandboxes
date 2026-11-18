#!/usr/bin/env bash
# Bash oracle for scan_repo_secrets. Run on LINUX with LC_ALL=C:  LC_ALL=C oracle.sh > golden-scan.tsv
# Reads cases.tsv: id repo overlay usercfg accept scenario  ("-" = unset/empty).
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
"$here/setup.sh" "$T/fx"
fx="$T/fx"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
us=$'\037'
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id repo ov uc acc scen; do
  (
    export HOME="$fx/home" TMPDIR="$fx/tmp" LEAKSCAN_CACHE_DIR="$fx/cache" PATH="$here/stub:$PATH"
    export USER_SANDBOX_CONFIG="$fx/uc/none.yaml"; [[ "$uc" != "-" ]] && USER_SANDBOX_CONFIG="$fx/uc/$uc.yaml"
    unset SANDBOX_OVERLAY; [[ "$ov" != "-" ]] && export SANDBOX_OVERLAY="$fx/ov/$ov"
    export STUB_ROOT="$fx" STUB_LOG="$fx/log/$id" STUB_SCEN="$here/scen/$scen"
    : > "$STUB_LOG"
    source "$root/lib/config.sh"; source "$root/lib/profile.sh"; source "$root/lib/filesystem.sh"
    set +e +u
    a=""; [[ "$acc" != "-" ]] && a="$fx/acc/$acc"
    printf '### %s\n' "$id"
    scan_repo_secrets "$fx/$repo" "$a" 2>/dev/null
    printf -- '--- stub\n'
    cat "$STUB_LOG"
  )
done | sed "s|$T/fx|<T>|g"
