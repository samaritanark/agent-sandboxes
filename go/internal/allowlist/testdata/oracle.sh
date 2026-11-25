#!/usr/bin/env bash
# Bash oracle for the domain set of build_cilium_policy (lib/policy.sh). Run on LINUX with LC_ALL=C:
#   LC_ALL=C oracle.sh > golden-allowlist.tsv
# One line per case in cases.tsv (see internal/genallowlist): "id rc stdout stderr", stdout and
# stderr as "=" + base64. indent_fqdn_entry is replaced so each rendered entry prints as one marked
# line; stdout is those entries, in order. Layout keys as in the checks corpus; o=REAL is the
# install's own config/blocked-destinations.yaml, o=- a missing one.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
fx="$root/go/internal/checks/testdata/fx"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
us=$'\037'
b64() { printf '='; base64 -w0; }
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id agent tier layout eextras; do
  c="$T/$id"; mkdir -p "$c"
  (
    extras=()
    while IFS= read -r -d '' a; do extras+=("$a"); done < <(printf '%s' "${eextras#=}" | base64 -d)
    export HOME="$c" SANDBOX_ROOT="$root" USER_SANDBOX_CONFIG="$c/none.yaml" BLOCKED_DESTINATIONS_CONFIG="$c/missing.yaml"
    export OPENCODE_BASE_URL="https://llm.example.org/v1"
    unset SANDBOX_OVERLAY
    IFS=, read -ra parts <<<"$layout"
    for p in "${parts[@]}"; do
      k="${p%%=*}" v="${p#*=}"; [[ "$v" == - || "$k" == "$p" ]] && continue
      case "$k" in
        o) if [[ "$v" == REAL ]]; then BLOCKED_DESTINATIONS_CONFIG="$root/config/blocked-destinations.yaml"
           else BLOCKED_DESTINATIONS_CONFIG="$fx/$v"; fi ;;
        u) USER_SANDBOX_CONFIG="$fx/$v" ;;
        b) mkdir -p "$c/ov"; cp "$fx/$v" "$c/ov/blocked-destinations.yaml"; export SANDBOX_OVERLAY="$c/ov" ;;
      esac
    done
    for l in platform config profile checks agents tier policy; do source "$root/lib/$l.sh"; done
    indent_fqdn_entry() { printf '@@FQDN@@%s\n' "$1"; }
    set +e +u
    ( build_cilium_policy ses-1 "$agent" "$tier" "" "" "${extras[@]+"${extras[@]}"}" ) > "$c/.pol" 2> "$c/.err"
    rc=$?
    sed -n 's/^@@FQDN@@//p' "$c/.pol" > "$c/.out"
    printf '%s\t%s\t%s\t%s\n' "$id" "$rc" "$(b64 < "$c/.out")" "$(sed "s|$c|<C>|g" "$c/.err" | b64)"
  )
  rm -rf "$c"
done
