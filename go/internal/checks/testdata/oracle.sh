#!/usr/bin/env bash
# Bash oracle for lib/checks.sh. Run on LINUX with LC_ALL=C:
#   LC_ALL=C oracle.sh > golden-checks.tsv
# One line per case in cases.tsv (see internal/genchecks): "id rc stdout stderr", stdout and
# stderr as "=" + base64; the fixture directory prints as <FX>, the case directory as <C>. A check
# that refuses calls exit, so each runs in a subshell.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
us=$'\037'
b64() { printf '='; base64 -w0; }
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id op layout e1 e2; do
  c="$T/$id"; mkdir -p "$c"
  (
    d() { local v; v="$(printf '%s' "${2#=}" | base64 -d; printf x)"; printf -v "$1" '%s' "${v%x}"; }
    d a1 "$e1"; d a2 "$e2"
    export HOME="$c" SANDBOX_ROOT="$root" USER_SANDBOX_CONFIG="$c/none.yaml" BLOCKED_DESTINATIONS_CONFIG="$c/missing.yaml"
    unset SANDBOX_OVERLAY
    IFS=, read -ra parts <<<"$layout"
    for p in "${parts[@]}"; do
      k="${p%%=*}" v="${p#*=}"; [[ "$v" == - || "$k" == "$p" ]] && continue
      case "$k" in
        o) BLOCKED_DESTINATIONS_CONFIG="$here/fx/$v" ;;
        u) USER_SANDBOX_CONFIG="$here/fx/$v" ;;
        b) mkdir -p "$c/ov"; cp "$here/fx/$v" "$c/ov/blocked-destinations.yaml"; export SANDBOX_OVERLAY="$c/ov" ;;
        c) mkdir -p "$c/ov"; cp "$here/fx/$v" "$c/ov/config.yaml"; export SANDBOX_OVERLAY="$c/ov" ;;
      esac
    done
    source "$root/lib/config.sh"; source "$root/lib/profile.sh"; source "$root/lib/checks.sh"
    set +e +u
    case "$op" in
      norm)   _normalize_domain "$a1" ;;
      match)  _domain_matches_block_pattern "$a1" "$a2" ;;
      cdnb)   ( check_domain_not_blocked "$a1" ) ;;
      dib)    domain_is_blocked "$a1" ;;
      gbc)    get_blocked_cidrs ;;
      vcidr)  validate_cidr "$a1" ;;
      cbcv)   ( check_blocked_cidrs_valid ) ;;
      ip4)    _is_ipv4_literal "$a1" ;;
      ip2int) _ipv4_to_int "$a1" ;;
      iic)    ip_in_cidr "$a1" "$a2" ;;
      cinb)   ( check_ip_not_in_blocked_cidrs "$a1" ) ;;
      mps)    _is_multilabel_public_suffix "$a1" ;;
      apex)   _apex_is_registrable_domain "$a1" ;;
      wtb)    _egress_wildcard_too_broad "$a1" ;;
      cetnb)  ( check_egress_target_not_blocked "$a1" ) ;;
      iet)    inference_endpoint_is_trusted "$a1" ;;
    esac > "$c/.out" 2> "$c/.err"
    rc=$?
    # bash's own arithmetic error for an octal-invalid prefix (/08) is interpreter noise, not the
    # check's output; its effect (not inside) is in the return code
    clean() { sed -e '/value too great for base/d' -e "s|$here/fx|<FX>|g" -e "s|$c|<C>|g" "$1" | b64; }
    printf '%s\t%s\t%s\t%s\n' "$id" "$rc" "$(clean "$c/.out")" "$(clean "$c/.err")"
  )
  rm -rf "$c"
done
