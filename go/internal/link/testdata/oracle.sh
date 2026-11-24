#!/usr/bin/env bash
# Bash oracle for lib/link.sh. Run on LINUX with LC_ALL=C:
#   LC_ALL=C oracle.sh > golden-link.tsv
# Each case in cases.tsv is "id op arg1 arg2 arg3" ("=" + base64 each; see internal/genlink).
# Output: "id rc stdout stderr userconfig head", "=" + base64 each ("-" when absent); the case
# directory prints as <C>. An overlay tree (validate) is a spec of lines "f path content",
# "d path" or "l path target" (base64 words) built under <C>/ov.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
umask 022
us=$'\037'
b64() { printf '='; base64 -w0; }
dec() { local _dv; _dv="$(printf '%s' "${2#=}" | base64 -d; printf x)"; printf -v "$1" '%s' "${_dv%x}"; }
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id op e1 e2 e3; do
  c="$T/$id"; mkdir -p "$c/home"
  (
    dec a1 "$e1"; dec a2 "$e2"; dec a3 "$e3"
    export HOME="$c/home" USER_SANDBOX_CONFIG="$c/home/.sandbox/config.yaml" LINK_OVERLAYS_DIR="$c/home/.sandbox/overlays"
    export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
    unset SANDBOX_OVERLAY SANDBOX_NO_LINK_CHECK SANDBOX_VERSION
    case "$op" in
      validate)
        mkdir -p "$c/ov"
        while IFS= read -r line; do
          read -ra w <<<"$line"; [[ ${#w[@]} -gt 0 ]] || continue
          dec k "${w[0]}"; dec p "${w[1]}"; t=""; [[ ${#w[@]} -gt 2 ]] && dec t "${w[2]}"
          case "$k" in
            f) mkdir -p "$(dirname "$c/ov/$p")"; printf '%s' "$t" > "$c/ov/$p" ;;
            d) mkdir -p "$c/ov/$p" ;;
            l) mkdir -p "$(dirname "$c/ov/$p")"; ln -s "$t" "$c/ov/$p" ;;
          esac
        done <<<"$a1" ;;
      wcfg|ccfg|active) mkdir -p "$c/home/.sandbox"; [[ "$a1" != $'\x01' ]] && printf '%s' "$a1" > "$USER_SANDBOX_CONFIG"
        if [[ "$op" == active && "$a2" == file:* ]]; then mkdir -p "$(dirname "$c/home/${a2#file:}")"; : > "$c/home/${a2#file:}"
        elif [[ "$op" == active && -n "$a2" ]]; then mkdir -p "$c/home/$a2"; fi ;;
      sync) "$here/setup-sync.sh" "$a1" "$c" >/dev/null 2>&1
        [[ "$a1" == no-check ]] && export SANDBOX_NO_LINK_CHECK=1
        [[ -n "$a2" ]] && export SANDBOX_VERSION="$a2" ;;
    esac
    source "$root/lib/config.sh"; source "$root/lib/profile.sh"; source "$root/lib/platform.sh"; source "$root/lib/link.sh"
    set +e +u
    warn() { echo "WARN: $*" >&2; }
    die() { echo "DIE: $*" >&2; exit 1; }
    case "$op" in
      name)     link_is_valid_name "$a1" ;;
      fromurl)  link_name_from_url "$a1" ;;
      norm)     HOME="$a1"; _link_normalize_path "$a2" ;;
      sens)     HOME="$a1"; _link_default_repo_is_sensitive "$a2" ;;
      validate) link_validate_shape "$c/ov" ;;
      wcfg)     link_write_config "$a2" "u-$a3" "r-$a3" "c-$a3" ;;
      ccfg)     link_clear_config "${a2//<HOME>/$HOME}" ;;
      active)   link_active_dir; echo "active=$(link_is_active && echo yes || echo no) url=$(link_url_config) ref=$(link_ref_config) commit=$(link_commit_config)" ;;
      sync)     ( link_sync_on_run ) ;;
    esac > "$c/.out" 2> "$c/.err"
    rc=$?
    clean() { sed "s|$c|<C>|g" "$1" | b64; }
    uc=-; [[ -f "$USER_SANDBOX_CONFIG" ]] && uc="$(clean "$USER_SANDBOX_CONFIG")"
    hd=-; [[ "$op" == sync ]] && hd="=$(git -C "$c/home/.sandbox/overlays/team" rev-parse HEAD 2>/dev/null | base64 -w0)"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$rc" "$(clean "$c/.out")" "$(clean "$c/.err")" "$uc" "$hd"
  )
  rm -rf "$c"
done
