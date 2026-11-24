#!/usr/bin/env bash
# Bash oracle for lib/profile.sh and version_ge (lib/platform.sh). Run on LINUX with LC_ALL=C:
#   LC_ALL=C oracle.sh > golden-profile.tsv
# One line per case in cases.tsv (see internal/genprofile): "id rc stdout stderr", stdout and
# stderr as "=" + base64, the case directory printed as <C>. An arg of a single NUL byte means
# "absent" (no config file; SANDBOX_VERSION unset).
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
umask 022
us=$'\037'
b64() { printf '='; base64 -w0; }
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id op e1 e2 e3 e4 e5; do
  c="$T/$id"; mkdir -p "$c"
  (
    # decode each arg; "absent" (one NUL byte) cannot live in a bash string, so test the base64
    absent() { [[ "$1" == "=AA==" ]]; }
    d() {  # d VAR ENCODED: decode into VAR, keeping trailing newlines
      local v=""; absent "$2" || { v="$(printf '%s' "${2#=}" | base64 -d; printf x)"; v="${v%x}"; }
      printf -v "$1" '%s' "$v"
    }
    d a1 "$e1"; d a2 "$e2"; d a3 "$e3"; d a4 "$e4"; d a5 "$e5"
    export HOME="$c/a/b/home" USER_SANDBOX_CONFIG="$c/a/b/home/none.yaml"
    unset SANDBOX_OVERLAY SANDBOX_VERSION
    mkdir -p "$HOME"
    warn() { echo "WARN: $*" >&2; }
    layout() {  # $1 = layout, $2 = profile name
      local l="$1" nm="$2" ov="$HOME/ov" i
      for ((i = 0; i < ${#l}; i++)); do
        case "${l:i:1}" in
          E) export SANDBOX_OVERLAY="$ov" ;;
          C) printf 'overlay: %s\n' "$ov" > "$HOME/uc.yaml"; USER_SANDBOX_CONFIG="$HOME/uc.yaml" ;;
          T) printf 'overlay: ~/ov\n' > "$HOME/uc.yaml"; USER_SANDBOX_CONFIG="$HOME/uc.yaml" ;;
          U) mkdir -p "$(dirname "$HOME/.sandbox/profiles/$nm.yaml")"; echo 'tier: 1' > "$HOME/.sandbox/profiles/$nm.yaml" ;;
          u) mkdir -p "$HOME/.sandbox/profiles/$nm.yaml" ;;
          O) mkdir -p "$(dirname "$ov/profiles/$nm.yaml")"; echo 'tier: 2' > "$ov/profiles/$nm.yaml" ;;
          o) mkdir -p "$ov/profiles/$nm.yaml" ;;
          B) mkdir -p "$ov"; echo 'blocked_domains: []' > "$ov/blocked-destinations.yaml" ;;
          b) mkdir -p "$ov/blocked-destinations.yaml" ;;
        esac
      done
    }
    case "$op" in  # set-up (its errors are not part of the answer)
      find)   layout "$a1" "$a2" ;;
      obdf)   layout "$a1" x ;;
      minver) mkdir -p "$c/ov"; absent "$e1" || printf '%s' "$a1" > "$c/ov/config.yaml"
              absent "$e2" || export SANDBOX_VERSION="$a2" ;;
    esac 2>/dev/null
    source "$root/lib/config.sh"; source "$root/lib/profile.sh"; source "$root/lib/platform.sh"
    set +e +u
    case "$op" in
      valid)   is_valid_profile_name "$a1" ;;
      numeric) is_numeric_profile "$a1" ;;
      find)    find_profile_path "$a2" ;;
      obdf)    overlay_blocked_destinations_file ;;
      minver)  overlay_min_version_unmet "$c/ov" ;;
      vge)     version_ge "$a1" "$a2" ;;
      render)  printf '%s' "$a5" | render_profile_yaml "$a1" "$a2" "$a3" "$a4" ;;
      upd)     user_profiles_dir ;;
    esac > "$c/.out" 2> "$c/.err"
    rc=$?
    printf '%s\t%s\t%s\t%s\n' "$id" "$rc" "$(sed "s|$c|<C>|g" "$c/.out" | b64)" "$(sed "s|$c|<C>|g" "$c/.err" | b64)"
  )
  rm -rf "$c"
done
