#!/usr/bin/env bash
# Bash oracle for lib/catalogue.sh. Run on LINUX with LC_ALL=C:
#   LC_ALL=C oracle.sh > golden-catalogue.tsv
# One line per case in cases.tsv (see internal/genentries): "id rc stdout stderr cosign", each
# "=" + base64; cosign is the stub's argument log. <C> is the case directory. A validate, field or
# haskey case carries the entry's YAML as arg1; it is written to <C>/entry.yaml.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
us=$'\037'
b64() { printf '='; base64 -w0; }
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id op e1 e2 e3; do
  c="$T/$id"; mkdir -p "$c"
  (
    d() { local v; v="$(printf '%s' "${2#=}" | base64 -d; printf x)"; printf -v "$1" '%s' "${v%x}"; }
    d a1 "$e1"; d a2 "$e2"; d a3 "$e3"
    export HOME="$c" USER_SANDBOX_CONFIG="$c/none.yaml" BLOCKED_DESTINATIONS_CONFIG="$c/blocked.yaml" COSIGN_LOG="$c/.cosign"
    printf 'blocked_domains:\n  - evil.com\nblocked_cidrs:\n  - 10.0.0.0/8\n' > "$c/blocked.yaml"
    [[ "$op" == validate || "$op" == field || "$op" == haskey ]] && printf '%s' "$a1" > "$c/entry.yaml"
    unset SANDBOX_OVERLAY
    : > "$c/.cosign"
    export SANDBOX_ROOT="$c/root"; mkdir -p "$c/root"
    if [[ "$op" == resolve ]]; then
      for ((i = 0; i < ${#a1}; i++)); do
        case "${a1:i:1}" in
          O) mkdir -p "$c/root/config/catalogue"; echo 'kind: service' > "$c/root/config/catalogue/$a2.yaml" ;;
          V) mkdir -p "$c/ov/catalogue"; echo 'kind: mcp' > "$c/ov/catalogue/$a2.yaml"; export SANDBOX_OVERLAY="$c/ov" ;;
          d) mkdir -p "$c/ov" ;;
          E) export SANDBOX_OVERLAY="$c/ov" ;;
        esac
      done 2>/dev/null
    fi
    source "$root/lib/config.sh"; source "$root/lib/profile.sh"; source "$root/lib/checks.sh"; source "$root/lib/catalogue.sh"
    set +e +u
    case "$a2" in
      absent) PATH="/usr/bin:/bin" ;;
      ok)     PATH="$here/stub:/usr/bin:/bin"; export COSIGN_RC=0 ;;
      fail)   PATH="$here/stub:/usr/bin:/bin"; export COSIGN_RC=1 ;;
    esac
    case "$op" in
      name)     catalogue_is_valid_name "$a1" ;;
      resolve)  catalogue_resolve "$a2" ;;
      validate) catalogue_validate_entry "$c/entry.yaml" "$a3" ;;
      field)    catalogue_field "$c/entry.yaml" "$a2" "$a3" ;;
      haskey)   catalogue_has_key "$c/entry.yaml" "$a2" ;;
    esac > "$c/.out" 2> "$c/.err"
    rc=$?
    clean() { sed -e '/value too great for base/d' -e "s|$c|<C>|g" "$1" | b64; }
    printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$rc" "$(clean "$c/.out")" "$(clean "$c/.err")" "$(clean "$c/.cosign")"
  )
  rm -rf "$c"
done
