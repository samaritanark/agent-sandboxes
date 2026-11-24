#!/usr/bin/env bash
# Bash oracle for the lib/config.sh writers and remaining readers. Run on LINUX with LC_ALL=C:
#   LC_ALL=C oracle.sh > golden-write.tsv
# One line per case in cases.tsv (see internal/genwrite):
#   id  rc  stdout  file  mode
# stdout and file are "=" + base64 (file is the written file's bytes, "-" if it does not exist);
# mode is its permission bits, or "-". The case directory is printed as <C>. umask is 022.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
umask 022
us=$'\037'
b64() { printf '='; base64 -w0; }
dec() { printf '%s' "${1#=}" | base64 -d; }
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id op fx mode a1 a2; do
  c="$T/$id"; mkdir -p "$c"
  (
    a1="$(dec "$a1"; printf x)"; a1="${a1%x}"
    a2="$(dec "$a2"; printf x)"; a2="${a2%x}"
    export HOME="$c" USER_SANDBOX_CONFIG="$c/none.yaml"; unset SANDBOX_OVERLAY SANDBOX_EXTRA_ALLOWED_DOMAINS
    put() { [[ "$fx" == - ]] && return 0; mkdir -p "$(dirname "$1")"; cp "$here/fx/$fx" "$1"; chmod "$mode" "$1"; }
    target=-
    case "$op" in
      rmscalar|rmlist) target="$c/f.yaml"; put "$target" ;;
      addmask)         target="$c/r/.sandbox/config.yaml"; put "$target" ;;
      addfp)           target="$c/ign"; put "$target" ;;
      ignfile)
        mkdir -p "$c/r"
        for ((i = 0; i < ${#a1}; i++)); do
          case "${a1:i:1}" in
            B) cp "$here/fx/$fx" "$c/r/.betterleaksignore" ;; b) mkdir "$c/r/.betterleaksignore" ;;
            G) cp "$here/fx/$fx" "$c/r/.gitleaksignore" ;;    g) mkdir "$c/r/.gitleaksignore" ;;
          esac
        done ;;
      honor)
        mkdir -p "$c/ov"; [[ "$fx" != - ]] && cp "$here/fx/$fx" "$c/ov/config.yaml"
        case "$a1" in
          env)        export SANDBOX_OVERLAY="$c/ov" ;;
          env-empty)  export SANDBOX_OVERLAY=""; printf 'overlay: %s\n' "$c/ov" > "$c/uc.yaml"; USER_SANDBOX_CONFIG="$c/uc.yaml" ;;
          user)       printf 'overlay: %s\n' "$c/ov" > "$c/uc.yaml"; USER_SANDBOX_CONFIG="$c/uc.yaml" ;;
          user-tilde) printf 'overlay: ~/ov\n' > "$c/uc.yaml"; USER_SANDBOX_CONFIG="$c/uc.yaml" ;;
        esac ;;
      envdom)
        [[ "$fx" != - ]] && USER_SANDBOX_CONFIG="$here/fx/$fx"
        [[ -n "$a1" ]] && export SANDBOX_EXTRA_ALLOWED_DOMAINS="$a1"
        mkdir -p "$c/cwd"; for f in evil.example.com x.example.com .hidden.example.com a1 b1 c1; do : > "$c/cwd/$f"; done ;;
    esac
    source "$root/lib/config.sh"; source "$root/lib/profile.sh"
    set +e +u
    case "$op" in
      rmscalar) remove_yaml_scalar_from_file "$target" "$a1" ;;
      rmlist)   remove_yaml_list_from_file "$target" "$a1" ;;
      addmask)  config_add_masked_path "$target" "$a1" ;;
      addfp)    ignorefile_add_fingerprint "$target" "$a1" "$a2" ;;
      ignfile)  repo_ignore_file "$c/r"; load_repo_ignore_fingerprints "$c/r" ;;
      honor)    honor_repo_allowed_domains ;;
      envdom)   cd "$c/cwd" && load_user_extra_allowed_domains ;;
    esac > "$c/.out" 2>/dev/null
    rc=$?
    out="$(sed "s|$c|<C>|g" "$c/.out" | b64)"
    if [[ "$target" != - && -f "$target" ]]; then
      file="$(b64 < "$target")"; m="$(stat -c %a "$target")"
    else
      file=-; m=-
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$rc" "$out" "$file" "$m"
  )
  rm -rf "$c"
done
