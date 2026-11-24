#!/usr/bin/env bash
# Bash oracle for lib/onboard.sh. Run on LINUX with LC_ALL=C:
#   LC_ALL=C oracle.sh > golden-onboard.tsv
# Each case in cases.tsv is "id tree op flags env" ("=" + base64 each; see internal/genonboard).
# tree builds $HOME (lines "f path content", "d path", "l path target"); op is an agent name,
# "warnenv", or "starter"; flags is "dry,force" as true/false; env is NAME=VALUE lines.
# Output: "id rc stdout stderr tree", where tree lists every path under the case directory
# (sorted; type, mode, symlink target or content) so a write through a symlink shows.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
umask 022
us=$'\037'
b64() { printf '='; base64 -w0; }
dec() { local _dv; _dv="$(printf '%s' "${2#=}" | base64 -d; printf x)"; printf -v "$1" '%s' "${_dv%x}"; }
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id etree eop eflags eenv; do
  c="$T/$id"; mkdir -p "$c/home"
  (
    dec tree "$etree"; dec op "$eop"; dec flags "$eflags"; dec envs "$eenv"
    export HOME="$c/home"
    for v in ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN OPENAI_API_KEY COPILOT_GITHUB_TOKEN GH_TOKEN GITHUB_TOKEN GROK_DEPLOYMENT_KEY; do unset "$v"; done
    while IFS= read -r line; do [[ -n "$line" ]] && export "$line"; done <<<"$envs"
    while IFS= read -r line; do
      read -ra w <<<"$line"; [[ ${#w[@]} -gt 0 ]] || continue
      dec k "${w[0]}"; dec p "${w[1]}"; t=""; [[ ${#w[@]} -gt 2 ]] && dec t "${w[2]}"
      case "$k" in
        f) mkdir -p "$(dirname "$HOME/$p")"; printf '%s' "$t" > "$HOME/$p" ;;
        d) mkdir -p "$HOME/$p" ;;
        l) mkdir -p "$(dirname "$HOME/$p")"; ln -s "$t" "$HOME/$p" ;;
      esac
    done <<<"$tree"
    source "$root/lib/onboard.sh"
    set +e +u
    dry="${flags%,*}" force="${flags#*,}"
    case "$op" in
      warnenv) warn_forbidden_env ;;
      starter) write_starter_user_config "$dry" "$force" ;;
      *)       onboard_agent "$op" "$dry" "$force" ;;
    esac > "$c/.out" 2> "$c/.err"
    rc=$?
    clean() { sed "s|$c|<C>|g" "$1" | b64; }
    listing="$(cd "$c" && find . -mindepth 1 ! -name .out ! -name .err | LC_ALL=C sort | while IFS= read -r p; do
      if [[ -L "$p" ]]; then printf 'l %s -> %s\n' "$p" "$(readlink "$p")"
      elif [[ -d "$p" ]]; then printf 'd %s %s\n' "$p" "$(stat -c %a "$p")"
      else printf 'f %s %s %s\n' "$p" "$(stat -c %a "$p")" "$(b64 < "$p")"; fi
    done | b64)"
    printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$rc" "$(clean "$c/.out")" "$(clean "$c/.err")" "$listing"
  )
  rm -rf "$c"
done
