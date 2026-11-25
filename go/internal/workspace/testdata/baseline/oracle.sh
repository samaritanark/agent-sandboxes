#!/usr/bin/env bash
# Bash oracle for capture_workspace_baseline and capture_workspace_diff (lib/filesystem.sh). Run on
# LINUX (GNU find, sha256sum, diff) with LC_ALL=C:
#   LC_ALL=C oracle.sh > golden-baseline.tsv
# One line per case in cases.tsv (see internal/genbaseline): "id stdout baseline files.log
# current-left", the texts as "=" + base64 ("-" for a missing file), the case home as <HOME> and the
# log directory as <LOG>. Tree steps: f PATH CONTENT, d PATH, l PATH TARGET, r PATH, u PATH (mode
# 000), p PATH (FIFO); a path starting LOG/ is in the log directory.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
src="$(cd "$here/../../../../.." && pwd)"
T="$(mktemp -d)"; trap 'chmod -R u+rwx "$T" 2>/dev/null; rm -rf "$T"' EXIT
us=$'\037'
dec() { local v; v="$(printf '%s' "${2#=}" | base64 -d; printf x)"; printf -v "$1" '%s' "${v%x}"; }
b64f() { if [[ -f "$1" ]]; then printf '='; sed -e "s|$H|<HOME>|g" -e "s|$LOG|<LOG>|g" "$1" | base64 -w0; else printf -- -; fi; }
steps() {
  local line w k p t
  while IFS= read -r line; do
    read -ra w <<<"$line"; [[ ${#w[@]} -gt 0 ]] || continue
    dec k "${w[0]}"; dec p "${w[1]}"; t=""; [[ ${#w[@]} -gt 2 ]] && dec t "${w[2]}"
    if [[ "$p" == LOG/* ]]; then p="$LOG/${p#LOG/}"; else p="$H/$p"; fi
    case "$k" in
      f) mkdir -p "$(dirname "$p")"; printf '%s' "$t" > "$p" ;;
      d) mkdir -p "$p" ;;
      l) mkdir -p "$(dirname "$p")"; ln -s "$t" "$p" ;;
      r) rm -rf "$p" ;;
      u) chmod 000 "$p" ;;
      p) mkdir -p "$(dirname "$p")"; mkfifo "$p" ;;
    esac
  done
}
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id prune erepos ebefore eafter; do
  c="$T/$id"; H="$c/home"; LOG="$c/log"; R="$c/root"; mkdir -p "$H" "$LOG" "$R/config"
  case "$prune" in
    real) R="$src" ;;
    none) ;;
    *) cp "$here/fx/$prune" "$R/config/workspace-audit.yaml" ;;
  esac
  dec before "$ebefore"; dec after "$eafter"
  repos=()
  while IFS= read -r -d '' x; do repos+=("$H/$x"); done < <(printf '%s' "${erepos#=}" | base64 -d; printf '\0')
  steps <<<"$before"
  out="$(
    cd "$H"
    export HOME="$H" SANDBOX_ROOT="$R"
    source "$src/lib/platform.sh"; source "$src/lib/filesystem.sh"
    set +e +u
    capture_workspace_baseline "$LOG" "${repos[@]}"
    steps <<<"$after"
    capture_workspace_diff "$LOG" "${repos[@]}"
  )"
  left=0; [[ -e "$LOG/current.sha256" ]] && left=1
  printf '%s\t=%s\t%s\t%s\t%s\n' "$id" "$(printf '%s\n' "$out" | sed -e "s|$H|<HOME>|g" -e "s|$LOG|<LOG>|g" | base64 -w0)" \
    "$(b64f "$LOG/baseline.sha256")" "$(b64f "$LOG/files.log")" "$left"
  chmod -R u+rwx "$c" 2>/dev/null; rm -rf "$c"
done
