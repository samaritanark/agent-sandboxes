#!/usr/bin/env bash
# Bash oracle for the workspace mounts of a Tier 2/3 pod (lib/manifest.sh). Run on LINUX with LC_ALL=C:
#   LC_ALL=C oracle.sh > golden-mounts.tsv
# One line per case in cases.tsv (see internal/genmounts): "id stdout stderr", as "=" + base64:
# build_volume_mounts_block for tier 2 over the case's repos, then each repo's
# _readonly_workspace_entries. The case home prints as <HOME>.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
src="$(cd "$here/../../../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
us=$'\037'
dec() { local v; v="$(printf '%s' "${2#=}" | base64 -d; printf x)"; printf -v "$1" '%s' "${v%x}"; }
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id erepos etree; do
  H="$T/$id"; mkdir -p "$H"
  dec tree "$etree"
  while IFS= read -r line; do
    read -ra w <<<"$line"; [[ ${#w[@]} -gt 0 ]] || continue
    dec k "${w[0]}"; dec p "${w[1]}"; t=""; [[ ${#w[@]} -gt 2 ]] && dec t "${w[2]}"
    case "$k" in
      f) mkdir -p "$(dirname "$H/$p")"; printf '%s' "$t" > "$H/$p" ;;
      d) mkdir -p "$H/$p" ;;
      l) mkdir -p "$(dirname "$H/$p")"; ln -s "$t" "$H/$p" ;;
    esac
  done <<<"$tree"
  repos=()
  while IFS= read -r -d '' x; do repos+=("$H/$x"); done < <(printf '%s' "${erepos#=}" | base64 -d; printf '\0')
  (
    export HOME="$H" SANDBOX_ROOT="$src"
    for l in platform config filesystem manifest; do source "$src/lib/$l.sh"; done
    set +e +u
    build_volume_mounts_block 2 "" "" "" "${repos[@]}"
    for r in "${repos[@]}"; do echo "### readonly $(basename "$r")"; _readonly_workspace_entries "$r"; done
  ) > "$H.out" 2> "$H.err"
  printf '%s\t=%s\t=%s\n' "$id" "$(sed "s|$H|<HOME>|g" "$H.out" | base64 -w0)" "$(sed "s|$H|<HOME>|g" "$H.err" | base64 -w0)"
  rm -rf "$H" "$H.out" "$H.err"
done
