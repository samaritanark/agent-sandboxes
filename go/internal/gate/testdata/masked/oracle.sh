#!/usr/bin/env bash
# Bash oracle for is_path_masked and extract_yaml_list_from_file. Run on LINUX with LC_ALL=C:
#   LC_ALL=C oracle.sh masked  > golden-masked.tsv   (cfg, relpath, rc)
#   LC_ALL=C oracle.sh lists   > golden-lists.tsv    (cfg, item) one row per list item
# Each config is copied to <tmp>/<cfg>/.sandbox/config.yaml, the layout is_path_masked expects.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../../.." && pwd)"
source "$root/lib/config.sh"
source "$root/lib/filesystem.sh"
type load_repo_masked_paths >/dev/null || { echo "oracle: load_repo_masked_paths not defined" >&2; exit 3; }
set +e +u   # the sourced libs enable -e; the oracle must survive nonzero answers
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
for f in "$here"/cfgs/*.yaml; do
  n="$(basename "$f" .yaml)"; mkdir -p "$tmp/$n/.sandbox"; cp "$f" "$tmp/$n/.sandbox/config.yaml"
done
us=$'\037'
case "$1" in
  masked)
    tr '\t' '\037' < "$here/cases-masked.tsv" | while IFS="$us" read -r c p; do
      if is_path_masked "$tmp/$c" "$p"; then rc=0; else rc=1; fi
      printf '%s\t%s\t%s\n' "$c" "$p" "$rc"
    done ;;
  lists)
    for f in "$here"/cfgs/*.yaml; do
      n="$(basename "$f" .yaml)"
      extract_yaml_list_from_file "$tmp/$n/.sandbox/config.yaml" masked_paths | while IFS= read -r item; do
        printf '%s\t%s\n' "$n" "$item"
      done
    done ;;
esac
