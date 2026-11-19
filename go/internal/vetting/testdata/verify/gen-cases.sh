#!/usr/bin/env bash
# Writes cases.tsv: id <TAB> repo <TAB> user-config <TAB> overlay <TAB> home.  "REL:x" = relative path.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
repos="r-notag r-empty r-shallow r-at-head r-behind1 r-behind3 r-multi r-ties r-ties-mixed r-divergent r-untrusted r-signed-b r-unsigned r-lightweight r-wrongprefix r-oddnames r-branch-shadow r-dirty-untracked r-dirty-modified r-dirty-staged r-clean r-link r-evil not-a-repo missing-dir REL:r-at-head REL:r-notag"
combos="uc-base:-:a uc-clean:-:a uc-rootb:-:a uc-base:b:a uc-base:same:a uc-base:-:b uc-gpg:-:a uc-gpg-home:-:a uc-rootmissing:-:a uc-clean:b:a"
i=0
for r in $repos; do for c in $combos; do
  IFS=: read -r uc ov home <<< "$c"
  printf 'v%04d\t%s\t%s\t%s\t%s\n' $i "$r" "$uc" "$ov" "$home"; i=$((i+1))
done; done > "$here/cases.tsv"
wc -l < "$here/cases.tsv"
