#!/usr/bin/env bash
# Bash oracle for _leakscan_finding_accepted. Run on LINUX with LC_ALL=C from anywhere:
#   LC_ALL=C oracle.sh > golden-accepted.tsv
# ABSENT means an empty accept-file argument; "missing" is a path that does not exist.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../../.." && pwd)"
source "$root/lib/filesystem.sh"
set +e +u
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
"$here/setup.sh" "$tmp"
us=$'\037'
tr '\t' '\037' < "$here/cases-accepted.tsv" | while IFS="$us" read -r a p r l; do
  af="$tmp/acc/$a"; [[ "$a" == ABSENT ]] && af=""
  if _leakscan_finding_accepted "$af" "$tmp/repo" "$p" "$r" "$l"; then rc=0; else rc=1; fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$a" "$p" "$r" "$l" "$rc"
done
