#!/usr/bin/env bash
# Writes cases-accepted.tsv: acc-file <TAB> relpath <TAB> rule <TAB> line, for every variant.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
accs="exact crlf trailing-space suffixed leading-space other-lines no-final-newline with-comments empty just-newline is-a-directory symlink-ok symlink-dangling missing ABSENT"
while IFS= read -r p; do
  for a in $accs; do
    for rl in "generic-api-key	3" "generic-api-key	4" "other-rule	4" "other-rule	3" "x	1"; do
      printf '%s\t%s\t%s\n' "$a" "$p" "$rl"
    done
  done
done < "$here/relpaths.txt" > "$here/cases-accepted.tsv"
wc -l < "$here/cases-accepted.tsv"
