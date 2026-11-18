#!/usr/bin/env bash
# Runs the bash oracle (finding_is_encrypted in lib/filesystem.sh) over a cases file and prints the
# cases with its exit status appended. Run on LINUX from the repo root, because the appliance's awk
# is mawk and differs from macOS awk:
#   LC_ALL=C go/internal/gate/testdata/encrypted/oracle.sh cases-fixtures.tsv > golden-fixtures.tsv
# Fields are tab-separated; they are re-delimited with US (0x1f) for reading because bash's read
# collapses adjacent tabs (tab is IFS whitespace) and would shift empty fields.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../../.." && pwd)"
source "$root/lib/filesystem.sh"
us=$'\037'
tr '\t' '\037' < "$here/$1" | while IFS="$us" read -r f l sc ec; do
  if finding_is_encrypted "$here/$f" "$l" "$sc" "$ec"; then rc=0; else rc=1; fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$f" "$l" "$sc" "$ec" "$rc"
done
