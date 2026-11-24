#!/usr/bin/env bash
# Bash oracle for lib/tier.sh. Run on Linux: oracle.sh > golden-tier.txt
# For each input (one per line in inputs.txt, written with printf %q), the four functions' answers.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
source "$root/lib/tier.sh"
set +e +u
while IFS= read -r q; do
  eval "t=$q"
  printf '### %s\n' "$q"
  err="$( (validate_tier "$t") 2>&1 )"; printf 'validate rc=%s err=%q\n' "$?" "$err"
  printf 'domains=%s\n' "$(get_tier_domains "$t" | tr '\n' ',')"
  printf 'retention=%s\n' "$(get_tier_retention_days "$t")"
  printf 'description=%s\n' "$(get_tier_description "$t")"
done < "$here/inputs.txt"
