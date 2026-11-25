#!/usr/bin/env bash
# Bash oracle for the in-VM CLI: runs bin/sandbox with each case's arguments. Run on LINUX:
#   LC_ALL=C oracle.sh > golden-cli.tsv
# Each case in cases.tsv is "id version args" (args: "=" + base64 of NUL-separated words;
# version: none | full). The install is copied to a temporary root (with a .version file for
# "full"). Output: "id rc stdout stderr" ("=" + base64). The root prints as <ROOT>, the bash
# version as <RT>, and the JSON "bash" key as "runtime" (the Go binary reports its own runtime).
set -u
here="$(cd "$(dirname "$0")" && pwd)"
src="$(cd "$here/../../../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
for v in none full; do
  mkdir -p "$T/$v"; cp -R "$src/bin" "$src/lib" "$src/setup" "$src/config" "$T/$v/"
done
printf 'VERSION=v3.0.0-test\nCOMMIT=0123456789ab\nCOMMIT_DATE=2026-11-24\nBUILD_DATE=2026-11-25\nTREE_STATE=clean\n' > "$T/full/.version"
rt="bash ${BASH_VERSION%%(*}"
us=$'\037'
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id ver eargs; do
  args=()
  while IFS= read -r -d '' a; do args+=("$a"); done < <(printf '%s' "${eargs#=}" | base64 -d)
  out="$(mktemp)" err="$(mktemp)"
  env -i PATH=/usr/bin:/bin HOME="$T/home" LC_ALL=C SANDBOX_LOGS_DIR="$T/home/logs" "$T/$ver/bin/sandbox" "${args[@]}" > "$out" 2> "$err"
  rc=$?
  norm() { sed -e "s|$T/$ver|<ROOT>|g" -e "s|bash ${BASH_VERSION%%(*}|<RT>|g" -e "s|\"bash\":\"${BASH_VERSION%%(*}\"|\"runtime\":\"<RT>\"|g" -e "s|$T/home|<HOME>|g" "$1" | base64 -w0; }
  printf '%s\t%s\t=%s\t=%s\n' "$id" "$rc" "$(norm "$out")" "$(norm "$err")"
  rm -f "$out" "$err"
done
