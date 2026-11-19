#!/usr/bin/env bash
# Bash oracle for vetting_gate_repos. Run on LINUX with LC_ALL=C.UTF-8:
#   LC_ALL=C.UTF-8 oracle.sh > golden-gate.txt
# bash's own arithmetic-error messages ("[[: 08: value too great for base") are dropped: the port does
# not reproduce them; their effect (a false comparison) is compared.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
export ROOT="$(cd "$here/../../../../.." && pwd)" SHIM="$here/shim"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
export FX="$T"; mkdir -p "$T/home"
us=$'\037'
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id scn repos posture accept drift forbid cap agecap roots tty sign attest; do
  export CASE_REPOS=$repos CASE_POSTURE=$posture CASE_ACCEPT=$accept CASE_DRIFT=$drift CASE_FORBID=$forbid CASE_CAP=$cap CASE_AGECAP=$agecap CASE_ROOTS=$roots CASE_SIGN=$sign CASE_ATTEST=$attest
  export SCEN="$here/scen/$scn" LOG="$T/log.$id" META="$T/meta.$id"
  : > "$LOG"
  printf '### %s\n' "$id"
  if [[ "$tty" == - ]]; then
    bash "$here/case.sh" > "$T/out" 2> "$T/err" < /dev/null
    printf -- '--- stdout\n'; cat "$T/out"; printf -- '--- stderr\n'; grep -Ev 'vetting\.sh: line [0-9]+: \[\[: ' "$T/err"
  else
    printf -- '--- tty\n'
    python3 "$here/ptyrun.py" "$tty" bash "$here/case.sh" | tr -d '\r' | grep -Ev 'vetting\.sh: line [0-9]+: \[\[: '
  fi
  printf -- '--- log\n'; cat "$LOG"; printf -- '--- meta\n'; cat "$META"
done
