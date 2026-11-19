#!/usr/bin/env bash
# Bash oracle for secret_gate_repos. Run on LINUX with LC_ALL=C.UTF-8 (printf %q depends on the
# locale):  LC_ALL=C.UTF-8 oracle.sh > golden-gate.txt
set -u
here="$(cd "$(dirname "$0")" && pwd)"
export ROOT="$(cd "$here/../../../../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
"$here/../scan/setup.sh" "$T/fx"
export FX="$T/fx" STUB_DIR="$here/../scan/stub"
us=$'\037'
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id repos acc trusted unv vec tty legacy accfix scen path; do
  export CASE_ID=$id CASE_REPOS=$repos CASE_ACCEPT=$acc CASE_TRUSTED=$trusted CASE_UNVETTED=$unv CASE_VEC=$vec CASE_LEGACY=$legacy CASE_ACCFIX=$accfix CASE_PATH=$path
  export SCEN="$here/scen/$scen" LOG="$FX/log/$id" META="$FX/log/$id.meta"
  : > "$LOG"
  printf '### %s\n' "$id"
  if [[ "$tty" == - ]]; then
    bash "$here/case.sh" > "$FX/log/$id.out" 2> "$FX/log/$id.err" < /dev/null
    printf -- '--- stdout\n'; cat "$FX/log/$id.out"; printf -- '--- stderr\n'; cat "$FX/log/$id.err"
  else
    printf -- '--- tty\n'
    python3 "$here/ptyrun.py" "$tty" bash "$here/case.sh" | tr -d '\r'
  fi
  printf -- '--- log\n'; cat "$LOG"; printf -- '--- stub\n'; cat "$FX/log/stub-$id"; printf -- '--- meta\n'; cat "$META"
done | sed "s|$T/fx|<T>|g"
