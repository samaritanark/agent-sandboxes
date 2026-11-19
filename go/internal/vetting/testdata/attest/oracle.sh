#!/usr/bin/env bash
# Bash oracle for the attestation functions. Run on LINUX with LC_ALL=C.UTF-8:
#   LC_ALL=C.UTF-8 oracle.sh > golden-attest.txt
# git/ssh-keygen/gpg diagnostics are filtered from the stream (their wording differs between
# versions and platforms); the project's own messages are compared.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
export ROOT="$(cd "$here/../../../../.." && pwd)" STUB_DIR="$here/../../../gate/testdata/scan/stub"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
"$here/setup.sh" "$T/fx"; export FX="$T/fx"
noise='^(error|fatal|hint|warning): |^Couldn.t load|^Load key|^No such file|^ssh-keygen|^Failed |^gpg: |^Error loading|^Signing file|^Write failed|^usage: '
us=$'\037'
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id func repo uc yes msg home tty scen path; do
  export CASE_FUNC=$func CASE_REPO=$repo CASE_YES=$yes CASE_MSG=$msg CASE_PATH=$path
  export RUN="$FX/run" SCEN="$here/scen/$scen" LOG="$FX/log" META="$FX/meta"
  rm -rf "$RUN"; mkdir -p "$RUN"; rm -f "$FX"/markers/* "$LOG" "$META" "$FX/stub.log"
  [[ -d "$FX/tpl/$repo" ]] && cp -a "$FX/tpl/$repo" "$RUN/$repo"
  cp -a "$FX/home-$home" "$RUN/home"; cp "$FX/uc-$uc.yaml" "$RUN/uc.yaml"; chmod 644 "$RUN/uc.yaml"; : > "$LOG"
  printf '### %s\n' "$id"
  if [[ "$tty" == - ]]; then
    bash "$here/case.sh" > "$FX/out" 2> "$FX/err" < /dev/null
    printf -- '--- stdout\n'; grep -Ev "$noise" "$FX/out"; printf -- '--- stderr\n'; grep -Ev "$noise" "$FX/err"
  else
    printf -- '--- tty\n'
    python3 "$here/ptyrun.py" "$tty" bash "$here/case.sh" | tr -d '\r' | grep -Ev "$noise"
  fi
  printf -- '--- log\n'; cat "$LOG"; printf -- '--- meta\n'; cat "$META"
  printf -- '--- post\n'; "$here/poststate.sh" "$RUN/$repo"
  printf -- '--- markers\n'; ls "$FX/markers"
  printf -- '--- gitconfig\n'; cat "$RUN/home/.gitconfig" 2>/dev/null
  printf -- '--- usercfg\n'; cat "$RUN/uc.yaml" 2>/dev/null
  printf -- '--- stat\n'; stat -c '%a' "$RUN/uc.yaml" 2>/dev/null
done | sed -E -e "s|$FX|<T>|g" -e 's#ssh-(ed25519|rsa) AAAA[A-Za-z0-9+/=]+#ssh-\1 <KEY>#g'
