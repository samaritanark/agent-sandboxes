#!/usr/bin/env bash
# Bash oracle for the session-record half of lib/audit.sh. Run on LINUX with LC_ALL=C:
#   LC_ALL=C oracle.sh > golden-audit.tsv
# Each case in cases.tsv is "id steps"; steps is "=" + base64 of lines, each line a step whose
# fields are space-separated "=" + base64 words (see internal/genaudit). Output per case:
# "id stdout file mode", stdout and file as "=" + base64 (file "-" when session.json is absent).
# date is a fixed clock and get_agent_credential_type a stub ("cred-<agent>").
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
umask 022
us=$'\037'
b64() { printf '='; base64 -w0; }
dec() { local _dv; _dv="$(printf '%s' "${2#=}" | base64 -d; printf x)"; printf -v "$1" '%s' "${_dv%x}"; }
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id esteps; do
  c="$T/$id"; mkdir -p "$c/logs/ses-x" "$c/tmp"
  (
    export TMPDIR="$c/tmp" HOME="$c"
    source "$root/lib/tier.sh"; source "$root/lib/audit.sh"
    set +e +u
    date() { echo "2026-01-02T03:04:05Z"; }
    get_agent_credential_type() { echo "cred-$1"; }
    SESSION_OVERRIDES=()
    L="$c/logs/ses-x"
    dec steps "$esteps"
    while IFS= read -r line; do
      read -ra w <<<"$line"
      args=()
      for x in "${w[@]}"; do dec v "$x"; args+=("$v"); done
      op="${args[0]}"; a=("${args[@]:1}")
      case "$op" in
        V) export "${a[0]}=${a[1]}" ;;
        W) audit_write_session_json "$L" "${a[@]}" ;;
        O) record_override "${a[@]}" ;;
        F) audit_flush_overrides "$L" ;;
        E) audit_update_end_time "$L" "${a[0]}" ;;
        R) audit_record_end_reason "$L" "${a[0]}" "${a[1]}" ;;
        A) audit_record_agent_session_id "$L" "${a[0]}" ;;
        D) audit_record_dependencies "$L" "${a[0]}" ;;
        d) audit_record_dependencies_down "$L" "${a[0]}" ;;
        G) audit_log_event "$L" "${a[0]}" "${a[1]}" ;;
        X) printf '%s' "${a[0]}" > "$L/session.json" ;;
        M) rm -f "$L/session.json" ;;
        K) case "${a[1]}" in
             dir) mkdir -p "$c/logs/${a[0]}" ;; file) : > "$c/logs/${a[0]}" ;;
             link) ln -s "$c/logs/ses-x" "$c/logs/${a[0]}" ;; dangling) ln -s "$c/nowhere" "$c/logs/${a[0]}" ;;
           esac ;;
        S) audit_list_sessions "$c/logs" ;;
        N) audit_list_sessions "$c/missing" ;;
      esac
    done <<<"$steps" > "$c/.out" 2>/dev/null
    out="$(sed "s|$c|<C>|g" "$c/.out" | b64)"
    if [[ -f "$L/session.json" ]]; then f="$(b64 < "$L/session.json")"; m="$(stat -c %a "$L/session.json")"; else f=-; m=-; fi
    printf '%s\t%s\t%s\t%s\n' "$id" "$out" "$f" "$m"
  )
  rm -rf "$c"
done
