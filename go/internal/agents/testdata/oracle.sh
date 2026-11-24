#!/usr/bin/env bash
# Bash oracle for lib/agents.sh and check_host_env_not_leaked (lib/credentials.sh). Run on LINUX
# with LC_ALL=C:   LC_ALL=C oracle.sh > golden-agents.tsv
# Each case in cases.tsv is "id op agent args env" ("=" + base64 each; args and env are
# newline-separated). The function runs under `env -i` with only PATH and the case's env.
# Output: "id rc stdout stderr" ("=" + base64).
set -u
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../.." && pwd)"
us=$'\037'
dec() { local _dv; _dv="$(printf '%s' "${2#=}" | base64 -d; printf x)"; printf -v "$1" '%s' "${_dv%x}"; }
tr '\t' '\037' < "$here/cases.tsv" | while IFS="$us" read -r id eop eagent eargs eenv; do
  dec op "$eop"; dec agent "$eagent"; dec args "$eargs"; dec envs "$eenv"
  envargs=(PATH=/usr/bin:/bin LC_ALL=C)
  if [[ -n "$envs" ]]; then
    while IFS= read -r -d $'\x1e' kv; do envargs+=("$kv"); done < <(printf '%s\x1e' "$envs")
  fi
  out="$(mktemp)" err="$(mktemp)"
  env -i "${envargs[@]}" bash -c '
    source "$1/lib/agents.sh"; source "$1/lib/credentials.sh"; set +e +u
    op="$2" agent="$3"; mapfile -t a <<<"$4"
    case "$op" in
      validate) ( validate_agent "$agent" ) ;;
      domains)  ( get_agent_domains "$agent" ) ;;
      endpoint) resolve_inference_endpoint "$agent" ;;
      flags)    printf "[%s][%s][%s]\n" "$(get_agent_session_id_flag "$agent")" "$(get_agent_resume_flag "$agent")" "$(get_agent_sandbox_flags "$agent")" ;;
      mcp)      agent_supports_mcp "$agent"; echo "supports=$?"; get_agent_mcp_launch_args "$agent" ;;
      render)   [[ -z "$4" ]] && a=(); render_agent_mcp_config "$agent" "${a[@]}" ;;
      cred)     get_agent_credential_type "$agent" ;;
      envcheck) check_host_env_not_leaked "$agent" ;;
    esac' _ "$root" "$op" "$agent" "$args" > "$out" 2> "$err"
  rc=$?
  printf '%s\t%s\t=%s\t=%s\n' "$id" "$rc" "$(base64 -w0 < "$out")" "$(base64 -w0 < "$err")"
  rm -f "$out" "$err"
done
