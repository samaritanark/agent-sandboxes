#!/usr/bin/env bash
# cmd-stub.sh <install> <run|allow|resume> [ARGS...] — a cluster-facing command from oracle.sh,
# stopped where the cluster work begins. bin/sandbox is sourced and these functions replaced:
#   k3s_image_present             answers $STUB_IMAGE_RC (default 2, "cannot tell")
#   ensure_cluster_ready          with STOP_AT=b1, prints the launch decisions and exits;
#                                 otherwise nothing (there is no cluster)
#   ensure_network_config_current, prepare_agent_home, prepare_workspace, check_masking_paths
#                                 nothing: v3 removes them (VM-local paths, no gVisor mounts)
#   audit_flush_overrides         runs; for run, then prints the decisions and exits (Step 4 ends)
#   date                          the clock is fixed at $FAKE_NOW unless a date is given
#   head                          /dev/urandom reads answer fixed bytes (session ID, UUID)
#   kubectl                       `get pod` succeeds when $STUB_POD is set (a live session),
#                                 printing $STUB_POD as the phase for a jsonpath query;
#                                 `apply` reads and drops its input
#   build_cilium_policy           prints its inputs to stderr (what v3 hands the gateway)
#   build_pod_manifest            prints its inputs to stderr (what v3 hands sandboxd)
#   wait_for_pod                  succeeds
#   _arm_teardown_trap            (resume, just before attaching) prints the agent command and
#                                 exits
# Everything else is the v2 code.
source "$1/bin/sandbox"
cmd="$2"
shift 2
export USER=t

date() {
  local a
  for a in "$@"; do [[ "$a" == -d* || "$a" == -r* || "$a" == --date* ]] && { command date "$@"; return; }; done
  command date -d "@${FAKE_NOW:?}" "$@"
}
head() {
  case "$*" in
    "-c 2 /dev/urandom") printf '\xbe\xef' ;;
    "-c 16 /dev/urandom") printf '\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10' ;;
    *) command head "$@" ;;
  esac
}
kubectl() {
  local a
  case "$*" in
    *" apply "*|apply*) cat >/dev/null; return 0 ;;
  esac
  for a in "$@"; do
    if [[ "$a" == get ]]; then
      [[ -n "${STUB_POD:-}" ]] || return 1
      [[ "$*" == *jsonpath* ]] && printf '%s' "$STUB_POD"
      return 0
    fi
  done
  echo "stub kubectl: unexpected: $*" >&2
  return 99
}
build_cilium_policy() {
  local x
  echo "### policy" >&2
  for x in "$@"; do printf 'arg=%s\n' "$x" >&2; done
  for x in "${SESSION_DEP_ENDPOINTS[@]+"${SESSION_DEP_ENDPOINTS[@]}"}"; do printf 'dep_endpoint=%s\n' "$x" >&2; done
  printf 'host_entity=%s\n' "${SESSION_KUBE_HOST_ENTITY:-}" >&2
}
build_pod_manifest() {
  local x
  echo "### manifest" >&2
  for x in "$@"; do printf 'arg=%s\n' "$x" >&2; done
}
wait_for_pod() { return 0; }
_arm_teardown_trap() {
  local x
  echo "### attach"
  printf 'pod=%s\n' "$pod_name"
  for x in "${agent_cmd[@]}"; do printf 'arg=%s\n' "$x"; done
  printf 'keep_alive=%s\n' "$opt_keep_alive"
  exit 0
}
k3s_image_present() { return "${STUB_IMAGE_RC:-2}"; }
ensure_network_config_current() { :; }
prepare_agent_home() { :; }
prepare_workspace() { :; }
check_masking_paths() { :; }

_q() { printf '%s=%s\n' "$1" "${2//$'\n'/\\n}"; }  # one line per value, bytes as given
_dump_b1() {
  echo "### decisions"
  _q agent "$opt_agent"; _q tier "$opt_tier"; _q profile "${SESSION_PROFILE:-}"; _q overlay "${SESSION_OVERLAY:-}"
  _q name "$opt_name"
  local x
  for x in "${opt_repos[@]+"${opt_repos[@]}"}"; do _q repo "$x"; done
  for x in "${opt_allow_domains[@]+"${opt_allow_domains[@]}"}"; do _q domain "$x"; done
  for x in "${opt_infra_endpoints[@]+"${opt_infra_endpoints[@]}"}"; do _q endpoint "$x"; done
  for x in "${opt_infra_token_pairs[@]+"${opt_infra_token_pairs[@]}"}"; do _q token "$x"; done
  for x in "${opt_infra_kubeconfigs[@]+"${opt_infra_kubeconfigs[@]}"}"; do _q kubeconfig "$x"; done
  _q kube_context "$opt_infra_kube_context"
  for x in "${SESSION_PROFILE_SECRETS_LIST[@]+"${SESSION_PROFILE_SECRETS_LIST[@]}"}"; do _q secret "$x"; done
  _q mcps "${SESSION_PROFILE_MCPS:-}"; _q services "${SESSION_PROFILE_SERVICES:-}"
  _q dry_run "$opt_dry_run"; _q keep_alive "$opt_keep_alive"; _q allow_exec_plugin "$opt_allow_exec_plugin"
  _q accept_unmasked "$opt_accept_unmasked_secrets"; _q accept_unvetted "$opt_accept_unvetted_repo"
  _q accept_drift "$opt_accept_vetting_drift"; _q base_url "${OPENCODE_BASE_URL:-}"
  _q homedir "${SANDBOX_AGENT_HOME_OVERRIDE:-}"; _q has_secrets "$SESSION_HAS_SECRETS"
}
ensure_cluster_ready() {
  [[ "${STOP_AT:-}" == b1 ]] || return 0
  _dump_b1
  exit 0
}
eval "_v2_$(declare -f audit_flush_overrides)"
# cmd_run's locals (session_id, pod_name, _endpoint_trusted) are visible here: bash scoping is dynamic.
audit_flush_overrides() {
  _v2_audit_flush_overrides "$@"
  [[ "$cmd" == run ]] || return 0  # resume re-gates and flushes too, then goes on
  _dump_b1
  echo "### session"
  _q session_id "$session_id"; _q pod_name "$pod_name"; _q endpoint_trusted "${_endpoint_trusted:-}"
  local i
  for i in "${!SESSION_DEP_NAMES[@]}"; do
    _q dep "${SESSION_DEP_NAMES[$i]}|${SESSION_DEP_KINDS[$i]}|${SESSION_DEP_RESOURCE_NAMES[$i]}|${SESSION_DEP_PORTS[$i]}|${SESSION_DEP_SECRETS[$i]}"
  done
  for i in "${SESSION_MCP_SERVER_RECORDS[@]+"${SESSION_MCP_SERVER_RECORDS[@]}"}"; do _q mcp "$i"; done
  exit 0
}
"cmd_$cmd" "$@"
