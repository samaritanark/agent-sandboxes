#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/cluster.sh — Kubernetes cluster helpers
set -euo pipefail

# ensure_cluster_ready — verify kubectl works and required infra is present
ensure_cluster_ready() {
  # On macOS, ensure Lima is running first
  ensure_lima_running

  require_command kubectl "Install kubectl: https://kubernetes.io/docs/tasks/tools/"

  if ! kubectl cluster-info &>/dev/null 2>&1; then
    echo "ERROR: Cannot reach Kubernetes cluster." >&2
    echo "  On Linux: ensure k3s is running (sudo systemctl status k3s)" >&2
    echo "  On macOS: run 'sandbox setup' or 'limactl start sandbox-vm'" >&2
    exit 1
  fi

  # Verify sandbox namespace exists
  if ! kubectl get namespace "${SANDBOX_NAMESPACE}" &>/dev/null; then
    echo "ERROR: Namespace '${SANDBOX_NAMESPACE}' not found." >&2
    echo "  Run 'sandbox setup' to initialize the cluster." >&2
    exit 1
  fi

  # Verify gVisor RuntimeClass exists
  if ! kubectl get runtimeclass gvisor &>/dev/null; then
    echo "ERROR: gVisor RuntimeClass 'gvisor' not found." >&2
    echo "  Run 'sandbox setup' to install gVisor." >&2
    exit 1
  fi
}

# wait_for_pod — wait for the pod's container to be running and ready.
# Checks container readiness, not just pod phase: a container stuck in a
# crash/start loop leaves the pod phase at "Running" with nothing actually
# running, so a phase-only check would falsely report success and the
# session would then attach to a container that isn't there.
wait_for_pod() {
  local pod_name="$1"
  local max_wait="${2:-120}"
  local interval=3
  local elapsed=0

  while true; do
    # One query for everything we need: pod phase, plus the agent
    # container's readiness, restart count, and waiting/terminated reasons.
    local raw phase ready restarts waiting terminated
    raw="$(kubectl get pod -n "${SANDBOX_NAMESPACE}" "${pod_name}" -o jsonpath='{.status.phase}|{.status.containerStatuses[0].ready}|{.status.containerStatuses[0].restartCount}|{.status.containerStatuses[0].state.waiting.reason}|{.status.containerStatuses[0].state.terminated.reason}' 2>/dev/null || echo '')"
    IFS='|' read -r phase ready restarts waiting terminated <<<"${raw}"
    phase="${phase:-Pending}"

    # Success: the container is running and ready.
    if [[ "${ready}" == "true" ]]; then
      echo "  Pod is Running."
      return 0
    fi

    # Terminal failures — fail fast instead of waiting out max_wait. The
    # agent container runs 'sleep infinity', so it must never restart or
    # terminate; a crash/start loop keeps the pod phase at "Running".
    local fail_reason=""
    if [[ "${phase}" == "Failed" ]]; then
      fail_reason="pod phase Failed"
    elif [[ -n "${restarts}" ]] && [[ "${restarts}" -ge 1 ]]; then
      fail_reason="agent container has restarted ${restarts}x — it should never restart"
    else
      case "${waiting}" in
        CrashLoopBackOff|CreateContainerError|RunContainerError|StartError|ImagePullBackOff|ErrImagePull|ErrImageNeverPull|InvalidImageName)
          fail_reason="container not starting (${waiting})" ;;
      esac
      case "${terminated}" in
        StartError|Error|OOMKilled|ContainerCannotRun)
          fail_reason="container terminated (${terminated})" ;;
      esac
    fi
    if [[ -n "${fail_reason}" ]]; then
      echo "ERROR: Pod '${pod_name}' is not healthy — ${fail_reason}." >&2
      kubectl describe pod -n "${SANDBOX_NAMESPACE}" "${pod_name}" >&2 || true
      exit 1
    fi

    if [[ "${elapsed}" -ge "${max_wait}" ]]; then
      echo "ERROR: Pod '${pod_name}' did not become ready within ${max_wait}s." >&2
      kubectl describe pod -n "${SANDBOX_NAMESPACE}" "${pod_name}" >&2 || true
      exit 1
    fi

    sleep "${interval}"
    (( elapsed += interval )) || true
    echo "  Waiting for pod... (${elapsed}s / ${max_wait}s, phase: ${phase}, ready: ${ready:-false})"
  done
}

# assert_session_identity_distinct — verify the session pod has a DISTINCT
# Cilium security identity keyed on its session ID, BEFORE any dependency
# toEndpoints/ingress rule is wired (§1.6). Everything that scopes a rule to
# "the session pod" or "this dependency's pod" assumes each session pod carries
# a distinct Cilium identity; Cilium derives identity from labels, and operators
# are advised to *narrow* the identity-relevant label set at scale. If
# 'sandbox-session' falls outside that set, every session collapses to one
# identity and a dependency's "only from the session pod" rule silently matches
# ALL sessions. Sessions share one namespace, so 'sandbox-session' is the only
# discriminator — there is no namespace boundary doing the work for us.
#
# This reads the LIVE CiliumEndpoint (the labels Cilium actually fed into the
# identity), so it is mechanism-agnostic: it catches a narrowed set whether it
# came from cilium-config, an agent flag, or a mounted label-prefix-file. Fail
# closed. Gate the call on sessions that actually declare dependencies — a
# browserless session has nothing for it to protect.
#
# The check proves identity at launch, not that an operator won't narrow the set
# mid-session; that TOCTOU is marginal (cilium-config changes are rare and
# operator-driven) and is intentionally not re-checked.
assert_session_identity_distinct() {
  local pod_name="$1"
  local max_wait="${2:-60}"
  local interval=3
  local elapsed=0

  while true; do
    local labels
    labels="$(kubectl get ciliumendpoint -n "${SANDBOX_NAMESPACE}" "${pod_name}" \
      -o jsonpath='{.status.identity.labels}' 2>/dev/null || true)"

    if [[ -n "${labels}" ]]; then
      if echo "${labels}" | grep -q 'sandbox-session'; then
        return 0
      fi
      echo "ERROR: session pod '${pod_name}' Cilium identity does not include the" >&2
      echo "       'sandbox-session' label, so per-session network isolation would" >&2
      echo "       collapse — every session would share one identity and a" >&2
      echo "       dependency's 'only from the session pod' rule would match ALL" >&2
      echo "       sessions (§1.6). Refusing to wire dependencies." >&2
      echo "       Cause: the identity-relevant label set was narrowed (cilium-config" >&2
      echo "       'labels' / 'label-prefix-file', an agent flag, or a mounted file)." >&2
      exit 1
    fi

    # The CiliumEndpoint lands a beat after the pod schedules — don't fail on the
    # first empty read, only on timeout.
    if [[ "${elapsed}" -ge "${max_wait}" ]]; then
      echo "ERROR: CiliumEndpoint for '${pod_name}' did not report an identity" >&2
      echo "       within ${max_wait}s; cannot verify per-session isolation." >&2
      echo "       Refusing to wire dependencies (fail closed)." >&2
      exit 1
    fi

    sleep "${interval}"
    (( elapsed += interval )) || true
  done
}

# create_infra_token_secret — create K8s Secret for Tier 3 infra token
create_infra_token_secret() {
  local secret_name="$1"
  local token_file="$2"

  local token_value
  token_value="$(cat "${token_file}")"

  kubectl create secret generic "${secret_name}" \
    --namespace "${SANDBOX_NAMESPACE}" \
    --from-literal="INFRA_TOKEN=${token_value}" \
    --dry-run=client -o yaml | kubectl apply -f -

  echo "  Created secret: ${secret_name}"
}

# minify_kubeconfig — emit a single-context, self-contained kubeconfig.
# Extracts only the named context (or current-context if context is empty) and
# inlines any externally-referenced cert/key files via --flatten, so the result
# is portable into a pod with no host file dependencies.
minify_kubeconfig() {
  local src="$1"
  local context="${2:-}"

  local -a args=(config view --minify --flatten "--kubeconfig=${src}" -o yaml)
  [[ -n "${context}" ]] && args+=("--context=${context}")

  # Capture kubectl's stderr so we can surface the real reason on failure
  # (missing context, malformed YAML, bad base64 field, etc.) instead of
  # hiding it behind a generic message.
  local errfile
  errfile="$(mktemp)"
  if ! kubectl "${args[@]}" 2>"${errfile}"; then
    echo "ERROR: kubectl could not minify kubeconfig '${src}':" >&2
    sed 's/^/  /' "${errfile}" >&2
    [[ -n "${context}" ]] && echo "  (context requested: '${context}')" >&2
    [[ -z "${context}" ]] && echo "  Try --infra-kube-context <NAME> to name a context explicitly." >&2
    rm -f "${errfile}"
    exit 1
  fi
  rm -f "${errfile}"
}

# kubeconfig_server_url — print the server: URL from a (minified) kubeconfig
kubeconfig_server_url() {
  local kc="$1"
  kubectl --kubeconfig="${kc}" config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null
}

# url_host — print the hostname from a URL (https://host:port/path → host)
# Does not handle IPv6 literal addresses; sufficient for typical kube API servers.
url_host() {
  local rest="${1#*://}"
  rest="${rest%%/*}"
  rest="${rest%%\?*}"
  echo "${rest%:*}"
}

# url_port — print the explicit port, or the scheme default (443/80), or empty
url_port() {
  local url="$1"
  local scheme="${url%%://*}"
  local rest="${url#*://}"
  rest="${rest%%/*}"
  rest="${rest%%\?*}"
  if [[ "${rest}" == *:* ]]; then
    echo "${rest##*:}"
  else
    case "${scheme}" in
      https) echo "443" ;;
      http)  echo "80" ;;
      *)     echo "" ;;
    esac
  fi
}

# kubeconfig_exec_command — print the exec.command for the current user, if any.
# Empty output means no exec credential plugin is configured.
kubeconfig_exec_command() {
  local kc="$1"
  kubectl --kubeconfig="${kc}" config view --minify -o jsonpath='{.users[0].user.exec.command}' 2>/dev/null
}

# create_kubeconfig_secret — create K8s Secret holding the minified kubeconfig.
# The single key 'config' lets the pod mount it via subPath to /home/agent/.kube/config.
create_kubeconfig_secret() {
  local secret_name="$1"
  local kubeconfig_file="$2"

  kubectl create secret generic "${secret_name}" \
    --namespace "${SANDBOX_NAMESPACE}" \
    --from-file="config=${kubeconfig_file}" \
    --dry-run=client -o yaml | kubectl apply -f -

  echo "  Created secret: ${secret_name}"
}

# delete_kubeconfig_secret — remove kubeconfig secret after session
delete_kubeconfig_secret() {
  local session_id="$1"
  local secret_name="kubeconfig-${session_id}"

  kubectl delete secret -n "${SANDBOX_NAMESPACE}" \
    "${secret_name}" --ignore-not-found=true 2>&1 || true
}

# export_hubble_flows — export Hubble flows for session
# Reads from the Cilium agent's local Hubble via `kubectl exec`, not the host
# `hubble` CLI: the host CLI needs a Hubble Relay connection on localhost:4245
# that nothing sets up. On this single-node cluster the agent sees every flow.
export_hubble_flows() {
  local session_id="$1"
  local log_dir="$2"

  kubectl -n kube-system exec ds/cilium -- \
    hubble observe \
      --namespace "${SANDBOX_NAMESPACE}" \
      --label "sandbox-session=${session_id}" \
      --output json \
      --last 10000 \
    2>/dev/null > "${log_dir}/flows.json" || true

  if [[ -s "${log_dir}/flows.json" ]]; then
    local flow_count
    flow_count="$(wc -l < "${log_dir}/flows.json" | tr -d ' ')"
    echo "  Exported ${flow_count} flow records."
  else
    echo "  No flows captured (empty result)."
    rm -f "${log_dir}/flows.json"
  fi
}
