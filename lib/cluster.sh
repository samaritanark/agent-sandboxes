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

# create_infra_token_secret — create K8s Secret for Tier 3 infra token(s).
# Signature: create_infra_token_secret <secret_name> <ENVNAME=PATH> [ENVNAME=PATH ...]
# Each pair becomes a literal key ENVNAME in the one Secret; the pod pulls them
# all in via envFrom (lib/manifest.sh). Command substitution strips trailing
# newlines from each token file, matching the historical single-token behavior.
create_infra_token_secret() {
  local secret_name="$1"
  shift

  local -a lit_args=()
  local pair envname path token_value
  for pair in "$@"; do
    envname="${pair%%=*}"
    path="${pair#*=}"
    token_value="$(cat "${path}")"
    lit_args+=("--from-literal=${envname}=${token_value}")
  done

  kubectl create secret generic "${secret_name}" \
    --namespace "${SANDBOX_NAMESPACE}" \
    "${lit_args[@]}" \
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

# merge_kubeconfigs — combine several already-minified, single-context
# kubeconfigs into one self-contained file.
# Signature: merge_kubeconfigs <dest> <part1> <part2> [part3 ...]
#
# Each part is expected to hold exactly one cluster/user/context (the shape
# minify_kubeconfig produces). We rename each part's cluster/user to index-based
# names (sandbox-cluster-N / sandbox-user-N) so two parts can never collide on
# those internal names — kubectl's native merge is first-wins by name, which
# would otherwise silently drop a second cluster called "kubernetes". The
# user-facing CONTEXT name is preserved (that is what 'kubectl config
# use-context' selects), only suffixed -2, -3, ... on collision. The first
# part's context becomes current-context.
#
# The rename happens on a JSON dump of each part (kubectl config view --minify
# --flatten --raw), edited with jq, then all parts are combined via kubectl's
# own KUBECONFIG merge. Nothing secret ever reaches a command line: jq's --arg
# carries only the (non-secret) names, KUBECONFIG carries file paths, and the
# credential material stays inside the files. This deliberately avoids putting
# tokens / client keys on the argv (readable via /proc/PID/cmdline and, on
# macOS, other users' `ps`), which the earlier per-field 'config set-credentials
# --token=…' / 'config set …-key-data' approach did.
#
# jq is a hard dependency of this tool (require_command jq in bin/sandbox), so
# no new dependency is introduced. Static auth only: token or client cert+key.
# Basic auth (username/password) is dropped — the API server dropped it in
# k8s 1.19, so it cannot authenticate and, mixed with a token, would make
# kubectl reject the credential outright. Exec plugins are rejected upstream
# before a multi-kubeconfig launch ever reaches here. tls-server-name and
# proxy-url, if present on a source cluster, ride through unchanged (the whole
# cluster object is carried, not a hand-picked field subset).
merge_kubeconfigs() {
  local dest="$1"
  shift

  # Scratch lives beside dest, in the caller's 0700 temp dir that is reaped on
  # EXIT (bin/sandbox Step 1b). The per-part JSON holds credential material, so
  # keep it 0600 even inside that dir.
  local scratch
  scratch="$(dirname "${dest}")"

  : > "${dest}"
  chmod 0600 "${dest}"

  local -a used_ctx=() renamed=()
  local part idx=0 first_ctx=""
  local part_json ctx newctx cname uname_new seen collide n
  local token cc_data ck_data rfile
  for part in "$@"; do
    # One JSON dump per part; every field read below comes from this, so the
    # part file is opened once and no value transits a command line.
    part_json="$(kubectl --kubeconfig="${part}" config view --minify --flatten --raw -o json)"

    # Context name — preserved for use-context. Parts are minified so
    # contexts[0].name == current-context; fall back defensively. The `// ""`
    # keeps an empty field from tripping set -e (it never exits nonzero here).
    ctx="$(jq -r '.contexts[0].name // ."current-context" // ""' <<<"${part_json}")"
    [[ -z "${ctx}" ]] && ctx="context-${idx}"

    # Preserve the context name; suffix only to dodge a collision with one
    # already taken by an earlier part.
    newctx="${ctx}"
    n=2
    while :; do
      collide="false"
      for seen in "${used_ctx[@]+"${used_ctx[@]}"}"; do
        [[ "${seen}" == "${newctx}" ]] && collide="true" && break
      done
      [[ "${collide}" == "false" ]] && break
      newctx="${ctx}-${n}"
      n=$((n + 1))
    done
    used_ctx+=("${newctx}")
    [[ -z "${first_ctx}" ]] && first_ctx="${newctx}"

    cname="sandbox-cluster-${idx}"
    uname_new="sandbox-user-${idx}"

    # Static-credential guard: refuse a part whose user carries neither a bearer
    # token nor a client cert+key pair, so a credential-less context can never
    # fall back to ambient auth inside the pod. Basic auth does NOT count (see
    # header). Read from the JSON dump, not the argv.
    token="$(jq -r '.users[0].user.token // ""' <<<"${part_json}")"
    cc_data="$(jq -r '.users[0].user["client-certificate-data"] // ""' <<<"${part_json}")"
    ck_data="$(jq -r '.users[0].user["client-key-data"] // ""' <<<"${part_json}")"
    if [[ -z "${token}" ]] && { [[ -z "${cc_data}" ]] || [[ -z "${ck_data}" ]]; }; then
      echo "ERROR: kubeconfig for context '${ctx}' has no static credentials this" >&2
      echo "  tool can merge (a bearer token, or a client cert+key pair). Bake" >&2
      echo "  static credentials, or pass it as the only --infra-kubeconfig." >&2
      exit 1
    fi

    # Rename cluster/user/context and strip basic auth, all inside jq — the only
    # jq inputs are the non-secret names. Write to a 0600 part JSON that the
    # KUBECONFIG merge below reads back.
    rfile="${scratch}/merge-part-${idx}.json"
    ( umask 077; : > "${rfile}" )
    jq --arg c "${cname}" --arg u "${uname_new}" --arg x "${newctx}" '
      .clusters[0].name = $c
      | .users[0].name = $u
      | .users[0].user |= del(.username, .password)
      | .contexts[0].name = $x
      | .contexts[0].context.cluster = $c
      | .contexts[0].context.user = $u
      | ."current-context" = $x
    ' <<<"${part_json}" > "${rfile}"
    renamed+=("${rfile}")

    idx=$((idx + 1))
  done

  # Combine every renamed part via kubectl's own KUBECONFIG merge. current-context
  # resolves to the first file's, which is first_ctx; use-context makes that
  # explicit regardless of merge order.
  #
  # 'command kubectl' bypasses the kubectl() wrapper in lib/platform.sh, which
  # forces '--kubeconfig ${SANDBOX_KUBECONFIG}' onto every call. An explicit
  # --kubeconfig flag overrides the KUBECONFIG env var, so through the wrapper
  # this merge would read the sandbox cluster's config instead of our renamed
  # parts. The per-part reads above are immune (their own --kubeconfig=… is a
  # later flag and wins), but the env-driven merge has no flag to win with.
  local kubeconfig_list
  kubeconfig_list="$(IFS=':'; printf '%s' "${renamed[*]}")"
  KUBECONFIG="${kubeconfig_list}" command kubectl config view --flatten --raw -o yaml > "${dest}"
  kubectl --kubeconfig="${dest}" config use-context "${first_ctx}" >/dev/null
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

# adopt_session_secrets — set an ownerReference on each of the session's
# credential Secrets so Kubernetes garbage-collects them when the session pod
# OBJECT is deleted without cmd_stop having run: a manual `kubectl delete pod`,
# a namespace teardown, or the eventual sweep of an Evicted pod. Owner-reference
# GC fires on DELETION of the owner, not on it terminating — a node-pressure
# eviction leaves the pod object behind in Failed/Evicted state, so it does NOT
# trigger this cascade. An evicted --keep-alive session's Secrets therefore stay
# live in the namespace until `sandbox stop` deletes the (Evicted) pod and the
# Secrets (see PRINCIPLES.md). This is a backstop for pod-deletion paths cmd_stop
# never runs on, not a revocation guarantee under eviction (PR #92 finding F3).
#
# The Secrets are created before the pod exists (they must be mountable at pod
# creation), so the owner UID is unknown at creation time; we patch it in here
# once the pod has been applied and has a UID — the same create-then-adopt
# pattern the Phase-5 dependency objects use (lib/dependency.sh). cmd_stop still
# deletes them explicitly, so this is a backstop for the paths cmd_stop never
# runs on, not a replacement for it. Owner and dependents share a namespace, as
# cross-namespace ownerReferences are disallowed. Best-effort per Secret: a
# patch failure only reverts that Secret to the label/explicit-delete path.
adopt_session_secrets() {
  local session_id="$1"
  local owner_name="$2"
  local owner_uid="$3"

  local secret
  local -a session_secrets=(
    "infra-token-${session_id}"
    "kubeconfig-${session_id}"
    "opencode-apikey-${session_id}"
    "$(session_secrets_name "${session_id}")"
  )

  # No pod UID (lookup failed, or the pod vanished before we read it): we cannot
  # set an ownerReference. Don't skip silently — but stay quiet for the common
  # tier-1 case with no Secrets. Warn only when a credential Secret actually
  # exists, so its operator learns it now rests entirely on `sandbox stop` for
  # revocation, with no GC backstop (R6).
  if [[ -z "${owner_name}" || -z "${owner_uid}" ]]; then
    for secret in "${session_secrets[@]}"; do
      if kubectl get secret -n "${SANDBOX_NAMESPACE}" "${secret}" &>/dev/null; then
        warn "Could not resolve pod UID for session ${session_id}; its credential" \
             "Secrets were not adopted for garbage collection and now rely on" \
             "'sandbox stop' for revocation."
        break
      fi
    done
    return 0
  fi

  local patch
  patch="$(cat <<EOF
{"metadata":{"ownerReferences":[{"apiVersion":"v1","kind":"Pod","name":"${owner_name}","uid":"${owner_uid}","controller":false,"blockOwnerDeletion":false}]}}
EOF
)"

  for secret in "${session_secrets[@]}"; do
    kubectl get secret -n "${SANDBOX_NAMESPACE}" "${secret}" &>/dev/null || continue
    kubectl patch secret -n "${SANDBOX_NAMESPACE}" "${secret}" \
      --type=merge -p "${patch}" >/dev/null 2>&1 \
      || warn "Could not set pod ownerReference on secret ${secret}; it will be" \
              "reaped by 'sandbox stop' but not garbage-collected if the pod" \
              "object is later deleted without it."
  done
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
