#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/dependency.sh — Per-session dependency pod + Service manifests (Phase 5)
#
# A declared dependency (MCP server or plain service) runs as its OWN gVisor
# pod with its own ClusterIP Service and its own narrow CiliumNetworkPolicy
# (lib/policy.sh), session-scoped and reaped at teardown. See
# docs/design/phase5-mcp-dependencies.md §2.3.
#
# ADDITIVE-FROM-EMPTY, on purpose (§2.3): this is a separate code path from
# build_pod_manifest (lib/manifest.sh), NOT that builder with mounts stripped.
# build_pod_manifest exists to mount the workspace, agent config, and session
# secrets; a dependency that started from it and *subtracted* would be one
# forgotten argument away from leaking the workspace into, say, a browser pod.
# A dependency manifest starts with ZERO volumes and ZERO secret-env and adds
# only what its catalogue entry declares — so a browser entry that declares
# nothing is empty by construction, not by remembering to strip things. The
# no-host-mounts invariant is additionally *checked* by
# check_dependency_no_host_mounts (lib/checks.sh) before apply.
#
# Ownership / teardown (§2.7 #6): every object carries an ownerReference to the
# session pod (Kubernetes GC reaps them if the CLI dies after the pod exists)
# PLUS the sandbox-session label (a label-keyed sweeper covers the window
# before the ownerRef is set). The session pod is a fine owner because deps are
# created only AFTER it is Ready and has a UID.
set -euo pipefail

# dependency_resource_name <dep_name> <session_id> — canonical Kubernetes object
# name for a dependency, used identically for the Pod, the Service, the
# sandbox-dependency label value, and therefore the in-cluster DNS name. Forced
# to a DNS-1123 label (lowercase alnum + '-') so a catalogue name with dots or
# capitals can't produce an invalid object/Service name.
dependency_resource_name() {
  local dep_name="$1" session_id="$2"
  local n
  n="$(echo "${dep_name}" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9-' '-' | sed 's/^-*//;s/-*$//')"
  echo "dep-${n}-${session_id}"
}

# dependency_service_fqdn <resource_name> — the cluster-local FQDN the session
# resolves + dials. Always the full svc.cluster.local form (never the one-dot
# shorthand) so it resolves in one absolute query under the session's ndots:1
# (see lib/policy.sh / §2.4).
dependency_service_fqdn() {
  echo "$1.${SANDBOX_NAMESPACE}.svc.cluster.local"
}

# _dependency_ownerref_block <owner_pod_name> <owner_pod_uid> — emit the
# metadata.ownerReferences block (4-space indented to sit under metadata:).
# Empty when the owner is unknown (e.g. dry-run before the pod exists), in which
# case the sandbox-session label + sweeper is the sole reaping path.
_dependency_ownerref_block() {
  local owner_name="$1" owner_uid="$2"
  [[ -z "${owner_name}" || -z "${owner_uid}" ]] && return 0
  cat <<EOF
  ownerReferences:
    - apiVersion: v1
      kind: Pod
      name: "${owner_name}"
      uid: "${owner_uid}"
      controller: false
      blockOwnerDeletion: false
EOF
}

# Image pull policy for dependency pods is IfNotPresent, NOT Never. Catalogue
# images come from a registry and are digest-pinned, so the digest already
# guarantees exact content; the kubelet uses a locally-present copy or pulls the
# pinned digest. (The agent images use Never because they are built locally and
# referenced by tag. A digest ref plus Never cannot be satisfied by a
# "docker save | k3s ctr images import", which stores by tag, not by repo-digest,
# so the kubelet reports ErrImageNeverPull. For an air-gapped node, pre-pull the
# digest into containerd with "k3s ctr images pull IMAGE@DIGEST" so it is
# present before launch.)
#
# build_dependency_pod_manifest — emit Pod YAML for one dependency.
# Signature:
#   build_dependency_pod_manifest <session_id> <tier> <dep_name> <resource_name> \
#       <catalogue_path> <owner_pod_name> <owner_pod_uid> <secret_bundle_name>
# secret_bundle_name empty = no secret env (the Phase-1 default; Phase 2 passes
# the per-dependency session-secret bundle name).
build_dependency_pod_manifest() {
  local session_id="$1"
  local tier="$2"
  local dep_name="$3"
  local resource_name="$4"
  local catalogue_path="$5"
  local owner_name="${6:-}"
  local owner_uid="${7:-}"
  local secret_bundle="${8:-}"

  local kind image port
  kind="$(catalogue_field "${catalogue_path}" kind)"
  image="$(catalogue_field "${catalogue_path}" image)"
  port="$(catalogue_field "${catalogue_path}" port)"

  local cpu_req cpu_lim mem_req mem_lim eph_lim run_as_user
  cpu_req="$(catalogue_field "${catalogue_path}" cpu_request "${CATALOGUE_DEFAULT_CPU_REQUEST}")"
  cpu_lim="$(catalogue_field "${catalogue_path}" cpu_limit "${CATALOGUE_DEFAULT_CPU_LIMIT}")"
  mem_req="$(catalogue_field "${catalogue_path}" mem_request "${CATALOGUE_DEFAULT_MEM_REQUEST}")"
  mem_lim="$(catalogue_field "${catalogue_path}" mem_limit "${CATALOGUE_DEFAULT_MEM_LIMIT}")"
  eph_lim="$(catalogue_field "${catalogue_path}" ephemeral_limit "${CATALOGUE_DEFAULT_EPHEMERAL_LIMIT}")"
  # Pin a non-root UID. Catalogue images commonly default to root; we set an
  # explicit runAsUser (default 1000) ALONGSIDE runAsNonRoot so the pod runs
  # non-root regardless of the image's default user, rather than being rejected
  # by the kubelet for "image will run as root". An entry whose image needs a
  # specific non-zero UID overrides via run_as_user (validation forbids 0).
  run_as_user="$(catalogue_field "${catalogue_path}" run_as_user "${CATALOGUE_DEFAULT_RUN_AS_USER}")"

  local ownerref_block
  ownerref_block="$(_dependency_ownerref_block "${owner_name}" "${owner_uid}")"

  # Optional secret env — ONLY when a bundle was provisioned for this dep.
  local env_from_block=""
  if [[ -n "${secret_bundle}" ]]; then
    env_from_block="$(cat <<EOF
      envFrom:
        - secretRef:
            name: "${secret_bundle}"
            optional: false
EOF
)"
  fi

  # Optional container command + args from the catalogue entry. A browser entry
  # pins its launch flags here (QUIC off, DoH off, --no-sandbox, --allowed-origins
  # mirroring the egress allowlist, --block-service-workers, no devtools — §1.8).
  # Rendered as YAML sequences so each token is quoted exactly once.
  # Assembled as a single block (with a trailing newline when non-empty) so it
  # drops cleanly into the heredoc on its own line; empty when the entry pins
  # neither, leaving the image's own ENTRYPOINT/CMD in force.
  local cmd_args_block=""
  local -a cmd_list=() arg_list=()
  read_into_array cmd_list < <(catalogue_list "${catalogue_path}" command)
  read_into_array arg_list < <(catalogue_list "${catalogue_path}" args)
  local tok
  if [[ "${#cmd_list[@]}" -gt 0 ]]; then
    cmd_args_block+="      command:"$'\n'
    for tok in "${cmd_list[@]}"; do cmd_args_block+="        - \"${tok}\""$'\n'; done
  fi
  if [[ "${#arg_list[@]}" -gt 0 ]]; then
    cmd_args_block+="      args:"$'\n'
    for tok in "${arg_list[@]}"; do cmd_args_block+="        - \"${tok}\""$'\n'; done
  fi
  cmd_args_block="${cmd_args_block%$'\n'}"

  # Optional sized /dev/shm. Headless Chromium crashes under the default 64Mi, so
  # a browser entry declares shm_size (an emptyDir backed by RAM). This is an
  # emptyDir, NOT a hostPath, so the no-host-mounts invariant still holds; an
  # alternative is the --disable-dev-shm-usage launch flag (§1.8).
  local shm_size shm_volume="" shm_mount=""
  shm_size="$(catalogue_field "${catalogue_path}" shm_size "")"
  if [[ -n "${shm_size}" ]]; then
    shm_mount="$(cat <<EOF
      volumeMounts:
        - name: dshm
          mountPath: /dev/shm
EOF
)"
    shm_volume="$(cat <<EOF
  volumes:
    - name: dshm
      emptyDir:
        medium: Memory
        sizeLimit: "${shm_size}"
EOF
)"
  fi

  cat <<EOF
---
apiVersion: v1
kind: Pod
metadata:
  name: "${resource_name}"
  namespace: "${SANDBOX_NAMESPACE}"
${ownerref_block}
  labels:
    sandbox-session: "${session_id}"
    sandbox-dependency: "${resource_name}"
    sandbox-dependency-name: "${dep_name}"
    sandbox-role: "dependency"
    sandbox-tier: "${tier}"
  annotations:
    sandbox-session: "${session_id}"
    sandbox-dependency: "${dep_name}"
spec:
  runtimeClassName: gvisor
  automountServiceAccountToken: false
  # ndots:1 mirrors the session pod (lib/manifest.sh): an allow-listed external
  # FQDN this dep is permitted to reach resolves in one absolute query instead
  # of walking the cluster search list, which the scoped DNS proxy would refuse.
  dnsConfig:
    options:
      - name: ndots
        value: "1"
  restartPolicy: Always
  securityContext:
    runAsUser: ${run_as_user}
    runAsGroup: ${run_as_user}
    fsGroup: ${run_as_user}
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: dependency
      image: "${image}"
      # IfNotPresent — see the lib comment above; the digest pins exact content.
      imagePullPolicy: IfNotPresent
${cmd_args_block}
      ports:
        - containerPort: ${port}
          protocol: TCP
      resources:
        limits:
          cpu: "${cpu_lim}"
          memory: "${mem_lim}"
          ephemeral-storage: "${eph_lim}"
        requests:
          cpu: "${cpu_req}"
          memory: "${mem_req}"
${env_from_block}
      securityContext:
        # Capabilities are DROPPED ALL and never added. A browser under gVisor
        # needs --no-sandbox (a launch flag), NOT --cap-add=SYS_ADMIN: adding any
        # capability to "restore" Chromium's own sandbox trades gVisor's
        # containment for a worse posture and is forbidden (§1.8). This builder
        # has no path to add a capability, so the ban is structural; catalogue
        # validation refuses cap_add/privileged entries as defense in depth.
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: false
        capabilities:
          drop:
            - ALL
${shm_mount}
  # A dependency mounts no workspace, no agent config, and no host directory —
  # closing upload-exfil via file-picker structurally (§2.2). The only volume an
  # entry may add is a RAM-backed /dev/shm emptyDir (shm_size) for headless
  # Chromium; an emptyDir is not a host mount, so the invariant still holds.
${shm_volume}
EOF
}

# build_dependency_service — emit ClusterIP Service YAML for one dependency.
# Signature:
#   build_dependency_service <session_id> <dep_name> <resource_name> <port> \
#       <owner_pod_name> <owner_pod_uid>
build_dependency_service() {
  local session_id="$1"
  local dep_name="$2"
  local resource_name="$3"
  local port="$4"
  local owner_name="${5:-}"
  local owner_uid="${6:-}"

  local ownerref_block
  ownerref_block="$(_dependency_ownerref_block "${owner_name}" "${owner_uid}")"

  cat <<EOF
---
apiVersion: v1
kind: Service
metadata:
  name: "${resource_name}"
  namespace: "${SANDBOX_NAMESPACE}"
${ownerref_block}
  labels:
    sandbox-session: "${session_id}"
    sandbox-dependency: "${resource_name}"
    sandbox-role: "dependency"
spec:
  type: ClusterIP
  selector:
    sandbox-dependency: "${resource_name}"
  ports:
    - name: mcp
      port: ${port}
      targetPort: ${port}
      protocol: TCP
EOF
}

###############################################################################
# Orchestration (lifecycle). Mirrors the secrets lifecycle (lib/secrets.sh):
# resolve-in-profile → bring-up-at-launch keyed to session → reap-at-teardown.
###############################################################################

# session_mcp_configmap_name <session_id> — canonical ConfigMap name holding
# the per-session MCP registration the agent is launched against.
session_mcp_configmap_name() {
  echo "mcp-config-$1"
}

# resolve_session_dependencies <session_id> <agent> — parse the comma-joined
# SESSION_PROFILE_MCPS / SESSION_PROFILE_SERVICES (set during profile
# resolution), resolve and validate each against the catalogue, and populate the
# SESSION_DEP_* globals the launch + teardown paths consume. Cluster-independent,
# so it fails fast and closed: an unknown name, an invalid entry, an mcps: entry
# for an agent without MCP wiring, or a declared secret missing from the
# host-side store all abort before any cluster object exists.
#
# Populates (declared global):
#   SESSION_DEP_NAMES[]           catalogue names, in declared order
#   SESSION_DEP_KINDS[]           mcp | service
#   SESSION_DEP_RESOURCE_NAMES[]  dep-<name>-<session_id>
#   SESSION_DEP_PORTS[]
#   SESSION_DEP_PATHS[]           resolved catalogue YAML path
#   SESSION_DEP_ENDPOINTS_PENDING[]  "resource_name port" (wired into the session
#                                    policy only AFTER the identity assertion)
#   SESSION_MCP_SERVER_RECORDS[]  "name|transport|url" for render_agent_mcp_config
#   SESSION_HAS_DEPS              true|false
#   SESSION_HAS_MCPS             true|false   (consumed by lib/manifest.sh)
#   SESSION_MCP_CONFIGMAP        ConfigMap name (consumed by lib/manifest.sh)
resolve_session_dependencies() {
  local session_id="$1"
  local agent="$2"

  # Global arrays (consumed by manifest/secrets builders in other functions).
  # Plain assignment to an un-'local'-ized name sets the global in bash 3.2+,
  # so we avoid `declare -g` (bash 4.2+, absent from macOS's stock bash 3.2).
  SESSION_DEP_NAMES=(); SESSION_DEP_KINDS=()
  SESSION_DEP_RESOURCE_NAMES=(); SESSION_DEP_PORTS=()
  SESSION_DEP_PATHS=(); SESSION_DEP_ENDPOINTS_PENDING=()
  SESSION_DEP_SECRETS=(); SESSION_MCP_SERVER_RECORDS=()
  SESSION_HAS_DEPS="false"
  SESSION_HAS_MCPS="false"
  SESSION_MCP_CONFIGMAP=""

  # Build (name, declared-kind) pairs from the two lists. The declared kind is
  # how the profile asked for it; it must agree with the catalogue entry's own
  # kind (an mcps: entry must be kind: mcp), which we check below.
  local -a pending=()
  local _ifs="${IFS}" item
  IFS=','
  for item in ${SESSION_PROFILE_MCPS:-}; do
    item="$(echo "${item}" | tr -d '[:space:]')"
    [[ -n "${item}" ]] && pending+=("mcp:${item}")
  done
  for item in ${SESSION_PROFILE_SERVICES:-}; do
    item="$(echo "${item}" | tr -d '[:space:]')"
    [[ -n "${item}" ]] && pending+=("service:${item}")
  done
  IFS="${_ifs}"

  [[ "${#pending[@]}" -eq 0 ]] && return 0

  # Per-session dependency ceiling (§2.7 #5). Fail fast with a clear message
  # rather than letting an absurd profile schedule a swarm of pods that then sit
  # Pending against the namespace ResourceQuota.
  local max_deps="${SANDBOX_MAX_DEPS_PER_SESSION:-6}"
  if [[ "${#pending[@]}" -gt "${max_deps}" ]]; then
    echo "ERROR: profile declares ${#pending[@]} dependencies, over the per-session" >&2
    echo "       ceiling of ${max_deps}. Trim the profile, or raise" >&2
    echo "       SANDBOX_MAX_DEPS_PER_SESSION if your node can carry more." >&2
    return 1
  fi

  local pair declared_kind name path kind port transport mpath fqdn url
  for pair in "${pending[@]}"; do
    declared_kind="${pair%%:*}"
    name="${pair#*:}"

    path="$(catalogue_resolve "${name}" || true)"
    if [[ -z "${path}" ]]; then
      echo "ERROR: profile declares dependency '${name}' but no catalogue entry" >&2
      echo "       was found (config/catalogue/ or the overlay's catalogue/)." >&2
      return 1
    fi
    if ! catalogue_validate_entry "${path}" "${name}"; then
      return 1
    fi

    kind="$(catalogue_field "${path}" kind)"
    port="$(catalogue_field "${path}" port)"

    # The list a dependency was declared in must match the catalogue kind: a
    # plain service requested under mcps: would never get an MCP registration
    # (and vice versa), so reject the mismatch rather than silently mis-wire.
    if [[ "${declared_kind}" != "${kind}" ]]; then
      echo "ERROR: dependency '${name}' is declared under '${declared_kind}s:'" >&2
      echo "       but its catalogue entry is kind '${kind}'. Move it to the" >&2
      echo "       '${kind}s:' list." >&2
      return 1
    fi

    local rname
    rname="$(dependency_resource_name "${name}" "${session_id}")"

    # Declared secrets (Phase 4 names) must exist in the host-side store now, so
    # a missing one fails the launch before any cluster object is created — the
    # same fail-fast the agent's own profile secrets get (bin/sandbox).
    local -a dep_secrets=()
    read_into_array dep_secrets < <(catalogue_list "${path}" secrets)
    local sname
    for sname in "${dep_secrets[@]+"${dep_secrets[@]}"}"; do
      [[ -z "${sname}" ]] && continue
      if ! secret_exists "${sname}"; then
        echo "ERROR: dependency '${name}' requires secret '${sname}' but it is" >&2
        echo "       not in the host-side store. Run 'sandbox secret set ${sname}'." >&2
        return 1
      fi
    done

    SESSION_DEP_NAMES+=("${name}")
    SESSION_DEP_KINDS+=("${kind}")
    SESSION_DEP_RESOURCE_NAMES+=("${rname}")
    SESSION_DEP_PORTS+=("${port}")
    SESSION_DEP_PATHS+=("${path}")
    SESSION_DEP_ENDPOINTS_PENDING+=("${rname} ${port}")
    SESSION_DEP_SECRETS+=("$(printf '%s,' "${dep_secrets[@]+"${dep_secrets[@]}"}" | sed 's/,$//')")

    if [[ "${kind}" == "mcp" ]]; then
      if ! agent_supports_mcp "${agent}"; then
        echo "ERROR: profile declares MCP dependency '${name}', but agent" >&2
        echo "       '${agent}' has no per-session MCP wiring yet (only 'claude'" >&2
        echo "       is supported). Remove it or use --agent claude." >&2
        return 1
      fi
      SESSION_HAS_MCPS="true"
      transport="$(catalogue_field "${path}" mcp_transport http)"
      mpath="$(catalogue_field "${path}" mcp_path /mcp)"
      fqdn="$(dependency_service_fqdn "${rname}")"
      # In-cluster plain HTTP — the ClusterIP Service is internal; the egress
      # 443 rules don't apply to a toEndpoints-reached sibling. The connection
      # is governed by the toEndpoints rule + the dep's ingress policy.
      url="http://${fqdn}:${port}${mpath}"
      SESSION_MCP_SERVER_RECORDS+=("${name}|${transport}|${url}")
    fi
  done

  SESSION_HAS_DEPS="true"
  if [[ "${SESSION_HAS_MCPS}" == "true" ]]; then
    SESSION_MCP_CONFIGMAP="$(session_mcp_configmap_name "${session_id}")"
  fi
  export SESSION_HAS_MCPS SESSION_MCP_CONFIGMAP

  # A browser dependency strictly increases the in-allowlist exfil surface and
  # that increase is not removable by policy (§1.7). Enabling it is a conscious
  # choice, not a surprise — name the residual cost at launch, loudly when a
  # wildcard allowed domain (a possible exfil sink) is also in play.
  local p _class
  for p in "${SESSION_DEP_PATHS[@]}"; do
    _class="$(catalogue_field "${p}" class)"
    if [[ "${_class}" == "browser" ]]; then
      echo "WARN: this session includes a browser dependency. Even fully" >&2
      echo "      contained, a browser is a richer exfiltration channel WITHIN" >&2
      echo "      the allowlist than the bare agent (it can POST bodies, open" >&2
      echo "      WebSockets, and encode data into a wildcard-allowed domain)." >&2
      echo "      Audit sees destination granularity, not URL paths or bodies" >&2
      echo "      inside TLS (§1.7). Keep the allowlist tight." >&2
      break
    fi
  done
  return 0
}

# render_mcp_configmap <session_id> <agent> — emit the per-session MCP ConfigMap
# YAML (used for dry-run and apply). The agent MCP config JSON is embedded under
# the data key the pod mounts as the config file (lib/agents.sh).
render_mcp_configmap() {
  local session_id="$1" agent="$2"
  local cm_name
  cm_name="$(session_mcp_configmap_name "${session_id}")"

  local config_json
  config_json="$(render_agent_mcp_config "${agent}" \
    "${SESSION_MCP_SERVER_RECORDS[@]+"${SESSION_MCP_SERVER_RECORDS[@]}"}")"

  # Indent the JSON under the data key as a YAML block scalar so arbitrary JSON
  # (braces, quotes) survives without escaping.
  local indented
  indented="$(echo "${config_json}" | sed 's/^/    /')"

  cat <<EOF
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: "${cm_name}"
  namespace: "${SANDBOX_NAMESPACE}"
  labels:
    sandbox-session: "${session_id}"
    sandbox-role: "dependency"
data:
  ${SANDBOX_MCP_CONFIG_FILE}: |
${indented}
EOF
}

# create_mcp_configmap <session_id> <agent> — apply the per-session MCP
# ConfigMap. Must run BEFORE the session pod is applied, since the pod mounts it.
create_mcp_configmap() {
  local session_id="$1" agent="$2"
  render_mcp_configmap "${session_id}" "${agent}" | kubectl apply -f - >/dev/null
  echo "  Created MCP config: $(session_mcp_configmap_name "${session_id}") (${#SESSION_MCP_SERVER_RECORDS[@]} server(s))"
}

# bring_up_dependencies <session_id> <tier> <owner_pod_name> <owner_pod_uid> \
#                       <log_dir> — create each dependency's CNP, Pod, and
# Service (ownerRef'd to the session pod), then wait for each to become Ready.
# Returns non-zero on the first failure so the caller can tear down and abort
# (fail-closed: a profile asked for the dependency for a reason). Does NOT exit
# the process itself — wait_for_pod is run in a subshell so its exit is trapped.
bring_up_dependencies() {
  local session_id="$1" tier="$2" owner_name="$3" owner_uid="$4" log_dir="$5"

  local i name kind rname port path catpath
  for i in "${!SESSION_DEP_NAMES[@]}"; do
    name="${SESSION_DEP_NAMES[$i]}"
    rname="${SESSION_DEP_RESOURCE_NAMES[$i]}"
    port="${SESSION_DEP_PORTS[$i]}"
    catpath="${SESSION_DEP_PATHS[$i]}"

    echo "  Dependency '${name}' → ${rname}"

    # The dependency's own egress allowlist from its catalogue entry.
    local -a egress=()
    read_into_array egress < <(catalogue_list "${catpath}" egress)

    # Provision the dependency's secret bundle (if any) BEFORE its pod, so the
    # pod's envFrom can reference it. SESSION_DEP_SECRETS[i] is a comma-joined
    # list (validated to exist at resolve time).
    local secret_bundle=""
    local dep_secret_csv="${SESSION_DEP_SECRETS[$i]:-}"
    if [[ -n "${dep_secret_csv}" ]]; then
      local -a dep_secret_names=()
      IFS=',' read -ra dep_secret_names <<< "${dep_secret_csv}"
      create_dependency_secrets "${rname}" "${session_id}" "${dep_secret_names[@]}"
      secret_bundle="${rname}-secrets"
    fi

    local dep_policy dep_pod dep_svc
    dep_policy="$(build_dependency_policy "${session_id}" "${rname}" "${port}" \
      "${egress[@]+"${egress[@]}"}")"
    dep_pod="$(build_dependency_pod_manifest "${session_id}" "${tier}" "${name}" \
      "${rname}" "${catpath}" "${owner_name}" "${owner_uid}" "${secret_bundle}")"
    dep_svc="$(build_dependency_service "${session_id}" "${name}" "${rname}" \
      "${port}" "${owner_name}" "${owner_uid}")"

    # Enforced invariant: a dependency pod never carries a host mount (§2.3).
    check_dependency_no_host_mounts "${dep_pod}"

    echo "${dep_policy}" | kubectl apply -f - >/dev/null || return 1
    echo "${dep_svc}"    | kubectl apply -f - >/dev/null || return 1
    echo "${dep_pod}"    | kubectl apply -f - >/dev/null || return 1

    # Subshell so wait_for_pod's exit-on-failure is caught here instead of
    # killing the whole launch without teardown.
    if ! ( wait_for_pod "${rname}" ); then
      echo "ERROR: dependency '${name}' (${rname}) did not become ready." >&2
      return 1
    fi
  done
  return 0
}

# session_dependencies_audit_json <up_time> — emit the JSON array of resolved
# dependency records for the audit trail (consumed by audit_record_dependencies).
# Reads the SESSION_DEP_* globals populated by resolve_session_dependencies, plus
# each entry's catalogue version + resolved egress allowlist.
session_dependencies_audit_json() {
  local up_time="$1"
  local arr="[]"
  local i name kind rname port catpath version
  for i in "${!SESSION_DEP_NAMES[@]}"; do
    name="${SESSION_DEP_NAMES[$i]}"
    kind="${SESSION_DEP_KINDS[$i]}"
    rname="${SESSION_DEP_RESOURCE_NAMES[$i]}"
    port="${SESSION_DEP_PORTS[$i]}"
    catpath="${SESSION_DEP_PATHS[$i]}"
    version="$(catalogue_field "${catpath}" version "")"

    local egress_json="[]"
    egress_json="$(catalogue_list "${catpath}" egress | jq -R . | jq -s -c .)"

    arr="$(echo "${arr}" | jq \
      --arg name "${name}" \
      --arg kind "${kind}" \
      --arg rname "${rname}" \
      --argjson port "${port}" \
      --arg version "${version}" \
      --argjson egress "${egress_json}" \
      --arg up "${up_time}" \
      '. += [{
        name: $name,
        kind: $kind,
        resource_name: $rname,
        port: $port,
        version: $version,
        egress: $egress,
        up_time: $up,
        down_time: null
      }]')"
  done
  echo "${arr}"
}

# teardown_dependencies <session_id> — reap every per-session dependency object.
# Primary reap is by ownerReference (Kubernetes GC removes them when the session
# pod is deleted); this is the label-keyed backstop covering the window before a
# pod's ownerRef is set and the case where the pod was never created. Also
# removes the MCP ConfigMap. Idempotent / best-effort, like delete_*_secret.
teardown_dependencies() {
  local session_id="$1"
  local sel="sandbox-session=${session_id},sandbox-role=dependency"

  kubectl delete pod,service,ciliumnetworkpolicy,secret -n "${SANDBOX_NAMESPACE}" \
    -l "${sel}" --ignore-not-found=true >/dev/null 2>&1 || true

  kubectl delete configmap -n "${SANDBOX_NAMESPACE}" \
    "$(session_mcp_configmap_name "${session_id}")" \
    --ignore-not-found=true >/dev/null 2>&1 || true
}
