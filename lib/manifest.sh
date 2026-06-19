#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/manifest.sh — Pod manifest generation
set -euo pipefail

# build_pod_manifest — emit complete pod YAML for a session
build_pod_manifest() {
  local session_id="$1"
  local agent="$2"
  local tier="$3"
  local image="$4"
  local name="${5:-}"
  local current_user="${6:-unknown}"
  local infra_token="${7:-}"
  local pod_name="${8:-sandbox-${session_id}}"
  # "1" if --infra-kubeconfig was supplied (mount kubeconfig secret + set KUBECONFIG)
  local infra_kubeconfig="${9:-}"
  # Optional hostAlias for the kube API server (so pod DNS doesn't need to
  # know about it). Both must be set together.
  local kube_alias_ip="${10:-}"
  local kube_alias_host="${11:-}"
  shift 11
  # Repos — one or more host paths to mount as workspaces; variadic at the
  # end so callers can pass an array. Empty for Tier 1.
  local -a repos=("$@")

  # Build env vars block
  local env_block
  env_block="$(build_env_block "${agent}" "${session_id}" "${infra_token}" "${infra_kubeconfig}")"

  # Build volumes block
  # Host-side persistent directory for agent config (auth tokens, session state).
  # Mounted at the agent's specific config subdirectory — NOT /home/agent — so
  # the installed binaries baked into the image are not shadowed.
  local agent_home="${HOME}/.sandbox/agent-home/${agent}"
  local agent_config_mount
  case "${agent}" in
    claude)   agent_config_mount="/home/agent/.claude" ;;
    codex)    agent_config_mount="/home/agent/.codex" ;;
    opencode) agent_config_mount="/home/agent/.local/share/opencode" ;;
    *)        agent_config_mount="/home/agent/.${agent}" ;;
  esac
  local volumes_block
  volumes_block="$(build_volumes_block "${tier}" "${agent_home}" "${session_id}" "${infra_kubeconfig}" "${repos[@]+"${repos[@]}"}")"

  # Build volumeMounts block
  local mounts_block
  mounts_block="$(build_volume_mounts_block "${tier}" "${agent_home}" "${agent_config_mount}" "${infra_kubeconfig}" "${repos[@]+"${repos[@]}"}")"

  # Phase 5 — per-session MCP config. When the profile declared MCP
  # dependencies, mount the session-scoped ConfigMap (built by bin/sandbox after
  # the dependency Services resolve) read-only at SANDBOX_MCP_CONFIG_DIR. The
  # agent is then launched with --mcp-config pointing at it (lib/agents.sh).
  # Mounted from a ConfigMap, NOT the shared agent-home hostPath, so it is
  # session-scoped and reaped with the session.
  if [[ "${SESSION_HAS_MCPS:-false}" == "true" ]] && [[ -n "${SESSION_MCP_CONFIGMAP:-}" ]]; then
    volumes_block+=$'\n'"$(cat <<EOF
    - name: mcp-config
      configMap:
        name: "${SESSION_MCP_CONFIGMAP}"
EOF
)"
    mounts_block+=$'\n'"$(cat <<EOF
        - name: mcp-config
          mountPath: ${SANDBOX_MCP_CONFIG_DIR}
          readOnly: true
EOF
)"
  fi

  # envFrom: bundle infra-token (Tier 3 with --infra-token) and the
  # profile-declared session-secrets Secret (set via SESSION_HAS_SECRETS
  # by bin/sandbox after profile resolution). Either or both may be
  # present; the helper emits a single envFrom: header when needed.
  local env_from_block=""
  local _has_infra="false"
  [[ "${tier}" -eq 3 ]] && [[ -n "${infra_token}" ]] && _has_infra="true"
  local _has_secrets="${SESSION_HAS_SECRETS:-false}"
  if [[ "${_has_infra}" == "true" ]] || [[ "${_has_secrets}" == "true" ]]; then
    env_from_block="$(build_env_from_block "${session_id}" "${_has_infra}" "${_has_secrets}")"
  fi

  # Name annotation
  local name_annotation=""
  if [[ -n "${name}" ]]; then
    name_annotation="    sandbox-name: \"${name}\""
  fi

  # hostAliases block — only when both pieces are present.
  local host_aliases_block=""
  if [[ -n "${kube_alias_ip}" ]] && [[ -n "${kube_alias_host}" ]]; then
    host_aliases_block="$(cat <<EOF
  hostAliases:
    - ip: "${kube_alias_ip}"
      hostnames:
        - "${kube_alias_host}"
EOF
)"
  fi

  cat <<EOF
---
apiVersion: v1
kind: Pod
metadata:
  name: "${pod_name}"
  namespace: "${SANDBOX_NAMESPACE}"
  labels:
    sandbox-agent: "${agent}"
    sandbox-tier: "${tier}"
    sandbox-session: "${session_id}"
    sandbox-user: "${current_user}"
    # Distinguishes the session pod from its dependency pods (which carry
    # sandbox-role: dependency). A dependency's ingress rule (lib/policy.sh) is
    # scoped to {sandbox-session, sandbox-role: session} so it accepts the
    # owning session pod alone — never a sibling dependency. (Phase 5)
    sandbox-role: "session"
  annotations:
    sandbox-session: "${session_id}"
    sandbox-agent: "${agent}"
${name_annotation}
spec:
  runtimeClassName: gvisor
  serviceAccountName: ${SANDBOX_SERVICE_ACCOUNT}
  automountServiceAccountToken: false
  hostname: sandbox
${host_aliases_block}
  restartPolicy: Always
  # ndots:1 so external FQDN lookups (api.anthropic.com, chatgpt.com, …) are
  # tried as absolute names FIRST, before the cluster search-domain
  # permutations ("<fqdn>.<ns>.svc.cluster.local", "<fqdn>.cluster.local", …).
  # The session policy scopes the L7 DNS proxy to the FQDN allowlist
  # (lib/policy.sh), so under the cluster-default ndots:5 the resolver would
  # emit those permutations first, the proxy would refuse them (not in the
  # allowlist), and resolution of even allow-listed domains would stall or fail
  # — breaking agent auth/MCP. With ndots:1 the absolute, allow-listed name
  # resolves on the first query and the permutations are never sent.
  dnsConfig:
    options:
      - name: ndots
        value: "1"
  securityContext:
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: agent
      image: "${image}"
      imagePullPolicy: Never
      # Override ENTRYPOINT so the container waits rather than running the agent
      # as PID 1.  The agent is launched via 'kubectl exec -it' so it inherits
      # the calling terminal's dimensions (kubectl attach uses the container's
      # pre-existing PTY which defaults to 80 columns).
      command: ["sleep", "infinity"]
      resources:
        limits:
          cpu: "${POD_CPU_LIMIT}"
          memory: "${POD_MEM_LIMIT_GI}Gi"
          ephemeral-storage: "${POD_EPHEMERAL_LIMIT_GI}Gi"
        requests:
          cpu: "${POD_CPU_REQUEST}"
          memory: "${POD_MEM_REQUEST_GI}Gi"
          ephemeral-storage: "${POD_EPHEMERAL_REQUEST_GI}Gi"
      env:
${env_block}
${env_from_block}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: false
        capabilities:
          drop:
            - ALL
      volumeMounts:
${mounts_block}
      stdin: true
      tty: true
  volumes:
${volumes_block}
EOF
}

# build_env_block — emit env: list entries for the container
build_env_block() {
  local agent="$1"
  local session_id="$2"
  local infra_token="${3:-}"
  local infra_kubeconfig="${4:-}"

  cat <<'EOF'
        - name: HOME
          value: "/home/agent"
        - name: TERM
          value: "xterm-256color"
        - name: COLORTERM
          value: "truecolor"
EOF

  # Point KUBECONFIG at the mounted Secret when --infra-kubeconfig was supplied.
  # Mount path matches build_volume_mounts_block (subPath 'config').
  if [[ -n "${infra_kubeconfig}" ]]; then
    cat <<'EOF'
        - name: KUBECONFIG
          value: "/home/agent/.kube/config"
EOF
  fi

  # claude: CLAUDE_CONFIG_DIR moves ~/.claude.json (OAuth/onboarding session
  # state) into the persisted .claude mount. Without it that file lands on the
  # ephemeral root fs and Claude re-runs login every session despite a valid
  # .credentials.json. Cannot mount over /home/agent — the claude binary is
  # baked into /home/agent/.local/bin.
  if [[ "${agent}" == "claude" ]]; then
    cat <<'EOF'
        - name: CLAUDE_CONFIG_DIR
          value: "/home/agent/.claude"
EOF
  fi

  # opencode: inject API key and base URL
  if [[ "${agent}" == "opencode" ]]; then
    local api_key="${OPENCODE_API_KEY:-}"
    local base_url="${OPENCODE_BASE_URL:-}"
    if [[ -z "${api_key}" ]]; then
      echo "ERROR: OPENCODE_API_KEY not set in host environment." >&2
      exit 1
    fi
    if [[ -z "${base_url}" ]]; then
      echo "ERROR: OPENCODE_BASE_URL not set in host environment." >&2
      echo "  Set it to the URL of an OpenAI-compatible endpoint." >&2
      exit 1
    fi
    # We inject via a Kubernetes Secret rather than plaintext YAML
    # The secret is created in cmd_run before this function is called.
    cat <<EOF
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: "opencode-apikey-${session_id}"
              key: OPENAI_API_KEY
              optional: false
        - name: OPENCODE_CONFIG_CONTENT
          valueFrom:
            secretKeyRef:
              name: "opencode-apikey-${session_id}"
              key: OPENCODE_CONFIG_CONTENT
              optional: false
        - name: OPENAI_BASE_URL
          value: "${base_url}"
EOF
  fi

  # claude/codex: MUST NOT have ANTHROPIC_API_KEY or OPENAI_API_KEY
  # (enforced by omission — these agents authenticate via OAuth)
}

# build_env_from_block — emit pod envFrom: list referencing the
# infra-token Secret (Tier 3 --infra-token) and/or the session-secrets
# Secret (profile-declared `secrets:`). The two flags let callers
# select which refs to include; at least one must be true (callers
# gate the call so it never produces a stray empty `envFrom:`).
#
# Signature: build_env_from_block <session_id> <has_infra> <has_secrets>
build_env_from_block() {
  local session_id="$1"
  local has_infra="${2:-false}"
  local has_secrets="${3:-false}"

  echo "      envFrom:"
  if [[ "${has_infra}" == "true" ]]; then
    cat <<EOF
        - secretRef:
            name: "infra-token-${session_id}"
            optional: false
EOF
  fi
  if [[ "${has_secrets}" == "true" ]]; then
    cat <<EOF
        - secretRef:
            name: "$(session_secrets_name "${session_id}")"
            optional: false
EOF
  fi
}

# Multi-repo naming helpers — for a single repo we keep the legacy
# "workspace" / "overlay-kube-dir" / "/workspace" names (backward-compat with
# describe output); for >1 we suffix with the index.
_workspace_volume_name() {
  local idx="$1" total="$2"
  if [[ "${total}" -eq 1 ]]; then echo "workspace"
  else echo "workspace-${idx}"
  fi
}
_kube_overlay_volume_name() {
  local idx="$1" total="$2"
  if [[ "${total}" -eq 1 ]]; then echo "overlay-kube-dir"
  else echo "overlay-kube-dir-${idx}"
  fi
}
_workspace_mount_path() {
  local repo="$1" total="$2"
  if [[ "${total}" -eq 1 ]]; then echo "/workspace"
  else echo "/workspace/$(basename "${repo}")"
  fi
}

# build_volumes_block — emit volumes: list for pod spec
# Signature: build_volumes_block <tier> <agent_home> <session_id> <infra_kubeconfig> [repo1 ...]
build_volumes_block() {
  local tier="$1"
  local agent_home="${2:-}"
  local session_id="${3:-}"
  local infra_kubeconfig="${4:-}"
  shift 4
  local -a repos=("$@")
  local total="${#repos[@]}"

  # Tier 1: only emptyDir workspace
  if [[ "${tier}" -eq 1 ]]; then
    cat <<'EOF'
    - name: workspace
      emptyDir: {}
    - name: tmp
      emptyDir: {}
EOF
    [[ -n "${agent_home}" ]] && cat <<EOF
    - name: agent-home
      hostPath:
        path: "${agent_home}"
        type: Directory
EOF
    return 0
  fi

  # Tier 2/3: one hostPath volume per --repo + shared tmp + conditional overlays.
  local i r vname
  for i in "${!repos[@]}"; do
    r="${repos[$i]}"
    vname="$(_workspace_volume_name "$i" "${total}")"
    cat <<EOF
    - name: ${vname}
      hostPath:
        path: "${r}"
        type: Directory
EOF
  done

  cat <<'EOF'
    - name: tmp
      emptyDir: {}
EOF

  # Sensitive *files* are masked with the shared empty host file (FileOrCreate);
  # the .kube *directory* per repo is masked with its own emptyDir. The two
  # cannot be swapped — mounting a directory volume onto a file path (or vice
  # versa) crashes gVisor at container start. The masked-path set is defined
  # in lib/filesystem.sh (MASKED_FILE_PATHS, MASKED_DIR_PATH,
  # MASKED_OPENRC_PATTERN). lib/filesystem.sh:check_masking_paths refuses to
  # launch if any workspace path is the wrong type for its mask, so the
  # `-f` / `-type f` filters below are defense in depth.

  # The overlay-empty-file host volume is shared across every repo's file
  # overlays; emit it once if ANY repo has any masked file.
  local has_any_masked_file=false f
  for r in "${repos[@]}"; do
    for f in "${MASKED_FILE_PATHS[@]}"; do
      [[ -f "${r}/${f}" ]] && has_any_masked_file=true
    done
    [[ -n "$(find "${r}" -maxdepth 1 -name "${MASKED_OPENRC_PATTERN}" -type f -print -quit 2>/dev/null)" ]] \
      && has_any_masked_file=true
  done
  if [[ "${has_any_masked_file}" == true ]]; then
    cat <<EOF
    - name: overlay-empty-file
      hostPath:
        path: "${HOME}/.sandbox/overlay-empty"
        type: FileOrCreate
EOF
  fi

  # Per-repo .kube emptyDir overlays (each repo gets its own to avoid cross-
  # pollution between mount targets).
  for i in "${!repos[@]}"; do
    if [[ -d "${repos[$i]}/${MASKED_DIR_PATH}" ]]; then
      local kdname
      kdname="$(_kube_overlay_volume_name "$i" "${total}")"
      printf '    - name: %s\n      emptyDir: {}\n' "${kdname}"
    fi
  done

  [[ -n "${agent_home}" ]] && cat <<EOF
    - name: agent-home
      hostPath:
        path: "${agent_home}"
        type: Directory
EOF

  cat <<EOF
    # gitconfig read-only from host
    - name: gitconfig
      hostPath:
        path: "${HOME}/.gitconfig"
        type: FileOrCreate
EOF

  # Tier 3 only: operator-supplied kubeconfig mounted from a per-session Secret.
  # Secret is created in cmd_run before the pod is applied; deleted by cmd_stop.
  if [[ -n "${infra_kubeconfig}" ]] && [[ -n "${session_id}" ]]; then
    cat <<EOF
    - name: infra-kubeconfig
      secret:
        secretName: "kubeconfig-${session_id}"
        # 0440 octal — owner+group read; pod fsGroup=1000 grants the agent read.
        defaultMode: 288
        optional: false
EOF
  fi
}

# build_volume_mounts_block — emit volumeMounts: list for container
# Signature: build_volume_mounts_block <tier> <agent_home> <agent_config_mount> <infra_kubeconfig> [repo1 ...]
build_volume_mounts_block() {
  local tier="$1"
  local agent_home="${2:-}"
  local agent_config_mount="${3:-}"
  local infra_kubeconfig="${4:-}"
  shift 4
  local -a repos=("$@")
  local total="${#repos[@]}"

  if [[ "${tier}" -eq 1 ]]; then
    cat <<'EOF'
        - name: workspace
          mountPath: /workspace
        - name: tmp
          mountPath: /tmp
EOF
    [[ -n "${agent_home}" ]] && printf '        - name: agent-home\n          mountPath: %s\n' "${agent_config_mount}"
    return 0
  fi

  # Tier 2/3: emit each repo's workspace mount, then tmp, then each repo's
  # overlay mounts. This mirrors the order in build_volumes_block.
  local i r vname mpath mp openrc_file kdname
  for i in "${!repos[@]}"; do
    r="${repos[$i]}"
    vname="$(_workspace_volume_name "$i" "${total}")"
    mpath="$(_workspace_mount_path "$r" "${total}")"
    printf '        - name: %s\n          mountPath: %s\n' "${vname}" "${mpath}"
  done

  printf '        - name: tmp\n          mountPath: /tmp\n'

  # with the shared empty file (read-only); mask each repo's .kube directory
  # with its own emptyDir. Only mount overlays for paths that exist in the repo.
  for i in "${!repos[@]}"; do
    r="${repos[$i]}"
    mpath="$(_workspace_mount_path "$r" "${total}")"

    for mp in "${MASKED_FILE_PATHS[@]}"; do
      [[ -f "${r}/${mp}" ]] \
        && printf '        - name: overlay-empty-file\n          mountPath: %s/%s\n          readOnly: true\n' \
          "${mpath}" "${mp}"
    done
    while IFS= read -r openrc_file; do
      printf '        - name: overlay-empty-file\n          mountPath: %s/%s\n          readOnly: true\n' \
        "${mpath}" "$(basename "${openrc_file}")"
    done < <(find "${r}" -maxdepth 1 -name "${MASKED_OPENRC_PATTERN}" -type f -print 2>/dev/null | sort)
    if [[ -d "${r}/${MASKED_DIR_PATH}" ]]; then
      kdname="$(_kube_overlay_volume_name "$i" "${total}")"
      printf '        - name: %s\n          mountPath: %s/%s\n' "${kdname}" "${mpath}" "${MASKED_DIR_PATH}"
    fi
  done

  [[ -n "${agent_home}" ]] && printf '        - name: agent-home\n          mountPath: %s\n' "${agent_config_mount}"

  cat <<'EOF'
        - name: gitconfig
          mountPath: /home/agent/.gitconfig
          readOnly: true
EOF

  # Tier 3 only: kubeconfig Secret mounted as a single file via subPath, so
  # the rest of /home/agent/.kube/ (e.g. cache dirs) remains writable.
  if [[ -n "${infra_kubeconfig}" ]]; then
    cat <<'EOF'
        - name: infra-kubeconfig
          mountPath: /home/agent/.kube/config
          subPath: config
          readOnly: true
EOF
  fi
}
