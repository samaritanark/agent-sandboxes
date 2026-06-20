#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/lima.sh — Lima VM management helpers (macOS only)
set -euo pipefail

LIMA_VM_NAME="${LIMA_VM_NAME:-sandbox-vm}"
# Lima config is rendered from a template (port substituted) by setup/macos.sh.
LIMA_TEMPLATE="${SANDBOX_ROOT}/lima/sandbox-vm.yaml.tmpl"
LIMA_CONFIG="${HOME}/.sandbox/lima-sandbox-vm.yaml"

# lima_vm_running — returns 0 if VM is running
lima_vm_running() {
  if ! command -v limactl &>/dev/null; then
    return 1
  fi
  local status
  status="$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null \
    | awk -v vm="${LIMA_VM_NAME}" '$1==vm {print $2}')"
  [[ "${status}" == "Running" ]]
}

# ensure_lima_running — start Lima VM if not already running (macOS only)
ensure_lima_running() {
  if ! is_macos; then
    return 0
  fi

  require_command limactl "Install Lima: brew install lima"

  if lima_vm_running; then
    return 0
  fi

  local existing
  existing="$(limactl list --format '{{.Name}}' 2>/dev/null | grep -x "${LIMA_VM_NAME}" || true)"

  if [[ -z "${existing}" ]]; then
    if [[ ! -f "${LIMA_CONFIG}" ]]; then
      # No rendered config (setup never ran on this host) — render with the
      # default API server port so the VM can still be created. Run
      # 'sandbox setup --apiserver-port <PORT>' to pick a different port.
      mkdir -p "${HOME}/.sandbox"
      sed "s/__APISERVER_PORT__/${SANDBOX_APISERVER_PORT:-6443}/g" \
        "${LIMA_TEMPLATE}" > "${LIMA_CONFIG}"
    fi
    echo "==> Creating Lima VM '${LIMA_VM_NAME}' from ${LIMA_CONFIG}..."
    limactl start --name "${LIMA_VM_NAME}" "${LIMA_CONFIG}"
  else
    echo "==> Starting Lima VM '${LIMA_VM_NAME}'..."
    limactl start "${LIMA_VM_NAME}"
  fi

  # Wait for k3s inside VM to become ready. Uses sudo: k3s writes its
  # kubeconfig root-only (mode 0600), so a non-root kubectl in the VM
  # cannot read it.
  echo "==> Waiting for k3s inside Lima VM..."
  local retries=30
  local i=0
  until limactl shell "${LIMA_VM_NAME}" -- sudo kubectl get nodes &>/dev/null; do
    (( i++ )) || true
    if [[ "${i}" -ge "${retries}" ]]; then
      echo "ERROR: k3s inside Lima VM did not become ready after ${retries} attempts." >&2
      exit 1
    fi
    sleep 5
  done
  echo "==> Lima VM and k3s ready."
}

# lima_kubectl — run kubectl inside Lima VM (macOS helper). Uses sudo in the
# VM because k3s writes its kubeconfig root-only (mode 0600).
lima_kubectl() {
  if is_macos; then
    limactl shell "${LIMA_VM_NAME}" -- sudo kubectl "$@"
  else
    kubectl "$@"
  fi
}

# prepare_agent_home <agent> — ensure the agent-home directory the pod mounts
# exists and is writable by the pod's uid 1000 BEFORE the pod starts (hostPath
# type: Directory requires it to pre-exist on the node).
#
# macOS: create the VM-local working dir and chown it to 1000:1000 so the agent
# owns every file it later writes. Seed it from the host staging dir (onboard's
# output, visible inside the VM at the same absolute path via the 9p home mount)
# — but only files the working copy does not already have, so a token refreshed
# by an in-session /login (already in the working copy, which persists across
# sessions on the VM disk) is never clobbered by older staged state.
#
# Linux/WSL: the host dir IS the mount. chown to 1000:1000 where we are
# privileged enough (root in a WSL distro; a harmless no-op for the uid-1000
# Linux operator) and fall back to the historical world-writable chmod for the
# uncommon non-root, non-1000 operator.
prepare_agent_home() {
  local agent="$1"
  local mount_home staging
  mount_home="$(resolve_agent_home "${agent}")"
  staging="$(host_agent_home "${agent}")"
  mkdir -p "${staging}"

  if is_macos; then
    limactl shell "${LIMA_VM_NAME}" -- sudo sh -c '
      set -e
      mount_home="$1"; staging="$2"
      mkdir -p "$mount_home"
      if [ -d "$staging" ]; then
        for f in .credentials.json settings.json .claude.json auth.json config.toml; do
          if [ -f "$staging/$f" ] && [ ! -e "$mount_home/$f" ]; then
            cp "$staging/$f" "$mount_home/$f"
          fi
        done
      fi
      chown -R 1000:1000 "$mount_home"
      chmod 700 "$mount_home"
      [ -f "$mount_home/.credentials.json" ] && chmod 600 "$mount_home/.credentials.json" || true
      [ -f "$mount_home/auth.json" ] && chmod 600 "$mount_home/auth.json" || true
    ' _ "${mount_home}" "${staging}" \
      || die "Failed to prepare VM-local agent-home for '${agent}' inside ${LIMA_VM_NAME}."
  else
    chown -R 1000:1000 "${staging}" 2>/dev/null \
      || find "${staging}" -exec chmod u+rwX,go+rwX {} + 2>/dev/null \
      || true
  fi
}

# sync_agent_home_back <agent> — macOS only; best-effort. Copy the in-VM
# working copy of the agent-home back to the host staging dir
# (~/.sandbox/agent-home/<agent>) so host-side tooling sees current state: the
# audit transcript capture (which reads the host path), and a durable backup of
# the OAuth token that survives even a VM rebuild (prepare_agent_home re-seeds
# from it). cp -au is incremental (only newer files) and preserves modes and
# timestamps, so the transcript capture's -newer filter still works. Writes land
# owned by the Mac user (the 9p server's uid), readable by host tooling. A no-op
# on Linux/WSL, where the mount already IS the host staging dir.
sync_agent_home_back() {
  is_macos || return 0
  local agent="$1"
  local mount_home staging
  mount_home="$(resolve_agent_home "${agent}")"
  staging="$(host_agent_home "${agent}")"
  mkdir -p "${staging}"

  if ! limactl shell "${LIMA_VM_NAME}" -- sudo sh -c '
    mount_home="$1"; staging="$2"
    [ -d "$mount_home" ] || exit 0
    cp -au "$mount_home/." "$staging/" 2>/dev/null || true
  ' _ "${mount_home}" "${staging}" 2>/dev/null; then
    warn "Could not sync agent-home back to ${staging} (VM stopped?); transcript/backup may be stale."
  fi
}

# stop_lima_vm — gracefully stop Lima VM
stop_lima_vm() {
  if is_macos && lima_vm_running; then
    echo "==> Stopping Lima VM '${LIMA_VM_NAME}'..."
    limactl stop "${LIMA_VM_NAME}"
  fi
}
