#!/usr/bin/env bash
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

# stop_lima_vm — gracefully stop Lima VM
stop_lima_vm() {
  if is_macos && lima_vm_running; then
    echo "==> Stopping Lima VM '${LIMA_VM_NAME}'..."
    limactl stop "${LIMA_VM_NAME}"
  fi
}
