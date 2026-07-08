#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# setup/macos.sh — macOS-specific sandbox setup (Lima VM)
set -euo pipefail

SANDBOX_ROOT="${SANDBOX_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
LIMA_VM_NAME="${LIMA_VM_NAME:-sandbox-vm}"
LIMA_TEMPLATE="${SANDBOX_ROOT}/lima/sandbox-vm.yaml.tmpl"
# Rendered (port-substituted) Lima config. Kept under ~/.sandbox/ rather than
# in the repo so a checkout is never dirtied by setup.
LIMA_CONFIG="${HOME}/.sandbox/lima-sandbox-vm.yaml"

setup_macos() {
  echo "==> Setting up sandbox on macOS (Lima)..."

  check_macos_prerequisites
  install_lima_if_needed
  render_lima_config
  start_or_create_lima_vm
  ensure_cluster_ready
  configure_host_kubectl
}

# render_lima_config — substitute the API server port and the pinned component
# versions (setup/versions.sh) into the Lima template, producing the concrete
# config that limactl consumes. The version tokens let the in-VM provisioning
# script install the same k3s/Cilium/gVisor/nerdctl as the Linux host path; an
# empty pin renders an empty token, which each in-VM step treats as "latest".
render_lima_config() {
  mkdir -p "${HOME}/.sandbox"
  sed \
    -e "s/__APISERVER_PORT__/${SANDBOX_APISERVER_PORT}/g" \
    -e "s/__K3S_VERSION__/${SANDBOX_K3S_VERSION}/g" \
    -e "s/__CILIUM_VERSION__/${SANDBOX_CILIUM_VERSION}/g" \
    -e "s/__GVISOR_RELEASE__/${SANDBOX_GVISOR_RELEASE}/g" \
    -e "s/__HELM_VERSION__/${SANDBOX_HELM_VERSION}/g" \
    -e "s/__NERDCTL_VERSION__/${SANDBOX_NERDCTL_VERSION}/g" \
    "${LIMA_TEMPLATE}" > "${LIMA_CONFIG}"
}

# lima_kubeconfig_port — print the API server port recorded in the host
# kubeconfig from a previous setup, or empty if none exists.
lima_kubeconfig_port() {
  local kc="${HOME}/.sandbox/kubeconfig"
  [[ -f "${kc}" ]] || return 0
  local server
  server="$(grep -m1 -E '^[[:space:]]*server:' "${kc}" | sed -E 's/.*server:[[:space:]]*//')"
  local port="${server##*:}"
  echo "${port%%/*}"
}

check_macos_prerequisites() {
  echo "  Checking macOS prerequisites..."

  # Check macOS version (Virtualization.framework requires macOS 13+)
  local macos_version
  macos_version="$(sw_vers -productVersion | cut -d. -f1)"
  if [[ "${macos_version}" -lt 13 ]]; then
    echo "WARN: macOS ${macos_version} detected. macOS 13+ recommended for Lima vz backend." >&2
  fi

  # Check for Homebrew
  if ! command -v brew &>/dev/null; then
    echo "  Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  fi
}

install_lima_if_needed() {
  if command -v limactl &>/dev/null; then
    echo "  Lima already installed: $(limactl --version)"
    return 0
  fi

  echo "  Installing Lima..."
  brew install lima
  echo "  Lima installed: $(limactl --version)"
}

start_or_create_lima_vm() {
  echo "  Checking Lima VM '${LIMA_VM_NAME}'..."

  local existing
  existing="$(limactl list --format '{{.Name}}' 2>/dev/null | grep -x "${LIMA_VM_NAME}" || true)"

  if [[ -z "${existing}" ]]; then
    echo "  Creating Lima VM from ${LIMA_CONFIG}..."
    limactl start --name "${LIMA_VM_NAME}" "${LIMA_CONFIG}"
  else
    # Lima bakes the host port forward in at VM-creation time, so the API
    # server port cannot be changed on an existing VM. Refuse rather than
    # silently leaving the forward on the old port.
    local existing_port
    existing_port="$(lima_kubeconfig_port)"
    if [[ -n "${existing_port}" ]] && [[ "${existing_port}" != "${SANDBOX_APISERVER_PORT}" ]]; then
      echo "ERROR: Lima VM '${LIMA_VM_NAME}' already exists with API server port ${existing_port}." >&2
      echo "  Changing the port on macOS requires recreating the VM:" >&2
      echo "    limactl delete ${LIMA_VM_NAME}" >&2
      echo "    ./setup.sh --apiserver-port ${SANDBOX_APISERVER_PORT}" >&2
      exit 1
    fi

    local status
    status="$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null \
      | awk -v vm="${LIMA_VM_NAME}" '$1==vm {print $2}')"

    if [[ "${status}" != "Running" ]]; then
      echo "  Starting existing Lima VM '${LIMA_VM_NAME}'..."
      limactl start "${LIMA_VM_NAME}"
    else
      echo "  Lima VM '${LIMA_VM_NAME}' is already running."
    fi
  fi
}

# lima_node_ready — true when the k3s node inside the VM reports Ready.
# Uses sudo: k3s writes its kubeconfig root-only (mode 0600), so a non-root
# kubectl in the VM cannot read it — configure_host_kubectl and the Lima
# readiness probe both already use sudo for the same reason.
lima_node_ready() {
  limactl shell "${LIMA_VM_NAME}" -- \
    sudo kubectl get nodes --no-headers 2>/dev/null \
    | awk '$2 == "Ready" { ready = 1 } END { exit !ready }'
}

# wait_for_node_ready — poll lima_node_ready; return 1 if it never goes Ready.
# The node stays NotReady until Cilium (the CNI) is running, so this also
# gates on a healthy CNI — exactly what a half-finished provision run lacks.
wait_for_node_ready() {
  local retries="${1:-40}"
  local i=0
  while (( i < retries )); do
    if lima_node_ready; then
      return 0
    fi
    i=$(( i + 1 ))
    sleep 5
    echo "  Waiting for the cluster node to be Ready... (${i}/${retries})"
  done
  return 1
}

# dump_vm_diagnostics — print why the cluster is unhealthy. Without this a
# failed provision run is a black box — "did not become ready" and nothing
# actionable.
dump_vm_diagnostics() {
  echo "  ---- Lima VM diagnostics ----"
  echo "  k3s service state:"
  limactl shell "${LIMA_VM_NAME}" -- sudo systemctl is-active k3s 2>&1 \
    | sed 's/^/    /' || true
  echo "  Provisioning log (tail — a failed step, if any, is at the end):"
  limactl shell "${LIMA_VM_NAME}" -- \
    sudo tail -n 30 /var/log/sandbox-provision.log 2>&1 \
    | sed 's/^/    /' || true
  echo "  Nodes:"
  limactl shell "${LIMA_VM_NAME}" -- sudo kubectl get nodes -o wide 2>&1 \
    | sed 's/^/    /' || true
  echo "  kube-system pods (Cilium, CoreDNS, ...):"
  limactl shell "${LIMA_VM_NAME}" -- sudo kubectl get pods -n kube-system 2>&1 \
    | sed 's/^/    /' || true
  echo "  Last 25 lines of the k3s log:"
  limactl shell "${LIMA_VM_NAME}" -- sudo journalctl -u k3s --no-pager -n 25 2>&1 \
    | sed 's/^/    /' || true
  echo "  -----------------------------"
}

# recreate_lima_vm — delete and recreate the VM so the provision script runs
# again from scratch. Lima runs provisioning only at creation time, so an
# in-place re-run of setup cannot repair a half-provisioned VM.
recreate_lima_vm() {
  limactl delete --force "${LIMA_VM_NAME}"
  limactl start --name "${LIMA_VM_NAME}" "${LIMA_CONFIG}"
}

# ensure_cluster_ready — block until the in-VM cluster is genuinely usable
# (node Ready, which implies a healthy CNI). If it is not, the VM is
# half-provisioned; show diagnostics, recreate it once to re-run provisioning
# from scratch, and wait again. A second failure is fatal — not transient.
ensure_cluster_ready() {
  echo "  Waiting for the cluster to come up inside the VM..."
  if wait_for_node_ready 40; then
    echo "  Cluster node is Ready."
    return 0
  fi

  echo "" >&2
  echo "WARN: the cluster node never reached Ready — the VM looks" >&2
  echo "      half-provisioned. Lima runs the provision script only at VM" >&2
  echo "      creation, so re-running setup cannot repair it in place." >&2
  dump_vm_diagnostics
  echo "  Recreating the VM to re-run provisioning from scratch..."
  recreate_lima_vm

  if wait_for_node_ready 40; then
    echo "  Cluster node is Ready."
    return 0
  fi

  echo "" >&2
  echo "ERROR: the cluster still did not become Ready after recreating the" >&2
  echo "       VM. This is not a transient failure." >&2
  dump_vm_diagnostics
  echo "  Fix the cause shown above, then recreate the VM manually:" >&2
  echo "    limactl delete --force ${LIMA_VM_NAME}" >&2
  echo "    ./setup.sh" >&2
  exit 1
}

configure_host_kubectl() {
  echo "  Configuring host kubectl to reach Lima cluster..."

  # Write kubeconfig to ~/.sandbox/kubeconfig — the same path used on Linux
  # and by all kubectl/helm calls throughout the project (--kubeconfig flag).
  # We do NOT write to ~/.kube/config to avoid disturbing other cluster contexts.
  mkdir -p "${HOME}/.sandbox"
  limactl shell "${LIMA_VM_NAME}" -- \
    sudo cat /etc/rancher/k3s/k3s.yaml \
    > "${HOME}/.sandbox/kubeconfig"

  chmod 600 "${HOME}/.sandbox/kubeconfig"

  echo "  Verifying cluster access..."
  kubectl --kubeconfig "${HOME}/.sandbox/kubeconfig" get nodes
  echo "  Host kubectl configured. Kubeconfig: ~/.sandbox/kubeconfig"
}
