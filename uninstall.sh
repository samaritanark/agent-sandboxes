#!/usr/bin/env bash
# uninstall.sh — Remove the AI Agent Sandbox and all its components
# Mirrors setup.sh in reverse: Kubernetes resources → platform runtime → host artifacts
set -euo pipefail

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIMA_VM_NAME="${LIMA_VM_NAME:-sandbox-vm}"
SANDBOX_NAMESPACE="sandbox"

# Canonical kubeconfig path — must match lib/platform.sh and setup/common.sh.
# All kubectl calls below use --kubeconfig explicitly so that the user's default
# ~/.kube/config (which may point to other clusters) is never consulted.
SANDBOX_KUBECONFIG="${SANDBOX_KUBECONFIG:-${HOME}/.sandbox/kubeconfig}"

# Pull SANDBOX_POD_CIDR default from setup/common.sh so the iptables MASQUERADE
# rule we install at setup time can be removed cleanly. The actual CIDR-in-use
# is re-read from the systemd unit file when present so a custom --pod-cidr
# install is honored regardless of what the default happens to be.
# shellcheck source=setup/common.sh
source "${SANDBOX_ROOT}/setup/common.sh"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info()  { echo "  $*"; }
warn()  { echo "WARN: $*" >&2; }
step()  { echo "==> $*"; }
ok()    { echo "  [ok] $*"; }
skip()  { echo "  [skip] $*"; }

confirm() {
  local prompt="$1"
  local answer
  read -r -p "${prompt} [y/N] " answer
  [[ "${answer}" =~ ^[Yy]$ ]]
}

# Run a command and tolerate failure (log it, continue)
try() {
  if ! "$@" 2>/dev/null; then
    warn "Command failed (continuing): $*"
  fi
}

# ---------------------------------------------------------------------------
# Cilium / host-network teardown helpers
# ---------------------------------------------------------------------------

# run_cilium_dbg_cleanup — run cilium-dbg cleanup -f inside a cilium-agent pod.
# This is Cilium's official self-unwind: detaches BPF programs, removes
# interfaces, unmounts cgroupv2, deletes pinned BPF maps. Best-effort — the
# host sweep below catches anything missed (or the case where no cilium pod
# is running at all).
run_cilium_dbg_cleanup() {
  local cilium_pod
  cilium_pod="$(kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" \
    -n kube-system get pods -l k8s-app=cilium \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"

  if [[ -z "${cilium_pod}" ]]; then
    skip "No cilium-agent pod found — host sweep will catch any leftovers."
    return 0
  fi

  info "Running cilium-dbg cleanup in pod ${cilium_pod}..."
  # Newer Cilium ships cilium-dbg; older versions ship cilium with the same
  # subcommand. Try the modern name first, fall back to legacy.
  if kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" \
       -n kube-system exec -c cilium-agent "${cilium_pod}" -- \
       cilium-dbg cleanup -f &>/dev/null; then
    ok "Cilium datapath unwound by agent (cilium-dbg)."
  elif kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" \
         -n kube-system exec -c cilium-agent "${cilium_pod}" -- \
         cilium cleanup -f &>/dev/null; then
    ok "Cilium datapath unwound by agent (legacy cilium)."
  else
    warn "cilium cleanup failed inside pod — host sweep will catch leftovers."
  fi
}

# remove_sandbox_masquerade_service — stop, disable, and remove the systemd
# unit installed by setup/linux.sh, plus the iptables POSTROUTING MASQUERADE
# rule it bakes in. Linux-only.
remove_sandbox_masquerade_service() {
  local svc_path="/etc/systemd/system/sandbox-masquerade.service"

  # Authoritative CIDR is whatever was actually written into the unit file at
  # install time. Fall back to the common.sh default if the unit is missing.
  local cidr=""
  if [[ -f "${svc_path}" ]]; then
    cidr="$(grep -oE -- '-s [0-9.]+/[0-9]+' "${svc_path}" | head -1 \
            | awk '{print $2}' || true)"
  fi
  cidr="${cidr:-${SANDBOX_POD_CIDR:-100.64.0.0/10}}"

  if systemctl list-unit-files 2>/dev/null \
       | grep -q '^sandbox-masquerade\.service'; then
    info "Stopping and disabling sandbox-masquerade.service..."
    try sudo systemctl stop sandbox-masquerade.service
    try sudo systemctl disable sandbox-masquerade.service
    if [[ -f "${svc_path}" ]]; then
      try sudo rm -f "${svc_path}"
    fi
    try sudo systemctl daemon-reload
    ok "sandbox-masquerade.service removed."
  else
    skip "sandbox-masquerade.service not present."
  fi

  # Remove the iptables MASQUERADE rule (matches what setup installed). The -C
  # check makes the -D idempotent across repeated runs.
  if sudo iptables -t nat -C POSTROUTING -s "${cidr}" '!' -d "${cidr}" \
       -j MASQUERADE 2>/dev/null; then
    info "Removing iptables MASQUERADE rule for ${cidr}..."
    try sudo iptables -t nat -D POSTROUTING -s "${cidr}" '!' -d "${cidr}" \
      -j MASQUERADE
    ok "iptables MASQUERADE rule removed."
  else
    skip "No matching iptables MASQUERADE rule found for ${cidr}."
  fi
}

# sweep_cilium_host_artifacts — belt-and-suspenders pass for anything
# cilium-dbg cleanup didn't get (or in the case where it didn't run at all).
# All operations are idempotent. Linux-only.
sweep_cilium_host_artifacts() {
  step "Sweeping leftover Cilium host artifacts..."

  # Named Cilium interfaces (some only present in specific configurations).
  local iface
  for iface in cilium_host cilium_net cilium_vxlan cilium_geneve cilium_wg0; do
    if ip link show "${iface}" &>/dev/null; then
      info "Removing interface ${iface}..."
      try sudo ip link delete "${iface}"
      ok "Removed: ${iface}"
    else
      skip "Not present: ${iface}"
    fi
  done

  # Per-pod lxc* veth pairs — one survives for every pod that ever existed.
  local -a lxc_ifaces=()
  mapfile -t lxc_ifaces < <(ip -o link show 2>/dev/null \
    | awk -F': ' '/^[0-9]+: lxc[a-zA-Z0-9_]+@/ {sub(/@.*/,"",$2); print $2}')
  if (( ${#lxc_ifaces[@]} > 0 )); then
    info "Removing ${#lxc_ifaces[@]} leftover lxc* veth(s)..."
    for iface in "${lxc_ifaces[@]}"; do
      try sudo ip link delete "${iface}"
    done
    ok "lxc* veths removed."
  else
    skip "No lxc* veths present."
  fi

  # Pinned BPF maps under bpffs. Unlinking from bpffs deletes the map.
  if [[ -d /sys/fs/bpf/tc/globals ]]; then
    local map_count
    map_count="$(sudo find /sys/fs/bpf/tc/globals -maxdepth 1 -name 'cilium_*' \
                  2>/dev/null | wc -l | tr -d ' ')"
    if [[ "${map_count}" -gt 0 ]]; then
      info "Removing ${map_count} pinned BPF map(s) under /sys/fs/bpf/tc/globals/..."
      try sudo find /sys/fs/bpf/tc/globals -maxdepth 1 -name 'cilium_*' -delete
      ok "Pinned BPF maps removed."
    else
      skip "No cilium_* BPF maps pinned."
    fi
  else
    skip "/sys/fs/bpf/tc/globals not present."
  fi

  # Cilium's private cgroupv2 mount.
  if mountpoint -q /run/cilium/cgroupv2 2>/dev/null; then
    info "Unmounting /run/cilium/cgroupv2..."
    try sudo umount /run/cilium/cgroupv2
    ok "Unmounted /run/cilium/cgroupv2."
  else
    skip "/run/cilium/cgroupv2 not mounted."
  fi

  if [[ -d /run/cilium ]]; then
    info "Removing /run/cilium/..."
    try sudo rm -rf /run/cilium
    ok "Removed /run/cilium/."
  else
    skip "/run/cilium not present."
  fi

  # CILIUM_* iptables / ip6tables chains across every common table.
  local table
  local -a chains
  for table in nat filter mangle raw; do
    mapfile -t chains < <(sudo iptables -t "${table}" -S 2>/dev/null \
      | awk '/^-N CILIUM_/ {print $2}')
    if (( ${#chains[@]} > 0 )); then
      info "Flushing ${#chains[@]} CILIUM_* chain(s) in iptables ${table} table..."
      local chain
      for chain in "${chains[@]}"; do
        try sudo iptables -t "${table}" -F "${chain}"
        try sudo iptables -t "${table}" -X "${chain}"
      done
      ok "Removed from iptables ${table}."
    fi
  done

  if command -v ip6tables &>/dev/null; then
    for table in nat filter mangle raw; do
      mapfile -t chains < <(sudo ip6tables -t "${table}" -S 2>/dev/null \
        | awk '/^-N CILIUM_/ {print $2}')
      if (( ${#chains[@]} > 0 )); then
        info "Flushing ${#chains[@]} CILIUM_* chain(s) in ip6tables ${table} table..."
        local chain
        for chain in "${chains[@]}"; do
          try sudo ip6tables -t "${table}" -F "${chain}"
          try sudo ip6tables -t "${table}" -X "${chain}"
        done
        ok "Removed from ip6tables ${table}."
      fi
    done
  fi
}

# ---------------------------------------------------------------------------
# Detect platform
# ---------------------------------------------------------------------------

PLATFORM="$(uname -s)"

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------

OPT_KEEP_LOGS=false
OPT_KEEP_IMAGES=false
OPT_KEEP_LIMA=false       # macOS: leave Lima itself installed (just delete VM)
OPT_KEEP_KUBETOOLS=false  # leave helm/kubectl on PATH
OPT_YES=false             # skip all confirmation prompts

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-logs)       OPT_KEEP_LOGS=true ;;
    --keep-images)     OPT_KEEP_IMAGES=true ;;
    --keep-lima)       OPT_KEEP_LIMA=true ;;
    --keep-kubetools)  OPT_KEEP_KUBETOOLS=true ;;
    --yes|-y)          OPT_YES=true ;;
    --help|-h)
      cat <<EOF
uninstall.sh — Remove the AI Agent Sandbox

USAGE:
  ./uninstall.sh [OPTIONS]

OPTIONS:
  --yes, -y          Skip all confirmation prompts (use in scripts)
  --keep-logs        Preserve ~/.sandbox/logs (session audit records)
  --keep-images      Skip sandbox container image removal
  --keep-lima        macOS: delete the Lima VM but leave Lima itself installed
  --keep-kubetools   Leave Helm (and kubectl on Linux) on PATH

This script removes:
  - All running sandbox Kubernetes resources (pods, policies, secrets)
  - The sandbox Kubernetes namespace, ServiceAccount, and RuntimeClass
  - k3s (Linux) or the Lima VM containing k3s (macOS)
  - gVisor binaries (Linux)
  - sandbox container images imported into containerd
  - ~/.sandbox/ directory and session logs (unless --keep-logs)

It does NOT remove:
  - This repository directory
  - Homebrew (macOS)
  - Lima itself (macOS, unless Lima was installed solely for this sandbox)
  - Helm (unless you omit --keep-kubetools and confirm removal)
EOF
      exit 0
      ;;
    *) echo "Unknown option: $1. Run './uninstall.sh --help' for usage." >&2; exit 1 ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# Dry-run preview
# ---------------------------------------------------------------------------

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                AI Agent Sandbox — Uninstaller                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Platform: ${PLATFORM}"
echo ""
echo "This will remove:"
echo "  • All active sandbox pods, network policies, and secrets"
echo "  • Kubernetes namespace '${SANDBOX_NAMESPACE}', ServiceAccount, RuntimeClass"
if [[ "${PLATFORM}" == "Linux" ]]; then
  echo "  • Cilium datapath state (cilium-dbg cleanup + host-level sweep)"
  echo "  • sandbox-masquerade.service and its iptables MASQUERADE rule"
  echo "  • k3s (via k3s-uninstall.sh) — removes Cilium pods and cluster state"
  echo "  • gVisor binaries (/usr/local/bin/runsc, containerd-shim-runsc-v1)"
  echo "  • /etc/containerd/runsc.toml"
  echo "  • Leftover cilium_* / lxc* interfaces, pinned BPF maps,"
  echo "    /run/cilium/, and CILIUM_* iptables chains"
elif [[ "${PLATFORM}" == "Darwin" ]]; then
  echo "  • Lima VM '${LIMA_VM_NAME}' (stops and deletes the VM)"
fi
if [[ "${OPT_KEEP_IMAGES}" == "false" ]]; then
  echo "  • sandbox container images (base, claude, codex, opencode, shell, *-infra)"
fi
if [[ "${OPT_KEEP_LOGS}" == "false" ]]; then
  echo "  • ~/.sandbox/ (config, kubeconfig, session logs)"
else
  echo "  • ~/.sandbox/ config and kubeconfig (logs preserved — --keep-logs)"
fi
echo ""

if [[ "${OPT_YES}" == "false" ]]; then
  if ! confirm "Proceed with uninstall?"; then
    echo "Aborted."
    exit 0
  fi
fi
echo ""

# ---------------------------------------------------------------------------
# Step 1: Clean up Kubernetes resources while the cluster is still running
# ---------------------------------------------------------------------------

step "Cleaning up Kubernetes resources..."

kubectl_available=false
if command -v kubectl &>/dev/null; then
  if kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" cluster-info &>/dev/null 2>&1; then
    kubectl_available=true
  else
    warn "kubectl found but cluster is not reachable (kubeconfig: ${SANDBOX_KUBECONFIG}) — skipping Kubernetes cleanup."
  fi
else
  warn "kubectl not found — skipping Kubernetes cleanup."
fi

if [[ "${kubectl_available}" == "true" ]]; then

  # Kill any running sandbox pods
  info "Deleting all running sandbox pods..."
  if kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" \
       get pods -n "${SANDBOX_NAMESPACE}" \
       -l sandbox-session \
       --no-headers 2>/dev/null | grep -q .; then
    try kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" delete pods \
      -n "${SANDBOX_NAMESPACE}" \
      -l sandbox-session \
      --grace-period=5 \
      --wait=false
    ok "Pods deleted (or already gone)."
  else
    skip "No active sandbox pods found."
  fi

  # Delete per-session CiliumNetworkPolicies
  info "Deleting per-session CiliumNetworkPolicies..."
  if kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" \
       get ciliumnetworkpolicies \
       -n "${SANDBOX_NAMESPACE}" \
       --no-headers 2>/dev/null | grep -q .; then
    try kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" delete ciliumnetworkpolicies \
      -n "${SANDBOX_NAMESPACE}" \
      --all
    ok "CiliumNetworkPolicies deleted."
  else
    skip "No CiliumNetworkPolicies found."
  fi

  # Delete any lingering infra-token and opencode API key secrets
  info "Deleting sandbox secrets..."
  if kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" \
       get secrets -n "${SANDBOX_NAMESPACE}" \
       --no-headers 2>/dev/null | grep -qE '(infra-token|opencode-apikey)'; then
    try kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" delete secrets \
      -n "${SANDBOX_NAMESPACE}" \
      -l sandbox-session
    ok "Secrets deleted."
  else
    skip "No sandbox secrets found."
  fi

  # Delete the sandbox namespace (takes ServiceAccount with it)
  info "Deleting namespace '${SANDBOX_NAMESPACE}'..."
  if kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" \
       get namespace "${SANDBOX_NAMESPACE}" &>/dev/null 2>&1; then
    try kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" \
      delete namespace "${SANDBOX_NAMESPACE}" --wait=true --timeout=60s
    ok "Namespace '${SANDBOX_NAMESPACE}' deleted."
  else
    skip "Namespace '${SANDBOX_NAMESPACE}' not found."
  fi

  # Delete gVisor RuntimeClass
  info "Deleting RuntimeClass 'gvisor'..."
  if kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" \
       get runtimeclass gvisor &>/dev/null 2>&1; then
    try kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" delete runtimeclass gvisor
    ok "RuntimeClass 'gvisor' deleted."
  else
    skip "RuntimeClass 'gvisor' not found."
  fi

fi

# ---------------------------------------------------------------------------
# Step 2: Cilium datapath teardown
#
# Two operations, both BEFORE k3s-uninstall.sh kills the cilium pods:
#   (a) cilium-dbg cleanup inside a running cilium-agent pod — this is
#       Cilium's own self-unwind and does the heavy lifting (BPF detach,
#       interface removal, cgroupv2 unmount, pinned-map deletion).
#   (b) Stop+remove sandbox-masquerade.service and its iptables rule.
#       The unit ExecStart-applies a POSTROUTING MASQUERADE rule that
#       k3s-uninstall has no idea about, so it would survive otherwise.
#
# Anything (a) misses (or the case where no cilium pod is running) is
# caught by the post-k3s sweep further down.
# ---------------------------------------------------------------------------

step "Cleaning up Cilium datapath state..."

if [[ "${kubectl_available}" == "true" ]]; then
  run_cilium_dbg_cleanup
else
  skip "Cluster unreachable — skipping cilium-dbg cleanup; host sweep still runs."
fi

if [[ "${PLATFORM}" == "Linux" ]]; then
  remove_sandbox_masquerade_service
fi

# ---------------------------------------------------------------------------
# Step 3: Remove sandbox container images
# ---------------------------------------------------------------------------

if [[ "${OPT_KEEP_IMAGES}" == "false" ]]; then
  step "Removing sandbox container images..."

  SANDBOX_IMAGES=(
    sandbox:base
    sandbox:claude
    sandbox:codex
    sandbox:opencode
    sandbox:shell
    sandbox:claude-infra
    sandbox:codex-infra
    sandbox:opencode-infra
  )

  # On Linux, images live in k3s containerd; we use k3s ctr to remove them
  # before k3s itself is uninstalled. On macOS, images are inside the Lima VM
  # and will be deleted when the VM is deleted.
  if [[ "${PLATFORM}" == "Linux" ]] && command -v k3s &>/dev/null; then
    info "Removing images from k3s containerd..."
    for img in "${SANDBOX_IMAGES[@]}"; do
      if sudo k3s ctr images ls --quiet 2>/dev/null | grep -qF "${img}"; then
        try sudo k3s ctr images rm "docker.io/library/${img}" 2>/dev/null || \
          try sudo k3s ctr images rm "${img}"
        ok "Removed: ${img}"
      else
        skip "Not found: ${img}"
      fi
    done
  elif [[ "${PLATFORM}" == "Darwin" ]]; then
    info "Images are inside the Lima VM and will be removed with it."
  fi

  # Also remove from Docker if present (images may have been built locally)
  if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    info "Removing sandbox images from Docker..."
    for img in "${SANDBOX_IMAGES[@]}"; do
      if docker image inspect "${img}" &>/dev/null 2>&1; then
        try docker rmi "${img}"
        ok "Removed from Docker: ${img}"
      fi
    done
  fi
else
  step "Skipping container image removal (--keep-images)."
fi

# ---------------------------------------------------------------------------
# Step 4: Platform-specific runtime teardown
# ---------------------------------------------------------------------------

if [[ "${PLATFORM}" == "Linux" ]]; then
  step "Uninstalling k3s (Linux)..."

  if [[ -x "/usr/local/bin/k3s-uninstall.sh" ]]; then
    info "Running k3s-uninstall.sh (removes k3s, Cilium, all cluster data)..."
    sudo /usr/local/bin/k3s-uninstall.sh
    ok "k3s uninstalled."
  else
    skip "k3s-uninstall.sh not found — k3s may not have been installed by setup.sh."
  fi

  step "Removing gVisor binaries..."
  for bin in /usr/local/bin/runsc /usr/local/bin/containerd-shim-runsc-v1; do
    if [[ -f "${bin}" ]]; then
      sudo rm -f "${bin}"
      ok "Removed: ${bin}"
    else
      skip "Not found: ${bin}"
    fi
  done

  info "Removing gVisor runsc config..."
  if [[ -f /etc/containerd/runsc.toml ]]; then
    sudo rm -f /etc/containerd/runsc.toml
    ok "Removed: /etc/containerd/runsc.toml"
  else
    skip "Not found: /etc/containerd/runsc.toml"
  fi

  # k3s-uninstall.sh removes /var/lib/rancher/k3s/agent/etc/containerd/,
  # so the containerd config template is gone with it. Nothing extra to do.

  # Belt-and-suspenders pass for anything cilium-dbg cleanup (Step 2) didn't
  # get, or for the case where it didn't run at all. Always runs — idempotent
  # and fast even on a clean host.
  sweep_cilium_host_artifacts

elif [[ "${PLATFORM}" == "Darwin" ]]; then
  step "Removing Lima VM '${LIMA_VM_NAME}'..."

  if ! command -v limactl &>/dev/null; then
    warn "limactl not found — Lima VM cleanup skipped."
  else
    local_status="$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null \
      | awk -v vm="${LIMA_VM_NAME}" '$1==vm {print $2}' || true)"

    if [[ -z "${local_status}" ]]; then
      skip "Lima VM '${LIMA_VM_NAME}' not found."
    else
      if [[ "${local_status}" == "Running" ]]; then
        info "Stopping Lima VM '${LIMA_VM_NAME}'..."
        try limactl stop "${LIMA_VM_NAME}"
        ok "Stopped."
      fi
      info "Deleting Lima VM '${LIMA_VM_NAME}'..."
      try limactl delete "${LIMA_VM_NAME}"
      ok "Lima VM '${LIMA_VM_NAME}' deleted."
    fi
  fi

  if [[ "${OPT_KEEP_LIMA}" == "false" ]] && command -v limactl &>/dev/null; then
    # Check if any other Lima VMs exist before suggesting Lima removal
    other_vms="$(limactl list --format '{{.Name}}' 2>/dev/null | grep -v "^${LIMA_VM_NAME}$" || true)"
    if [[ -z "${other_vms}" ]]; then
      echo ""
      echo "  Lima has no remaining VMs."
      if [[ "${OPT_YES}" == "false" ]]; then
        if confirm "  Remove Lima itself (brew uninstall lima)?"; then
          brew uninstall lima && ok "Lima uninstalled." || warn "brew uninstall lima failed."
        else
          skip "Keeping Lima."
        fi
      fi
    else
      info "Other Lima VMs exist ($(echo "${other_vms}" | tr '\n' ' ')) — leaving Lima installed."
    fi
  fi

else
  warn "Unrecognised platform '${PLATFORM}' — skipping platform-specific teardown."
fi

# ---------------------------------------------------------------------------
# Step 5: Remove ~/.sandbox/ directory
# ---------------------------------------------------------------------------

step "Cleaning up ~/.sandbox/..."

SANDBOX_DIR="${HOME}/.sandbox"

if [[ -d "${SANDBOX_DIR}" ]]; then
  if [[ "${OPT_KEEP_LOGS}" == "true" ]]; then
    # Remove everything except logs/
    info "Preserving logs. Removing config and kubeconfig..."
    try rm -f "${SANDBOX_DIR}/config.yaml"
    try rm -f "${SANDBOX_DIR}/kubeconfig"
    try rm -f "${SANDBOX_DIR}/lima-sandbox-vm.yaml"
    try rm -rf "${SANDBOX_DIR}/tmp"
    ok "~/.sandbox/ config removed; logs preserved at ${SANDBOX_DIR}/logs/"
  else
    # Show log count so user knows what they're deleting
    local_log_count=0
    if [[ -d "${SANDBOX_DIR}/logs" ]]; then
      local_log_count="$(find "${SANDBOX_DIR}/logs" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
    fi

    if [[ "${local_log_count}" -gt 0 ]]; then
      echo ""
      echo "  Found ${local_log_count} session log(s) in ${SANDBOX_DIR}/logs/"
      echo "  These are your audit records. Once deleted they cannot be recovered."
      echo "  Use --keep-logs to preserve them, or review with: ls ${SANDBOX_DIR}/logs/"
      echo ""
    fi

    if [[ "${OPT_YES}" == "true" ]] || confirm "  Delete ${SANDBOX_DIR}/ (${local_log_count} session log(s))?"; then
      rm -rf "${SANDBOX_DIR}"
      ok "~/.sandbox/ removed."
    else
      skip "Keeping ~/.sandbox/. Re-run with --keep-logs to skip this prompt."
    fi
  fi
else
  skip "~/.sandbox/ not found."
fi

# ---------------------------------------------------------------------------
# Step 6: Remove Helm (optional)
# ---------------------------------------------------------------------------

if [[ "${OPT_KEEP_KUBETOOLS}" == "false" ]] && command -v helm &>/dev/null; then
  # Only offer to remove Helm if it was installed by setup (i.e. from the
  # official get-helm-3 script which places it at /usr/local/bin/helm).
  if [[ "${PLATFORM}" == "Linux" ]] && [[ "$(command -v helm)" == "/usr/local/bin/helm" ]]; then
    echo ""
    if [[ "${OPT_YES}" == "false" ]]; then
      if confirm "  Remove Helm from /usr/local/bin/helm (installed by setup.sh)?"; then
        sudo rm -f /usr/local/bin/helm
        ok "Helm removed."
      else
        skip "Keeping Helm."
      fi
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                   Uninstall complete                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

if [[ "${OPT_KEEP_LOGS}" == "true" ]]; then
  echo "  Session audit logs preserved at: ${HOME}/.sandbox/logs/"
  echo "  Remove manually when no longer needed:"
  echo "    rm -rf ${HOME}/.sandbox"
  echo ""
fi

echo "  The sandbox source directory was not removed:"
echo "    ${SANDBOX_ROOT}"
echo "  Delete it manually if no longer needed."
echo ""
