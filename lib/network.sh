#!/usr/bin/env bash
# lib/network.sh — Host network interface detection + Cilium device wiring.
#
# Sandbox pods need to reach two distinct address spaces:
#   1. Public internet (LLM endpoints, package registries) — egresses via the
#      host's primary NIC.
#   2. Optionally, a corporate VPN-routed subnet (e.g. an internal Kubernetes
#      API server reached through tun0/wg0/utun0).
#
# Cilium's BPF masquerade SNATs pod egress to the IP of the device the packet
# exits through, but ONLY for devices in its `devices=` list. If a VPN
# interface is up at install time but not in that list, pod traffic going out
# the VPN keeps the raw pod IP as source and the VPN's gateway drops it.
#
# This module detects the primary and VPN interfaces at runtime and applies
# them to Cilium via helm upgrade. Linux-only (uses iproute2's `ip -j` JSON).
set -euo pipefail

# detect_primary_iface — name of the interface carrying the default route.
# Empty output if no default route (offline or weird routing setup).
detect_primary_iface() {
  ip -j route get 1.1.1.1 2>/dev/null | jq -r '.[0].dev // empty'
}

# detect_vpn_ifaces — names of POINTOPOINT interfaces (tun/wg/ppp/vti/utun),
# one per line, excluding the primary. POINTOPOINT covers nearly every
# common VPN flavor and avoids name-pattern guessing.
detect_vpn_ifaces() {
  local primary
  primary="$(detect_primary_iface)"
  ip -j link show 2>/dev/null | jq -r --arg primary "${primary}" '
    .[]
    | select(.flags // [] | any(. == "POINTOPOINT"))
    | select(.ifname != $primary)
    | .ifname
  '
}

# detect_primary_ipv4 [iface] — current IPv4 address on a given interface
# (default: the interface carrying the default route). Empty if the device
# has no IPv4 or the host is offline. Picks the first global-scope IPv4 so
# we ignore link-local 169.254/16 leftovers.
detect_primary_ipv4() {
  local iface="${1:-}"
  [[ -z "${iface}" ]] && iface="$(detect_primary_iface)"
  [[ -z "${iface}" ]] && return 0
  ip -j -4 addr show dev "${iface}" 2>/dev/null \
    | jq -r '[.[].addr_info[]? | select(.scope == "global") | .local] | first // empty'
}

# configure_cilium_for_vpn <kubeconfig_path>
#
# Detects the current primary + VPN interfaces and reconciles Cilium's device
# wiring to match. Three settings together are required for VPN-routed cluster
# egress:
#   --set devices='{primary,vpn1,...}'
#   --set extraConfig.direct-routing-device=<primary>
#   --set extraConfig.egress-masquerade-interfaces=''  (default; empty = per-egress-iface SNAT)
#
# Idempotent — the device list is compared as a SET, so VPN bring-up order
# alone doesn't churn Cilium. This matters because the only way to apply a
# devices change is `kubectl rollout restart ds/cilium`, and restarting the
# agent on a live cluster leaves the BPF service-LB backend map stale: pod
# veths can no longer resolve ClusterIP→PodIP, so CoreDNS loses its path to
# kube-apiserver, its readiness probe fails, kube-dns EndpointSlice goes
# unready, and cluster DNS dies. When a restart IS necessary we therefore
# also bounce the pod-backed control-plane pods (CoreDNS, hubble-relay) so
# their EndpointSlice updates re-program backend slots under the fresh agent.
#
# Behaviour by VPN state:
#   - VPN up: pin devices='{primary,vpn,...}' so VPN-routed pod egress is
#     SNAT'd to the tunnel source IP.
#   - VPN down, but Cilium still carries an explicit device list from an
#     earlier VPN session: reset to a single-NIC pin (devices='{primary}')
#     so a now-stale interface name can't break pod endpoint creation.
#   - VPN down and no explicit device list ever applied: leave Cilium on its
#     single-NIC auto-detect default untouched (avoids a needless restart).
# Safe to call unconditionally during setup and before every `sandbox run`.
configure_cilium_for_vpn() {
  local kc="${1:?configure_cilium_for_vpn: kubeconfig path required}"

  local primary
  primary="$(detect_primary_iface)"
  if [[ -z "${primary}" ]]; then
    echo "  No default route detected; skipping Cilium device configuration."
    return 0
  fi

  local -a vpn_ifaces=()
  while IFS= read -r line; do
    [[ -n "${line}" ]] && vpn_ifaces+=("${line}")
  done < <(detect_vpn_ifaces | sort)

  # Desired device list: primary first, then VPN interfaces alphabetically.
  # With no VPN up this is just the primary — a deterministic single-NIC pin.
  # The display CSV preserves primary-first; the comparison CSV sorts all
  # entries so a reordering by ifindex (bring-up order) doesn't look like a
  # change.
  local -a desired_devices=("${primary}" "${vpn_ifaces[@]+"${vpn_ifaces[@]}"}")
  local desired_csv
  desired_csv="$(IFS=,; echo "${desired_devices[*]}")"
  local desired_sorted
  desired_sorted="$(printf '%s\n' "${desired_devices[@]}" | sort | paste -sd, -)"

  # Compare against current helm values. Skip the helm upgrade and DS
  # rollout-restart entirely when nothing has actually changed.
  local current_json
  current_json="$(helm --kubeconfig "${kc}" -n kube-system get values cilium -o json 2>/dev/null || echo '{}')"
  local current_sorted current_primary current_mq
  current_sorted="$(jq -r '(.devices // []) | sort | join(",")' <<<"${current_json}")"
  current_primary="$(jq -r '.extraConfig["direct-routing-device"] // ""' <<<"${current_json}")"
  current_mq="$(jq -r '.extraConfig["egress-masquerade-interfaces"] // ""' <<<"${current_json}")"

  # No VPN, and Cilium has never had an explicit device list applied: leave it
  # on its single-NIC auto-detect default. Pinning devices here would force a
  # one-time DaemonSet restart on every plain no-VPN host for no real gain.
  if [[ "${#vpn_ifaces[@]}" -eq 0 ]] \
     && [[ -z "${current_sorted}" ]] && [[ -z "${current_primary}" ]]; then
    echo "  No VPN interface detected; Cilium on single-NIC auto-detect. Nothing to do."
    return 0
  fi

  if [[ "${current_sorted}" == "${desired_sorted}" ]] \
     && [[ "${current_primary}" == "${primary}" ]] \
     && [[ -z "${current_mq}" ]]; then
    echo "  Cilium already configured for current interfaces (${desired_csv}); skipping."
    return 0
  fi

  if [[ "${#vpn_ifaces[@]}" -eq 0 ]]; then
    echo "  No VPN interface detected; resetting stale device list to a single-NIC pin."
    echo "  Detected primary interface:  ${primary}"
  else
    echo "  Detected primary interface:  ${primary}"
    echo "  Detected VPN interface(s):   ${vpn_ifaces[*]}"
  fi
  echo "  Applying Cilium devices:     ${desired_csv}"
  echo "  Reconfiguring Cilium now — takes ~1-2 min; any sandboxes already"
  echo "  running may see a brief network blip during the DaemonSet restart."

  helm --kubeconfig "${kc}" upgrade cilium cilium/cilium \
    --namespace kube-system \
    --reuse-values \
    --set "devices={${desired_csv}}" \
    --set-string "extraConfig.direct-routing-device=${primary}" \
    --set-string "extraConfig.egress-masquerade-interfaces="

  echo "  Restarting Cilium DaemonSet..."
  kubectl --kubeconfig "${kc}" -n kube-system rollout restart ds/cilium
  kubectl --kubeconfig "${kc}" -n kube-system rollout status ds/cilium --timeout=120s

  # Force a fresh EndpointSlice update for pod-backed services so the new
  # agent re-programs BPF backend slots. Without this, CoreDNS (and any
  # other Service whose backend is a pod, e.g. hubble-relay's ClusterIP)
  # stays unreachable from inside other pods until something else triggers
  # a reconcile.
  echo "  Bouncing pod-backed control-plane pods to re-program service backends..."
  kubectl --kubeconfig "${kc}" -n kube-system delete pod \
    -l k8s-app=kube-dns --ignore-not-found >/dev/null 2>&1 || true
  kubectl --kubeconfig "${kc}" -n kube-system delete pod \
    -l app.kubernetes.io/name=hubble-relay --ignore-not-found >/dev/null 2>&1 || true
  kubectl --kubeconfig "${kc}" -n kube-system rollout status deploy/coredns --timeout=120s

  if [[ "${#vpn_ifaces[@]}" -eq 0 ]]; then
    echo "  Cilium reset to single-NIC config (${desired_csv})."
  else
    echo "  Cilium configured for VPN-routed egress."
  fi
}

# Node annotation used to remember the IPv4 address of the host's primary
# interface at the time the cluster was last reconciled. Compared against the
# live value on every `sandbox run` to detect a same-name-different-IP drift
# (DHCP lease change, swapping wifi SSIDs, WSL2 distro coming up with a fresh
# address from the Hyper-V NAT after a Windows reboot — none of which change
# `eth0`'s name, so the device-list check in configure_cilium_for_vpn can't
# see them).
SANDBOX_NODE_IPV4_ANNOTATION="sandbox-network-primary-ipv4"

# wait_for_k3s_api <kubeconfig> [retries] — block until kubectl can reach the
# API server again. Used after `systemctl restart k3s`. We don't depend on
# wait_for_k3s in setup/linux.sh because lib/network.sh is sourced by the
# runtime CLI, not the installer.
wait_for_k3s_api() {
  local kc="$1"
  local retries="${2:-30}"
  local i=0
  until kubectl --kubeconfig "${kc}" get --raw=/readyz &>/dev/null; do
    (( i++ )) || true
    if [[ "${i}" -ge "${retries}" ]]; then
      return 1
    fi
    sleep 2
  done
  return 0
}

# reconcile_node_ipv4 <kubeconfig>
#
# Detect a change in the host's primary IPv4 (interface name unchanged, IP
# changed) and run the full restart sequence needed to make k3s and Cilium
# re-learn the new address. The configure_cilium_for_vpn path only compares
# device NAMES, so it cannot see this kind of drift on its own.
#
# Why a full restart, and what each step does:
#   - `systemctl restart k3s`: kubelet stamps the node's `InternalIP` and the
#     API server's serving-cert SANs from the live primary IP at startup.
#     Without a restart the Node object keeps the old IP and the cert SAN
#     list stays stale (mostly cosmetic for us since pods talk to
#     k8sServiceHost=127.0.0.1, but any out-of-cluster client that resolved
#     the node by IP breaks).
#   - `rollout restart ds/cilium`: the cilium-agent reads the
#     direct-routing-device's IPv4 at startup and writes it into BPF maps for
#     masquerade source and the CiliumNode CRD. Netlink IP-change events
#     don't fully reconcile those.
#   - Bounce CoreDNS + hubble-relay: same problem the configure_cilium_for_vpn
#     restart path already handles — the BPF service-LB backend map is left
#     stale after the agent restart and pod->ClusterIP fails until the
#     EndpointSlice is re-emitted.
#
# State is stored as a Node annotation (one node in the cluster, so we read
# the first item). On a fresh install with no annotation we seed without
# restarting; that bootstrap stamp is written by setup/common.sh once Cilium
# is up. Subsequent runs compare against the stamped value.
#
# Best-effort: any failure to reach the API or detect the IP returns 0 — the
# caller (ensure_network_config_current) is a pre-flight hook and must not
# block a sandbox launch on a soft failure.
reconcile_node_ipv4() {
  local kc="$1"

  local primary
  primary="$(detect_primary_iface)"
  [[ -z "${primary}" ]] && return 0

  local current_ip
  current_ip="$(detect_primary_ipv4 "${primary}")"
  [[ -z "${current_ip}" ]] && return 0

  local node
  node="$(kubectl --kubeconfig "${kc}" get nodes \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  [[ -z "${node}" ]] && return 0

  local recorded_ip
  recorded_ip="$(kubectl --kubeconfig "${kc}" get node "${node}" \
    -o "jsonpath={.metadata.annotations.${SANDBOX_NODE_IPV4_ANNOTATION}}" \
    2>/dev/null || true)"

  if [[ -z "${recorded_ip}" ]]; then
    echo "  Recording baseline primary IPv4 (${current_ip}) on node/${node}."
    kubectl --kubeconfig "${kc}" annotate node "${node}" \
      "${SANDBOX_NODE_IPV4_ANNOTATION}=${current_ip}" --overwrite >/dev/null
    return 0
  fi

  if [[ "${recorded_ip}" == "${current_ip}" ]]; then
    return 0
  fi

  echo "  Host primary IPv4 changed: ${recorded_ip} -> ${current_ip} on ${primary}."
  echo "  Restarting k3s and Cilium so the node InternalIP and BPF masquerade"
  echo "  source pick up the new address. This takes ~1-2 min; any sandboxes"
  echo "  already running may see a brief network blip."

  echo "  Restarting k3s..."
  sudo systemctl restart k3s
  if ! wait_for_k3s_api "${kc}" 60; then
    echo "  WARN: k3s API did not become ready in time; aborting IP reconcile." >&2
    echo "        Run 'sandbox configure-network' once k3s is up to retry." >&2
    return 0
  fi

  echo "  Restarting Cilium DaemonSet..."
  kubectl --kubeconfig "${kc}" -n kube-system rollout restart ds/cilium
  kubectl --kubeconfig "${kc}" -n kube-system rollout status ds/cilium --timeout=120s

  echo "  Bouncing pod-backed control-plane pods to re-program service backends..."
  kubectl --kubeconfig "${kc}" -n kube-system delete pod \
    -l k8s-app=kube-dns --ignore-not-found >/dev/null 2>&1 || true
  kubectl --kubeconfig "${kc}" -n kube-system delete pod \
    -l app.kubernetes.io/name=hubble-relay --ignore-not-found >/dev/null 2>&1 || true
  kubectl --kubeconfig "${kc}" -n kube-system rollout status deploy/coredns --timeout=120s

  kubectl --kubeconfig "${kc}" annotate node "${node}" \
    "${SANDBOX_NODE_IPV4_ANNOTATION}=${current_ip}" --overwrite >/dev/null
  echo "  Node IPv4 reconcile complete."
}

# ensure_network_config_current <kubeconfig_path>
#
# Auto-correct hook for normal commands (e.g. `sandbox run`). Laptops move
# between wifi, ethernet, and dock adapters and toggle VPNs constantly; each
# change can leave Cilium's pinned `devices` / `direct-routing-device` list
# pointing at an interface that is now down or has no IP, which makes new pod
# endpoints fail to come up. Calling this before launching a sandbox keeps the
# device wiring matched to the host without the user remembering to run
# `sandbox configure-network` by hand.
#
# Two kinds of drift are reconciled, in order:
#   1. Primary IPv4 changed but interface name didn't (reconcile_node_ipv4).
#      This is the dominant case on WSL2, where the sandbox-vm distro comes
#      up with a fresh address from the Hyper-V virtual NAT after every
#      Windows host reboot. Fix requires a k3s + Cilium restart.
#   2. Primary or VPN interface NAMES changed (configure_cilium_for_vpn).
#      Cilium reads its `devices` list once at agent startup, so the stale
#      pin survives until the DaemonSet restarts.
#
# Guards so it is a clean no-op where it cannot apply:
#   - non-Linux: on macOS the cluster runs inside Lima and cannot see the
#     host's interfaces (same restriction as `configure-network`).
#   - helm or jq missing: cannot inspect or apply Cilium helm values.
ensure_network_config_current() {
  local kc="${1:?ensure_network_config_current: kubeconfig path required}"
  [[ "$(detect_platform)" == "linux" ]] || return 0
  command -v helm >/dev/null 2>&1 || return 0
  command -v jq >/dev/null 2>&1 || return 0
  echo "==> Checking host network configuration..."
  reconcile_node_ipv4 "${kc}"
  configure_cilium_for_vpn "${kc}"
}
