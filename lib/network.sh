#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
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

# Node annotation used to remember the IPv4 address of the host's primary
# interface at the time the cluster was last reconciled. Compared against the
# live value on every `sandbox run` to detect a same-name-different-IP drift
# (DHCP lease change, swapping wifi SSIDs, WSL2 distro coming up with a fresh
# address from the Hyper-V NAT after a Windows reboot — none of which change
# `eth0`'s name, so the device-list check alone can't see them).
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

# reconcile_host_network <kubeconfig_path>
#
# Single-pass reconcile of the cluster's host-network wiring. Laptops move
# between wifi, ethernet, and dock adapters and toggle VPNs constantly; a host
# can change its primary interface NAME, its primary IPv4, or both at once. This
# detects all three and applies the minimum restart needed — at most ONE k3s
# restart, ONE Cilium DaemonSet restart, and ONE control-plane bounce, even when
# every kind of drift fires together.
#
# Two independent facts about the host can drift:
#
#   A. Device names — the primary NIC and/or VPN interface names Cilium should
#      masquerade through. Cilium reads its `devices` / `direct-routing-device`
#      list once at cilium-agent startup, so a stale pin survives until the
#      DaemonSet restarts. The three settings below are required together for
#      VPN-routed cluster egress:
#        --set devices='{primary,vpn1,...}'
#        --set extraConfig.direct-routing-device=<primary>
#        --set extraConfig.egress-masquerade-interfaces=''  (empty = per-iface SNAT)
#
#   B. Primary IPv4 — the address on the primary NIC, even if its name didn't
#      change (DHCP lease change, wifi SSID swap, or — the dominant case — a
#      WSL2 distro getting a fresh Hyper-V NAT address after a Windows reboot).
#      kubelet stamps the node's InternalIP and the `kubernetes` Service
#      endpoint from the live primary IP at k3s startup; until k3s restarts,
#      in-cluster clients (notably CoreDNS's kubernetes plugin) keep dialing the
#      OLD apiserver IP and fail. The cilium-agent also stamps its BPF
#      masquerade source IP from the live interface at startup, so an IP change
#      needs a fresh agent too.
#
# Why ONE pass, and why this order:
#   1. Apply the device list to the cilium-config ConfigMap FIRST, with no
#      restart. A valid direct-routing-device is a precondition for the
#      cilium-agent to initialize its datapath at all ("IPv4 direct routing
#      device IP not found" otherwise). Writing the ConfigMap before any restart
#      guarantees the next agent start reads a device that is actually up — so
#      the restart order between k3s and Cilium no longer matters.
#   2. Restart k3s iff the IPv4 drifted, to re-stamp the node InternalIP and the
#      apiserver Service endpoint. NOTE: `systemctl restart k3s` does NOT bounce
#      already-running pods — containerd shims are re-parented and the kubelet
#      re-adopts them — so this does not restart cilium-agent. The two restarts
#      are genuinely independent; neither subsumes the other.
#   3. Restart the cilium-agent iff the devices OR the IPv4 drifted, so it
#      re-reads `devices` and re-stamps the BPF masquerade source.
#   4. Whenever the agent restarts, re-emit EndpointSlices for pod-backed
#      Services (CoreDNS, hubble-relay): the agent restart leaves the BPF
#      service-LB backend map stale, so pod->ClusterIP — including CoreDNS's
#      path to kube-apiserver — stays broken until the slice is re-programmed.
#
# Behaviour by VPN state (device half):
#   - VPN up: pin devices='{primary,vpn,...}' so VPN-routed pod egress is SNAT'd
#     to the tunnel source IP.
#   - VPN down, but Cilium still carries an explicit list from an earlier VPN
#     session: reset to a single-NIC pin so a stale name can't break pod
#     endpoint creation.
#   - VPN down and no explicit list ever applied: leave Cilium on its single-NIC
#     auto-detect default untouched (avoids a needless restart).
#
# State for the IPv4 half lives in a Node annotation. On a fresh install with no
# annotation we seed the baseline without restarting; subsequent runs compare
# against it. Best-effort throughout: any failure to reach the API or a rollout
# that times out warns and returns 0 — the caller is a pre-flight hook and must
# not block a sandbox launch, and the annotation is only stamped once a restart
# actually settles, so a later run retries.
#
# Safe to call unconditionally during setup and before every `sandbox run`.
reconcile_host_network() {
  local kc="${1:?reconcile_host_network: kubeconfig path required}"

  # ---- Detect host interface state --------------------------------------
  local primary
  primary="$(detect_primary_iface)"
  if [[ -z "${primary}" ]]; then
    echo "  No default route detected; skipping network reconcile."
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
  local desired_csv desired_sorted
  desired_csv="$(IFS=,; echo "${desired_devices[*]}")"
  desired_sorted="$(printf '%s\n' "${desired_devices[@]}" | sort | paste -sd, -)"

  # ---- Decide whether the Cilium device list needs reapplying (drift A) ---
  local current_json current_sorted current_primary current_mq
  current_json="$(helm --kubeconfig "${kc}" -n kube-system get values cilium -o json 2>/dev/null || echo '{}')"
  current_sorted="$(jq -r '(.devices // []) | sort | join(",")' <<<"${current_json}")"
  current_primary="$(jq -r '.extraConfig["direct-routing-device"] // ""' <<<"${current_json}")"
  current_mq="$(jq -r '.extraConfig["egress-masquerade-interfaces"] // ""' <<<"${current_json}")"

  local device_drift=0
  if [[ "${#vpn_ifaces[@]}" -eq 0 ]] \
     && [[ -z "${current_sorted}" ]] && [[ -z "${current_primary}" ]]; then
    # No VPN, and Cilium has never had an explicit device list applied: leave it
    # on its single-NIC auto-detect default. Pinning devices here would force a
    # one-time DaemonSet restart on every plain no-VPN host for no real gain.
    device_drift=0
  elif [[ "${current_sorted}" == "${desired_sorted}" ]] \
       && [[ "${current_primary}" == "${primary}" ]] \
       && [[ -z "${current_mq}" ]]; then
    device_drift=0
  else
    device_drift=1
  fi

  # ---- Decide whether the primary IPv4 drifted (drift B) -----------------
  # seed_only: a fresh cluster with no recorded baseline yet — stamp it without
  # restarting anything (the bootstrap path used by setup/common.sh).
  local current_ip node recorded_ip ip_drift=0 seed_only=0
  current_ip="$(detect_primary_ipv4 "${primary}")"
  node="$(kubectl --kubeconfig "${kc}" get nodes \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  if [[ -n "${current_ip}" && -n "${node}" ]]; then
    recorded_ip="$(kubectl --kubeconfig "${kc}" get node "${node}" \
      -o "jsonpath={.metadata.annotations.${SANDBOX_NODE_IPV4_ANNOTATION}}" \
      2>/dev/null || true)"
    if [[ -z "${recorded_ip}" ]]; then
      seed_only=1
    elif [[ "${recorded_ip}" != "${current_ip}" ]]; then
      ip_drift=1
    fi
  fi

  # ---- Fast path: nothing to restart ------------------------------------
  if [[ "${device_drift}" -eq 0 && "${ip_drift}" -eq 0 ]]; then
    if [[ "${seed_only}" -eq 1 ]]; then
      echo "  Recording baseline primary IPv4 (${current_ip}) on node/${node}."
      kubectl --kubeconfig "${kc}" annotate node "${node}" \
        "${SANDBOX_NODE_IPV4_ANNOTATION}=${current_ip}" --overwrite >/dev/null
    else
      echo "  Host network already current (${desired_csv}); nothing to do."
    fi
    return 0
  fi

  # ---- Report what drifted ----------------------------------------------
  if [[ "${device_drift}" -eq 1 ]]; then
    if [[ "${#vpn_ifaces[@]}" -eq 0 ]]; then
      echo "  No VPN interface detected; resetting stale device list to a single-NIC pin."
      echo "  Detected primary interface:  ${primary}"
    else
      echo "  Detected primary interface:  ${primary}"
      echo "  Detected VPN interface(s):   ${vpn_ifaces[*]}"
    fi
    echo "  Applying Cilium devices:     ${desired_csv}"
  fi
  if [[ "${ip_drift}" -eq 1 ]]; then
    echo "  Host primary IPv4 changed:   ${recorded_ip} -> ${current_ip} on ${primary}."
  fi
  echo "  Reconciling now — takes ~1-2 min; any sandboxes already running may"
  echo "  see a brief network blip during the restart."

  # ---- Phase 1: stage the Cilium device list (ConfigMap only, no restart) -
  # Writing the cilium-config ConfigMap before any restart guarantees the
  # cilium-agent reads a valid direct-routing-device when it next starts, so
  # datapath init can't fail on a now-down NIC — the precondition the old
  # two-pass ordering protected, now satisfied by sequencing helm first.
  if [[ "${device_drift}" -eq 1 ]]; then
    helm --kubeconfig "${kc}" upgrade cilium cilium/cilium \
      --namespace kube-system \
      --reuse-values \
      --set "devices={${desired_csv}}" \
      --set-string "extraConfig.direct-routing-device=${primary}" \
      --set-string "extraConfig.egress-masquerade-interfaces="
  fi

  # Best-effort from here: a rollout that times out must NOT abort under
  # `set -e`. We track success so the IPv4 baseline is only stamped once the
  # restart actually settled — otherwise we leave it stale so a later run
  # retries.
  local ok=1

  # ---- Phase 2: restart k3s iff the IPv4 drifted -------------------------
  if [[ "${ip_drift}" -eq 1 ]]; then
    echo "  Restarting k3s..."
    sudo systemctl restart k3s
    if ! wait_for_k3s_api "${kc}" 60; then
      echo "  WARN: k3s API did not become ready in time; aborting reconcile." >&2
      echo "        Run 'sandbox configure-network' once k3s is up to retry." >&2
      return 0
    fi
  fi

  # ---- Phase 3: restart cilium-agent iff devices OR IPv4 drifted ---------
  if [[ "${device_drift}" -eq 1 || "${ip_drift}" -eq 1 ]]; then
    echo "  Restarting Cilium DaemonSet..."
    kubectl --kubeconfig "${kc}" -n kube-system rollout restart ds/cilium || ok=0
    kubectl --kubeconfig "${kc}" -n kube-system rollout status ds/cilium --timeout=120s || {
      ok=0
      echo "  WARN: Cilium DaemonSet did not become ready within 120s." >&2
    }

    # Re-emit EndpointSlices for pod-backed Services so the fresh agent
    # re-programs BPF backend slots. Without this, CoreDNS (and any other
    # Service whose backend is a pod, e.g. hubble-relay's ClusterIP) stays
    # unreachable from inside other pods until something else reconciles.
    echo "  Bouncing pod-backed control-plane pods to re-program service backends..."
    kubectl --kubeconfig "${kc}" -n kube-system delete pod \
      -l k8s-app=kube-dns --ignore-not-found >/dev/null 2>&1 || true
    kubectl --kubeconfig "${kc}" -n kube-system delete pod \
      -l app.kubernetes.io/name=hubble-relay --ignore-not-found >/dev/null 2>&1 || true
    kubectl --kubeconfig "${kc}" -n kube-system rollout status deploy/coredns --timeout=120s || {
      ok=0
      echo "  WARN: CoreDNS did not become ready within 120s." >&2
    }
  fi

  # ---- Phase 4: stamp the IPv4 baseline once the restart settled ---------
  if [[ "${ip_drift}" -eq 1 || "${seed_only}" -eq 1 ]]; then
    if [[ "${ok}" -eq 1 ]]; then
      kubectl --kubeconfig "${kc}" annotate node "${node}" \
        "${SANDBOX_NODE_IPV4_ANNOTATION}=${current_ip}" --overwrite >/dev/null
      echo "  Host network reconcile complete."
    else
      echo "  WARN: reconcile did not fully settle; leaving baseline at" >&2
      echo "        ${recorded_ip:-unset} so a later run retries. Re-run" >&2
      echo "        'sandbox configure-network' once the host network is stable." >&2
    fi
  elif [[ "${ok}" -eq 1 ]]; then
    echo "  Cilium reconfigured for current interfaces (${desired_csv})."
  fi

  # Always succeed: a soft rollout timeout above must not abort the caller (a
  # pre-flight hook before `sandbox run`). The trailing branch would otherwise
  # leak its own exit status when ok=0.
  return 0
}

# ensure_network_config_current <kubeconfig_path>
#
# Auto-correct hook for normal commands (e.g. `sandbox run`). Laptops move
# between wifi, ethernet, and dock adapters and toggle VPNs constantly; each
# change can leave Cilium's pinned `devices` list pointing at an interface that
# is now down, or the node InternalIP stamped with a stale primary IP, either of
# which breaks pod networking or cluster DNS. Calling this before launching a
# sandbox keeps the wiring matched to the host without the user remembering to
# run `sandbox configure-network` by hand. All drift handling — and the careful
# single-restart ordering — lives in reconcile_host_network.
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
  reconcile_host_network "${kc}"
  # Mirror the host's split-DNS routing into CoreDNS so internal (VPN-routed)
  # names don't get load-balanced onto a public resolver and bounce NXDOMAIN.
  # Self-contained and change-gated; sourced from lib/dns.sh.
  sync_split_dns "${kc}"
}
