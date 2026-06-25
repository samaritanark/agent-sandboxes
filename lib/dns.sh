#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/dns.sh — Split-horizon DNS reconciliation for the cluster's CoreDNS.
#
# THE PROBLEM
#   k3s starts CoreDNS with `forward . /etc/resolv.conf`, and we point its
#   --resolv-conf at the host's resolver file. On a host using systemd-resolved
#   with a VPN, that file is the FLATTENED view of split-DNS: every link's
#   nameservers merged into one list, e.g.
#       nameserver 10.8.48.53   # internal (VPN), knows *.example.cloud
#       nameserver 10.4.48.53   # internal (VPN)
#       nameserver 1.1.1.1      # public,   does NOT know *.example.cloud
#   CoreDNS's forward plugin load-balances across ALL of them (policy random),
#   so ~1/3 of fresh lookups for an internal-only name land on the public
#   resolver and come back NXDOMAIN — which `cache 30` then negatively caches
#   for ~30s. The result is bursty, self-healing "Could not resolve host" for
#   internal hosts that the host itself resolves fine (glibc queries
#   nameservers in order and never reaches the public one). The flattening
#   threw away the per-domain routing systemd-resolved already computed.
#
# THE FIX
#   Mirror that routing back into CoreDNS. systemd-resolved knows, per link,
#   which routing domains map to which servers (`resolvectl status`). We render
#   a `coredns-custom` ConfigMap with one server block per internal routing
#   domain that forwards ONLY to that domain's VPN-routed resolvers. A
#   zone-specific block (`example.cloud:53 { ... }`) is more specific than the
#   default `.:53`, so internal names are diverted off the random public pool
#   while everything else keeps using the default forward. The Corefile already
#   does `import /etc/coredns/custom/*.server`, and the coredns deployment
#   mounts the (optional) `coredns-custom` ConfigMap there, so no Corefile edit
#   is needed. This is derived automatically and re-derived whenever the host
#   network is reconciled (every `sandbox run`, and `sandbox configure-network`).
#
#   When the VPN is down, resolvectl no longer reports the internal domains. We
#   fall back to the last-known mapping (persisted under ~/.sandbox) so internal
#   names keep routing to their — now unreachable — resolvers and return an
#   honest SERVFAIL/timeout, instead of flapping back to a misleading public
#   NXDOMAIN. The hosts are unreachable off-VPN regardless.
#
# Linux + systemd-resolved is the auto-detection path. Hosts without resolvectl
# (plain resolv.conf, WSL2, macOS-via-Lima where the VPN lives on the host
# outside the VM) can still declare zones explicitly via ~/.sandbox/config.yaml:
#       internal_dns_zones:
#         - example.cloud 10.8.48.53 10.4.48.53
set -euo pipefail

# k3s's auto-imported CoreDNS overlay. Name + mount path are fixed by k3s; we
# own a single key in it (other keys, if any, are left untouched by apply).
SANDBOX_COREDNS_CUSTOM_CM="coredns-custom"
SANDBOX_COREDNS_CUSTOM_KEY="sandbox-split-horizon.server"

# Last-known internal zone map, so a momentary VPN-down doesn't drop the
# diversion and let internal names fall back to the public resolver.
SANDBOX_SPLIT_DNS_STATE="${SANDBOX_SPLIT_DNS_STATE:-${HOME}/.sandbox/split-dns.zones}"

# dns_zones_from_json — read `resolvectl --json=short status` on stdin, print
# one "<zone> <server> [server...]" line per internal (non-catch-all) routing
# domain. The catch-all link's domain is ".", which we skip — that traffic
# stays on CoreDNS's default forward. Pure (no I/O), so it is unit-testable
# against a captured fixture.
dns_zones_from_json() {
  jq -r '
    .[]?
    | select((.searchDomains? != null) and (.servers? != null))
    | . as $l
    | $l.searchDomains[]
    | select(.name != ".")
    | ([.name] + [$l.servers[].addressString]) | join(" ")
  ' 2>/dev/null
}

# dns_detect_split_zones — internal zones from the live systemd-resolved state.
# Empty (and a clean return) when resolvectl is absent or the VPN is down.
dns_detect_split_zones() {
  command -v resolvectl >/dev/null 2>&1 || return 0
  resolvectl --json=short status 2>/dev/null | dns_zones_from_json
}

# dns_config_zones — internal zones declared explicitly in ~/.sandbox/config.yaml
# under `internal_dns_zones:` (each list item is "<zone> <server> [server...]").
# The escape hatch for hosts without systemd-resolved.
dns_config_zones() {
  extract_yaml_list_from_file "${USER_SANDBOX_CONFIG}" "internal_dns_zones"
}

# dns_effective_zones — merged, de-duplicated "<zone> <servers...>" lines.
# Precedence: explicit config first, then detected (or last-known when the VPN
# is momentarily down); first occurrence of a zone wins. Refreshes the
# persisted last-known map as a side effect whenever live detection succeeds.
dns_effective_zones() {
  local detected
  detected="$(dns_detect_split_zones)"
  if [[ -n "${detected}" ]]; then
    mkdir -p "$(dirname "${SANDBOX_SPLIT_DNS_STATE}")" 2>/dev/null || true
    printf '%s\n' "${detected}" > "${SANDBOX_SPLIT_DNS_STATE}" 2>/dev/null || true
  elif [[ -f "${SANDBOX_SPLIT_DNS_STATE}" ]]; then
    detected="$(cat "${SANDBOX_SPLIT_DNS_STATE}")"
  fi
  { dns_config_zones; printf '%s\n' "${detected}"; } \
    | awk 'NF>=2 && !seen[$1]++ { print }'
}

# render_split_dns_blocks — read "<zone> <servers...>" lines on stdin, emit the
# CoreDNS server blocks (the value of the ConfigMap key). `policy sequential`
# prefers the first internal resolver and only fails over to the next on error.
render_split_dns_blocks() {
  local line zone servers
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"   # ltrim
    [[ -z "${line}" ]] && continue
    zone="${line%% *}"
    servers="${line#* }"
    [[ "${zone}" == "${servers}" ]] && continue   # zone with no servers
    printf '%s:53 {\n    errors\n    cache 30\n    forward . %s {\n        policy sequential\n    }\n}\n' \
      "${zone}" "${servers}"
  done
}

# render_split_dns_configmap — read "<zone> <servers...>" lines on stdin, emit
# the full coredns-custom ConfigMap manifest (empty output if no zones).
render_split_dns_configmap() {
  local blocks
  blocks="$(render_split_dns_blocks)"
  [[ -z "${blocks}" ]] && return 0
  printf 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s\n  namespace: kube-system\n  labels:\n    app.kubernetes.io/managed-by: sandbox\ndata:\n  %s: |\n' \
    "${SANDBOX_COREDNS_CUSTOM_CM}" "${SANDBOX_COREDNS_CUSTOM_KEY}"
  printf '%s\n' "${blocks}" | sed 's/^/    /'
}

# sync_split_dns <kubeconfig> — reconcile the coredns-custom ConfigMap to match
# the host's split-DNS routing, restarting CoreDNS only when the content
# actually changed. Best-effort: a soft rollout timeout warns and returns 0 so
# this never blocks a sandbox launch. Linux-only (auto-detection needs
# systemd-resolved); the explicit config path still flows through here.
sync_split_dns() {
  local kc="${1:?sync_split_dns: kubeconfig path required}"
  is_linux || return 0
  command -v kubectl >/dev/null 2>&1 || return 0
  command -v jq >/dev/null 2>&1 || return 0

  local zones blocks
  zones="$(dns_effective_zones)"
  blocks="$(printf '%s\n' "${zones}" | render_split_dns_blocks)"
  [[ -z "${blocks}" ]] && return 0   # no internal zones to route — nothing to do

  local current
  current="$(kubectl --kubeconfig "${kc}" -n kube-system get cm "${SANDBOX_COREDNS_CUSTOM_CM}" -o json 2>/dev/null \
    | jq -r --arg k "${SANDBOX_COREDNS_CUSTOM_KEY}" '.data[$k] // ""' 2>/dev/null || true)"
  if [[ "${blocks}" == "${current}" ]]; then
    return 0   # already current — no restart
  fi

  echo "  Reconciling CoreDNS split-horizon zones:"
  printf '%s\n' "${zones}" \
    | awk 'NF>=2 { printf "    %s -> %s\n", $1, substr($0, index($0,$2)) }'
  printf '%s\n' "${zones}" | render_split_dns_configmap \
    | kubectl --kubeconfig "${kc}" apply -f - >/dev/null
  kubectl --kubeconfig "${kc}" -n kube-system rollout restart deploy/coredns >/dev/null 2>&1 || true
  if kubectl --kubeconfig "${kc}" -n kube-system rollout status deploy/coredns --timeout=120s >/dev/null 2>&1; then
    echo "  CoreDNS now resolves these zones via their dedicated (VPN-routed) servers."
  else
    echo "  WARN: CoreDNS did not become ready within 120s after the DNS update." >&2
  fi
  return 0
}
