#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/resources.sh — Sandbox resource sizing.
#
# Single source of truth for per-pod resource requests/limits and for the
# namespace ResourceQuota. The quota is computed at 'sandbox setup' time from
# the node's actual allocatable CPU/memory rather than hardcoded for one
# reference machine, so the same install behaves correctly on a 16Gi laptop
# and a 128Gi server.
#
# Memory is NOT overcommitted: the sum of per-pod memory *limits* is capped at
# (allocatable - host reservation), so even a full simultaneous burst of every
# sandbox still fits in RAM. CPU IS overcommitted: CPU is compressible (it
# throttles, it does not OOM-kill), so per-pod CPU limits may exceed the core
# count and pods simply time-share. Concurrency is therefore gated by memory.
#
# Per-pod values are consumed by lib/manifest.sh; the quota functions are
# consumed by setup/common.sh.
set -euo pipefail

# --- Per-pod resources ------------------------------------------------------
# requests = guaranteed share used for scheduling; limits = burst ceiling.
POD_CPU_REQUEST="1"
POD_CPU_LIMIT="4"
POD_MEM_REQUEST_GI="2"
POD_MEM_LIMIT_GI="6"
POD_EPHEMERAL_REQUEST_GI="1"
POD_EPHEMERAL_LIMIT_GI="20"

# --- Host headroom ----------------------------------------------------------
# CPU/RAM kept aside for the OS, the k3s + containerd + Cilium + CoreDNS +
# hubble + gVisor stack, and the operator's own IDE/browser. Subtracted from
# node-allocatable before the sandbox quota is sized.
HOST_RESERVE_CPU="2"
HOST_RESERVE_MEM_GI="6"

# --- Bounds on the computed concurrent-pod ceiling --------------------------
# MAX is a defensive cap for large hosts, not a capacity estimate; raise it
# if a single node genuinely needs to run more sandboxes at once.
POD_CEILING_MIN="1"
POD_CEILING_MAX="16"

# --- Per-session dependency ceiling (Phase 5) -------------------------------
# A session's dependency pods (MCP servers, services, a browser) count against
# the namespace ResourceQuota like any pod — that is the hard node-level
# backstop. This is the per-SESSION guard (§2.7 #5): a single multi-dependency
# profile shouldn't be able to claim the whole namespace pod budget and starve
# other sessions, and a profile asking for an absurd number of dependencies
# should get a clear early error rather than a pod stuck Pending against the
# quota. Overridable via the environment for unusual installs.
SANDBOX_MAX_DEPS_PER_SESSION="${SANDBOX_MAX_DEPS_PER_SESSION:-6}"

# _node_allocatable <kubeconfig> <cpu|memory> — raw allocatable quantity for
# the (single-node) cluster. Empty string on failure.
_node_allocatable() {
  kubectl --kubeconfig "$1" get nodes \
    -o jsonpath="{.items[0].status.allocatable.$2}" 2>/dev/null || true
}

# _mem_to_gib <quantity> — k8s memory quantity -> integer GiB, rounded down.
# Handles Ki/Mi/Gi/Ti suffixes and plain bytes; 0 for empty/garbage.
_mem_to_gib() {
  local q="${1:-0}"
  case "${q}" in
    *Ki) awk -v v="${q%Ki}" 'BEGIN { printf "%d", v / 1048576 }' ;;
    *Mi) awk -v v="${q%Mi}" 'BEGIN { printf "%d", v / 1024 }' ;;
    *Gi) awk -v v="${q%Gi}" 'BEGIN { printf "%d", v }' ;;
    *Ti) awk -v v="${q%Ti}" 'BEGIN { printf "%d", v * 1024 }' ;;
    ''|*[!0-9]*) echo 0 ;;
    *)   awk -v v="${q}"    'BEGIN { printf "%d", v / 1073741824 }' ;;
  esac
}

# _cpu_to_cores <quantity> — k8s CPU quantity -> integer cores, rounded down.
# Handles the millicore suffix and plain cores; 0 for empty/garbage.
_cpu_to_cores() {
  local q="${1:-0}"
  case "${q}" in
    *m) awk -v v="${q%m}" 'BEGIN { printf "%d", v / 1000 }' ;;
    ''|*[!0-9]*) echo 0 ;;
    *)  awk -v v="${q}"   'BEGIN { printf "%d", v }' ;;
  esac
}

# compute_pod_ceiling <kubeconfig> — echo how many concurrent sandbox pods fit
# on the node. Gated by memory limits (no overcommit) and by CPU requests (the
# guaranteed share); clamped to [POD_CEILING_MIN, POD_CEILING_MAX]. Falls back
# to POD_CEILING_MIN with a warning if the node can't be read.
compute_pod_ceiling() {
  local kc="${1:?compute_pod_ceiling: kubeconfig path required}"

  local alloc_cpu alloc_mem
  alloc_cpu="$(_cpu_to_cores "$(_node_allocatable "${kc}" cpu)")"
  alloc_mem="$(_mem_to_gib "$(_node_allocatable "${kc}" memory)")"

  if (( alloc_cpu <= 0 || alloc_mem <= 0 )); then
    echo "  WARN: could not read node allocatable resources;" \
         "defaulting to ${POD_CEILING_MIN} sandbox pod." >&2
    echo "${POD_CEILING_MIN}"
    return 0
  fi

  local avail_cpu=$(( alloc_cpu - HOST_RESERVE_CPU ))
  local avail_mem=$(( alloc_mem - HOST_RESERVE_MEM_GI ))

  # Memory: no overcommit — the summed per-pod memory limits must fit.
  # CPU: gate on requests (the guaranteed share); limits may overcommit.
  local by_mem=$(( avail_mem / POD_MEM_LIMIT_GI ))
  local by_cpu=$(( avail_cpu / POD_CPU_REQUEST ))

  local n=$(( by_mem < by_cpu ? by_mem : by_cpu ))
  (( n < POD_CEILING_MIN )) && n="${POD_CEILING_MIN}"
  (( n > POD_CEILING_MAX )) && n="${POD_CEILING_MAX}"
  echo "${n}"
}

# render_resourcequota <pod_ceiling> — emit the ResourceQuota + LimitRange
# YAML for the sandbox namespace, scaled to <pod_ceiling> concurrent pods.
render_resourcequota() {
  local n="${1:?render_resourcequota: pod ceiling required}"

  local req_cpu=$(( n * POD_CPU_REQUEST ))
  local lim_cpu=$(( n * POD_CPU_LIMIT ))
  local req_mem=$(( n * POD_MEM_REQUEST_GI ))
  local lim_mem=$(( n * POD_MEM_LIMIT_GI ))
  local req_eph=$(( n * POD_EPHEMERAL_REQUEST_GI ))
  local lim_eph=$(( n * POD_EPHEMERAL_LIMIT_GI ))

  cat <<EOF
# Generated by lib/resources.sh at 'sandbox setup' time — do not edit by hand.
# Sized for ${n} concurrent sandbox pod(s) from node-allocatable CPU/memory
# minus the host reservation (${HOST_RESERVE_CPU} CPU / ${HOST_RESERVE_MEM_GI}Gi).
# Re-run 'sandbox setup' to resize after a hardware change.
apiVersion: v1
kind: ResourceQuota
metadata:
  name: sandbox-quota
  namespace: sandbox
spec:
  hard:
    # Concurrent pod ceiling — primary guard against session sprawl.
    pods: "${n}"
    requests.cpu: "${req_cpu}"
    requests.memory: "${req_mem}Gi"
    requests.ephemeral-storage: "${req_eph}Gi"
    # CPU limits may overcommit (CPU is compressible); memory limits do not —
    # limits.memory equals the no-overcommit ceiling so a full burst still fits.
    limits.cpu: "${lim_cpu}"
    limits.memory: "${lim_mem}Gi"
    limits.ephemeral-storage: "${lim_eph}Gi"
---
# Backstop: guarantees any manually-created pod still carries limits and cannot
# exceed the per-pod ceiling, so it can't bypass the ResourceQuota above.
apiVersion: v1
kind: LimitRange
metadata:
  name: sandbox-limits
  namespace: sandbox
spec:
  limits:
    - type: Container
      default:
        cpu: "${POD_CPU_LIMIT}"
        memory: "${POD_MEM_LIMIT_GI}Gi"
        ephemeral-storage: "${POD_EPHEMERAL_LIMIT_GI}Gi"
      defaultRequest:
        cpu: "${POD_CPU_REQUEST}"
        memory: "${POD_MEM_REQUEST_GI}Gi"
        ephemeral-storage: "${POD_EPHEMERAL_REQUEST_GI}Gi"
      max:
        cpu: "${POD_CPU_LIMIT}"
        memory: "${POD_MEM_LIMIT_GI}Gi"
        ephemeral-storage: "${POD_EPHEMERAL_LIMIT_GI}Gi"
EOF
}

# apply_resourcequota <kubeconfig> — size the namespace ResourceQuota to the
# node's capacity and apply it, printing what was computed.
apply_resourcequota() {
  local kc="${1:?apply_resourcequota: kubeconfig path required}"

  local alloc_cpu alloc_mem n
  alloc_cpu="$(_cpu_to_cores "$(_node_allocatable "${kc}" cpu)")"
  alloc_mem="$(_mem_to_gib "$(_node_allocatable "${kc}" memory)")"
  n="$(compute_pod_ceiling "${kc}")"

  echo "  Node allocatable:    ${alloc_cpu} CPU / ${alloc_mem}Gi RAM"
  echo "  Host reservation:    ${HOST_RESERVE_CPU} CPU / ${HOST_RESERVE_MEM_GI}Gi RAM"
  echo "  Per-pod memory:      ${POD_MEM_REQUEST_GI}Gi request / ${POD_MEM_LIMIT_GI}Gi limit (no overcommit)"
  echo "  Concurrent sandbox ceiling: ${n} pod(s)"

  render_resourcequota "${n}" | kubectl --kubeconfig "${kc}" apply -f -
}
