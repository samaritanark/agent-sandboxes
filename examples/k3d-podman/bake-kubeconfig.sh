#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# examples/k3d-podman/bake-kubeconfig.sh — Rewrite a k3d cluster's kubeconfig
# so it's usable from `sandbox run --infra-kubeconfig`.
#
# k3d's kubeconfig already has static credentials inlined (client cert/key,
# no exec plugin) — the one thing that doesn't work as-is is the server
# address. k3d points `server:` at 127.0.0.1 (or 0.0.0.0), which means "this
# pod" from inside an agent session, not "the host". This script replaces it
# with the host's real, routable IPv4 (the same primary address Cilium
# already SNATs pod egress to — see docs/how-to/local-k3d-podman.md), so the
# sandbox's egress allowlisting and the kube API connection both land on an
# address that's actually reachable from the pod's network namespace.
#
# Requirements (on host):
#   - k3d, kubectl on PATH
#   - the target k3d cluster is already running (`k3d cluster list`)
#   - k3d's API server port is published on a routable interface, not just
#     127.0.0.1 (check with `k3d cluster get <name>` / your `--api-port` flag
#     at cluster-create time)
#
# Usage:
#   examples/k3d-podman/bake-kubeconfig.sh <k3d-cluster-name> [output-path]
#
# Example:
#   examples/k3d-podman/bake-kubeconfig.sh sandbox-target
#   sandbox run --tier 3 --repo ~/repos/infra \
#     --infra-kubeconfig ~/.kube/sandbox-k3d-sandbox-target.yaml
set -euo pipefail

CLUSTER="${1:?Usage: $0 <k3d-cluster-name> [output-path|output-dir]}"
SAFE_NAME="$(echo "${CLUSTER}" | tr '/.' '-')"
OUT="${2:-${HOME}/.kube/sandbox-k3d-${SAFE_NAME}.yaml}"

# If OUT is an existing directory, write a default filename inside it.
if [[ -d "${OUT}" ]]; then
  OUT="${OUT%/}/sandbox-k3d-${SAFE_NAME}.yaml"
fi

for cmd in k3d kubectl; do
  command -v "${cmd}" >/dev/null \
    || { echo "ERROR: '${cmd}' not found in PATH" >&2; exit 1; }
done

if ! k3d cluster list "${CLUSTER}" >/dev/null 2>&1; then
  echo "ERROR: no k3d cluster named '${CLUSTER}'." >&2
  echo "       Available clusters:" >&2
  k3d cluster list | sed 's/^/         /' >&2
  exit 1
fi

echo "==> Fetching kubeconfig for k3d cluster: ${CLUSTER}"
RAW_KUBECONFIG="$(mktemp -t k3d-kubeconfig.XXXXXX)"
trap 'rm -f "${RAW_KUBECONFIG}"' EXIT
k3d kubeconfig get "${CLUSTER}" > "${RAW_KUBECONFIG}"

# Detect the host's primary routable IPv4 — the same address Cilium already
# uses as the SNAT source for pod egress (see docs/how-to/corporate-vpn.md).
PRIMARY_IP="$(ip -4 route get 1.1.1.1 2>/dev/null \
  | awk '{for (i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')"
if [[ -z "${PRIMARY_IP}" ]]; then
  echo "ERROR: could not determine the host's primary IPv4 address (tried" >&2
  echo "       'ip -4 route get 1.1.1.1'). Pass it manually by editing this" >&2
  echo "       script or the output kubeconfig's 'server:' field." >&2
  exit 1
fi

ORIG_SERVER="$(kubectl --kubeconfig="${RAW_KUBECONFIG}" config view --minify \
  -o jsonpath='{.clusters[0].cluster.server}')"
ORIG_PORT="${ORIG_SERVER##*:}"
ORIG_PORT="${ORIG_PORT%%/*}"
if [[ ! "${ORIG_PORT}" =~ ^[0-9]+$ ]]; then
  echo "ERROR: could not parse a port out of server URL '${ORIG_SERVER}'." >&2
  exit 1
fi

CLUSTER_REF="$(kubectl --kubeconfig="${RAW_KUBECONFIG}" config view --minify \
  -o jsonpath='{.clusters[0].name}')"
NEW_SERVER="https://${PRIMARY_IP}:${ORIG_PORT}"
echo "==> Rewriting server: ${ORIG_SERVER} -> ${NEW_SERVER}"

mkdir -p "$(dirname "${OUT}")"
umask 077
kubectl --kubeconfig="${RAW_KUBECONFIG}" config set-cluster "${CLUSTER_REF}" \
  --server="${NEW_SERVER}" >/dev/null

# Minify + flatten now so the output is self-contained and inspectable on
# its own — `sandbox run --infra-kubeconfig` will do this again, harmlessly.
kubectl --kubeconfig="${RAW_KUBECONFIG}" config view --minify --flatten \
  > "${OUT}"
chmod 0600 "${OUT}"

echo "==> Wrote kubeconfig: ${OUT}"
echo
echo "Before wiring this into the sandbox, smoke-test reachability from the host:"
echo "  curl -k https://${PRIMARY_IP}:${ORIG_PORT}/version"
echo
echo "Use with:"
echo "  sandbox run --agent claude --tier 3 --repo ~/repos/your-infra-repo \\"
echo "    --infra-kubeconfig ${OUT}"
