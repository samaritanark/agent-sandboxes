#!/usr/bin/env bash
# examples/teleport/bake-kubeconfig.sh — Convert a Teleport-managed kube
# context into a static kubeconfig suitable for `sandbox run --infra-kubeconfig`.
#
# This is the Teleport-specific recipe. Operators on other auth providers
# follow the same pattern with their own tooling — the goal is identical:
# produce a kubeconfig with credentials inlined (no exec plugin) that the
# sandbox can mount into the pod. Equivalents in other ecosystems:
#   - AWS EKS:        `aws eks update-kubeconfig` (then strip the exec block
#                      and inline an STS-issued token / IAM role).
#   - GCP GKE:        `gcloud container clusters get-credentials` (replace
#                      the gke-gcloud-auth-plugin exec with a static token).
#   - Azure AKS:      `az aks get-credentials` (likewise replace the
#                      kubelogin exec plugin with a static token).
#   - ServiceAccount: `kubectl create token` + paste it into a bare
#                      kubeconfig (works on any cluster, no SSO required).
#
# Teleport-specific notes:
#   The kubeconfig that `tsh kube login` writes uses an `exec:` block that
#   shells out to `tsh` on every request. That exec plugin does not work
#   inside the sandbox (no `tsh` binary, no `~/.tsh/` profile, and both are
#   off-limits to the agent by design). This script asks `tsh` for short-
#   lived client certs on the host and writes a kubeconfig with those certs
#   inlined, no exec plugin required.
#
# Requirements (on host):
#   - tsh, kubectl, jq on PATH
#   - active Teleport session: tsh login --proxy=<your-proxy>
#   - tsh kube login already run for the target cluster
#
# Usage:
#   examples/teleport/bake-kubeconfig.sh <kube-context> [output-path]
#
# Example:
#   examples/teleport/bake-kubeconfig.sh teleport.example.com-dev-cluster
#   sandbox run --tier 3 --repo ~/repos/infra \
#     --infra-kubeconfig ~/.kube/sandbox-dev-cluster.yaml
set -euo pipefail

CONTEXT="${1:?Usage: $0 <kube-context> [output-path|output-dir]}"
SAFE_NAME="$(echo "${CONTEXT}" | tr '/.' '-')"
OUT="${2:-${HOME}/.kube/sandbox-${SAFE_NAME}.yaml}"

# If OUT is an existing directory, write a default filename inside it.
if [[ -d "${OUT}" ]]; then
  OUT="${OUT%/}/sandbox-${SAFE_NAME}.yaml"
fi

for cmd in tsh kubectl jq; do
  command -v "${cmd}" >/dev/null \
    || { echo "ERROR: '${cmd}' not found in PATH" >&2; exit 1; }
done

if ! tsh status >/dev/null 2>&1; then
  echo "ERROR: not logged in to Teleport. Run 'tsh login --proxy=<proxy>' first." >&2
  exit 1
fi

# Find the cluster ref + user ref for the requested context, in the *current*
# kubeconfig (not minified — Teleport's tsh writes everything into ~/.kube/config).
CLUSTER_REF="$(kubectl config view --raw \
  -o jsonpath="{.contexts[?(@.name=='${CONTEXT}')].context.cluster}")"
USER_REF="$(kubectl config view --raw \
  -o jsonpath="{.contexts[?(@.name=='${CONTEXT}')].context.user}")"

if [[ -z "${CLUSTER_REF}" || -z "${USER_REF}" ]]; then
  echo "ERROR: no context named '${CONTEXT}' in kubeconfig." >&2
  echo "       Available contexts:" >&2
  kubectl config get-contexts -o name | sed 's/^/         /' >&2
  exit 1
fi

# Teleport tunnels kube API traffic through its proxy — preserve those fields
# verbatim (server URL, CA, optional SNI hint).
SERVER="$(kubectl config view --raw \
  -o jsonpath="{.clusters[?(@.name=='${CLUSTER_REF}')].cluster.server}")"
CA_DATA="$(kubectl config view --raw \
  -o jsonpath="{.clusters[?(@.name=='${CLUSTER_REF}')].cluster.certificate-authority-data}")"
TLS_SNI="$(kubectl config view --raw \
  -o jsonpath="{.clusters[?(@.name=='${CLUSTER_REF}')].cluster.tls-server-name}")"

# Pull --kube-cluster and --teleport-cluster out of the exec args to know
# what to ask tsh for. Both are required by recent tsh versions.
EXEC_ARGS="$(kubectl config view --raw -o json \
  | jq -r --arg u "${USER_REF}" '
      .users[] | select(.name == $u) | .user.exec.args // []
      | join(" ")
    ')"
KUBE_CLUSTER="$(echo "${EXEC_ARGS}" | grep -oE -- '--kube-cluster=[^ ]+' | head -1 | cut -d= -f2 || true)"
TELEPORT_CLUSTER="$(echo "${EXEC_ARGS}" | grep -oE -- '--teleport-cluster=[^ ]+' | head -1 | cut -d= -f2 || true)"
if [[ -z "${KUBE_CLUSTER}" ]]; then
  echo "ERROR: could not read --kube-cluster from exec args for user '${USER_REF}'." >&2
  echo "       Is this actually a Teleport-managed context?" >&2
  exit 1
fi
if [[ -z "${TELEPORT_CLUSTER}" ]]; then
  echo "ERROR: could not read --teleport-cluster from exec args for user '${USER_REF}'." >&2
  echo "       Is this actually a Teleport-managed context?" >&2
  exit 1
fi

# Derive the Teleport proxy host:port from the cluster.server URL — for
# Teleport-managed kube contexts the cluster.server IS the proxy. Required
# when you're logged into multiple Teleport clusters; without --proxy tsh
# picks the first profile and the auth handshake fails.
PROXY_HOST_PORT="${SERVER#http://}"
PROXY_HOST_PORT="${PROXY_HOST_PORT#https://}"
PROXY_HOST_PORT="${PROXY_HOST_PORT%%/*}"

echo "==> Fetching short-lived credentials for: ${TELEPORT_CLUSTER}/${KUBE_CLUSTER}"
echo "    via proxy: ${PROXY_HOST_PORT}"
CREDS_JSON="$(tsh \
  --proxy="${PROXY_HOST_PORT}" \
  kube credentials \
  --teleport-cluster="${TELEPORT_CLUSTER}" \
  --kube-cluster="${KUBE_CLUSTER}")"
CERT="$(echo "${CREDS_JSON}" | jq -r '.status.clientCertificateData // empty')"
KEY="$(echo "${CREDS_JSON}" | jq -r '.status.clientKeyData // empty')"
EXPIRY="$(echo "${CREDS_JSON}" | jq -r '.status.expirationTimestamp // empty')"

[[ -n "${CERT}" && -n "${KEY}" ]] \
  || { echo "ERROR: tsh did not return a client certificate/key" >&2; exit 1; }

# tsh returns raw PEM (multi-line); kubeconfig wants single-line base64.
# `tr -d '\n'` strips the line wrapping that base64 adds on both GNU and BSD.
CERT_B64="$(printf '%s' "${CERT}" | base64 | tr -d '\n')"
KEY_B64="$(printf '%s' "${KEY}" | base64 | tr -d '\n')"

CTX_NAME="${KUBE_CLUSTER}"
USER_NAME="sandbox-${KUBE_CLUSTER}"
CLUSTER_NAME="${KUBE_CLUSTER}"

mkdir -p "$(dirname "${OUT}")"
umask 077
{
  echo "apiVersion: v1"
  echo "kind: Config"
  echo "clusters:"
  echo "- name: ${CLUSTER_NAME}"
  echo "  cluster:"
  echo "    server: ${SERVER}"
  echo "    certificate-authority-data: ${CA_DATA}"
  [[ -n "${TLS_SNI}" ]] && echo "    tls-server-name: ${TLS_SNI}"
  echo "users:"
  echo "- name: ${USER_NAME}"
  echo "  user:"
  echo "    client-certificate-data: ${CERT_B64}"
  echo "    client-key-data: ${KEY_B64}"
  echo "contexts:"
  echo "- name: ${CTX_NAME}"
  echo "  context:"
  echo "    cluster: ${CLUSTER_NAME}"
  echo "    user: ${USER_NAME}"
  echo "current-context: ${CTX_NAME}"
} > "${OUT}"

chmod 0600 "${OUT}"

echo "==> Wrote static kubeconfig: ${OUT}"
[[ -n "${EXPIRY}" ]] && echo "    Expires: ${EXPIRY}"
echo
echo "Use with:"
echo "  sandbox run --agent claude --tier 3 --repo ~/repos/your-infra-repo \\"
echo "    --infra-kubeconfig ${OUT}"
