#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# setup.sh — Main sandbox setup entrypoint
set -euo pipefail

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common setup functions
# shellcheck source=setup/common.sh
source "${SANDBOX_ROOT}/setup/common.sh"

main() {
  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pod-cidr)
        SANDBOX_POD_CIDR="$2"
        shift 2
        ;;
      --pod-cidr=*)
        SANDBOX_POD_CIDR="${1#*=}"
        shift
        ;;
      --service-cidr)
        SANDBOX_SERVICE_CIDR="$2"
        shift 2
        ;;
      --service-cidr=*)
        SANDBOX_SERVICE_CIDR="${1#*=}"
        shift
        ;;
      --apiserver-port)
        SANDBOX_APISERVER_PORT="$2"
        shift 2
        ;;
      --apiserver-port=*)
        SANDBOX_APISERVER_PORT="${1#*=}"
        shift
        ;;
      --dns)
        SANDBOX_DNS="$2"
        shift 2
        ;;
      --dns=*)
        SANDBOX_DNS="${1#*=}"
        shift
        ;;
      *)
        echo "ERROR: Unknown argument: $1" >&2
        echo "Usage: $0 [--pod-cidr CIDR] [--service-cidr CIDR] [--apiserver-port PORT] [--dns IP[,IP]]" >&2
        exit 1
        ;;
    esac
  done

  # The Kubernetes API server port defaults to 6443 (the k3s/upstream default).
  # It is overridable so the sandbox cluster can coexist with another local
  # Kubernetes endpoint already bound to 6443 — e.g. tooling that talks to a
  # cluster on OpenStack — which otherwise collides with the sandbox cluster.
  if ! [[ "${SANDBOX_APISERVER_PORT}" =~ ^[0-9]+$ ]] \
     || (( SANDBOX_APISERVER_PORT < 1 || SANDBOX_APISERVER_PORT > 65535 )); then
    echo "ERROR: --apiserver-port must be an integer between 1 and 65535 (got: '${SANDBOX_APISERVER_PORT}')" >&2
    exit 1
  fi

  local platform
  platform="$(uname -s)"

  echo "=== AI Agent Sandbox Setup ==="
  echo "Platform:        ${platform}"
  echo "Pod CIDR:        ${SANDBOX_POD_CIDR}"
  echo "Service CIDR:    ${SANDBOX_SERVICE_CIDR}"
  echo "API server port: ${SANDBOX_APISERVER_PORT}"
  echo ""

  case "${platform}" in
    Linux)
      # shellcheck source=setup/linux.sh
      source "${SANDBOX_ROOT}/setup/linux.sh"
      setup_linux
      ;;
    Darwin)
      # --dns / SANDBOX_DNS is not wired into the macOS/Lima path (the Lima VM
      # derives a pod-reachable resolver on its own). Warn rather than silently
      # ignore, so the operator isn't misled into thinking it took effect.
      if [[ -n "${SANDBOX_DNS}" ]]; then
        echo "WARN: --dns / SANDBOX_DNS is not supported on macOS and will be" >&2
        echo "      ignored; the Lima VM resolves DNS on its own." >&2
      fi
      # shellcheck source=setup/macos.sh
      source "${SANDBOX_ROOT}/setup/macos.sh"
      setup_macos
      ;;
    *)
      echo "ERROR: Unsupported platform: ${platform}" >&2
      echo "  Supported platforms: Linux, macOS (Darwin)" >&2
      exit 1
      ;;
  esac

  # Common post-platform setup
  setup_common

  # Build container images and import them into k3s containerd
  build_images

  # Record the component versions this run provisioned with (for status/upgrade).
  record_infra_versions

  # Embed the CLI version identity from git, once, so `sandbox version` reads it
  # instead of recomputing at runtime (see stamp_version_if_git in
  # lib/platform.sh). A released tarball has no .git and keeps its shipped
  # .version.
  stamp_version_if_git

  echo ""
  echo "=== Setup complete ==="
  echo ""
  echo "Next steps:"
  echo "  1. Run a session: sandbox run --agent claude --tier 1"
  echo "  2. Check status:  sandbox status"
  echo ""
  echo "  To rebuild images after changes:"
  echo "    sandbox rebuild --agent <claude|codex|opencode|shell|base|all>"
  echo "    sandbox rebuild --agent all --no-cache   (force a full rebuild)"
  echo "    sandbox rebuild --help                   (see all options)"
}

main "$@"
