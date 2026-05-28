#!/usr/bin/env bash
# lib/platform.sh — Platform detection helpers
set -euo pipefail

# Canonical kubeconfig for the sandbox k3s cluster.
# All kubectl and helm calls must use this explicitly so that the user's
# default ~/.kube/config (which may point to other clusters) is never used.
SANDBOX_KUBECONFIG="${SANDBOX_KUBECONFIG:-${HOME}/.sandbox/kubeconfig}"

# kubectl wrapper — always targets the sandbox k3s cluster.
# Shadowing the bare 'kubectl' command ensures every call in bin/sandbox and
# all lib/*.sh files uses --kubeconfig without needing per-call changes.
kubectl() {
  command kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" "$@"
}

# detect_platform — returns "linux" or "macos"
detect_platform() {
  local uname_out
  uname_out="$(uname -s)"
  case "${uname_out}" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "macos" ;;
    *)       echo "unknown:${uname_out}" ;;
  esac
}

# require_command — die if a command is not in PATH
require_command() {
  local cmd="$1"
  local hint="${2:-install ${cmd}}"
  if ! command -v "${cmd}" &>/dev/null; then
    echo "ERROR: '${cmd}' not found in PATH. ${hint}" >&2
    exit 1
  fi
}

# require_commands — check multiple commands
require_commands() {
  for cmd in "$@"; do
    require_command "${cmd}"
  done
}

# is_linux / is_macos — boolean helpers
is_linux() {
  [[ "$(detect_platform)" == "linux" ]]
}

is_macos() {
  [[ "$(detect_platform)" == "macos" ]]
}

# is_wsl — true when running inside a WSL distro on a Windows host.
# The WSL kernel stamps "microsoft" / "WSL" into /proc/sys/kernel/osrelease;
# detect_platform still returns "linux" because uname -s is Linux, so we need
# this separate predicate for WSL-only guards (e.g. refusing /mnt/* --repo
# paths whose NTFS<->WSL boundary kills filesystem perf).
is_wsl() {
  [[ -r /proc/sys/kernel/osrelease ]] \
    && grep -qiE 'microsoft|wsl' /proc/sys/kernel/osrelease
}
