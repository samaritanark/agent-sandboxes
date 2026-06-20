#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
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

# read_into_array <array_name> — portable `mapfile -t` replacement.
# Reads every line of stdin into the named indexed array, one element per line.
# macOS ships bash 3.2, which has no mapfile/readarray; this avoids them while
# preserving `mapfile -t` semantics: a final line with no trailing newline is
# kept, and empty input yields an empty array. The line is appended via a
# quoted expansion evaluated at eval-time, so values containing spaces, quotes,
# or glob characters are preserved literally (no word-splitting or injection).
read_into_array() {
  local __array_name="$1" __line
  eval "${__array_name}=()"
  while IFS= read -r __line || [[ -n "${__line}" ]]; do
    eval "${__array_name}+=( \"\${__line}\" )"
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

# host_agent_home <agent> — the operator-home staging/persistence dir for an
# agent's config (auth tokens, settings). 'sandbox onboard' writes here, and on
# macOS the in-VM working copy is seeded from here. Always on the operator's
# home, so it survives even a VM rebuild.
host_agent_home() {
  echo "${HOME}/.sandbox/agent-home/${1}"
}

# VM-local base for the agent-home the pod actually mounts on macOS. The pod's
# hostPath must NOT be the 9p-shared Mac home: the gVisor gofer runs as root and,
# over Lima's mapped-xattr 9p, presents every file the container creates as
# root-owned. The agent runs as uid 1000, so it cannot write the nested dirs
# Claude Code creates at runtime (session-env/, sessions/, projects/) and the
# OAuth token written by /login silently fails to persist — the next request
# reports "Not logged in". A VM-local ext4 path behaves like a native Linux host
# (the gofer owns new files as the container's uid 1000), so writes succeed.
SANDBOX_VM_AGENT_HOME_BASE="${SANDBOX_VM_AGENT_HOME_BASE:-/var/lib/sandbox/agent-home}"

# resolve_agent_home <agent> — the path the NODE mounts as the agent-home
# hostPath. On macOS this is the VM-local ext4 path (see above). On Linux/WSL
# the CLI, k3s, and this directory all share one filesystem, so there is no
# uid-remapping layer and the host path is mounted directly.
resolve_agent_home() {
  if is_macos; then
    echo "${SANDBOX_VM_AGENT_HOME_BASE}/${1}"
  else
    host_agent_home "${1}"
  fi
}
