#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# lib/lima.sh — Lima VM management helpers (macOS only)
set -euo pipefail

LIMA_VM_NAME="${LIMA_VM_NAME:-sandbox-vm}"
# Lima config is rendered from a template (port substituted) by setup/macos.sh.
LIMA_TEMPLATE="${SANDBOX_ROOT}/lima/sandbox-vm.yaml.tmpl"
LIMA_CONFIG="${HOME}/.sandbox/lima-sandbox-vm.yaml"

# HOME for the in-VM Mutagen daemon that keeps tier 2/3 workspaces in sync (see
# prepare_workspace). Mutagen runs as uid 1000 so the VM-local ext4 copy it
# writes is owned by the agent; this dir holds its daemon socket and session
# state under <home>/.mutagen. Lives on VM-local ext4, owned 1000.
SANDBOX_VM_MUTAGEN_HOME="${SANDBOX_VM_MUTAGEN_HOME:-/var/lib/sandbox/mutagen-home}"

# Username the in-VM Mutagen process runs as. It must run as uid 1000 (so the
# ext4 copy it writes is owned by the agent) AND under a real passwd entry:
# `sudo -u '#1000'` fails on stock Ubuntu when no user owns that uid
# ("sudo: unknown user #1000"), and the Lima guest user is not uid 1000.
# _ensure_vm_sync_user creates this user with uid 1000 when the uid is free, or
# reuses whatever user already owns uid 1000.
SANDBOX_VM_SYNC_USER="${SANDBOX_VM_SYNC_USER:-sandbox-agent}"

# lima_vm_running — returns 0 if VM is running
lima_vm_running() {
  if ! command -v limactl &>/dev/null; then
    return 1
  fi
  local status
  status="$(limactl list --format '{{.Name}} {{.Status}}' 2>/dev/null \
    | awk -v vm="${LIMA_VM_NAME}" '$1==vm {print $2}')"
  [[ "${status}" == "Running" ]]
}

# ensure_lima_running — start Lima VM if not already running (macOS only)
ensure_lima_running() {
  if ! is_macos; then
    return 0
  fi

  require_command limactl "Install Lima: brew install lima"

  if lima_vm_running; then
    return 0
  fi

  local existing
  existing="$(limactl list --format '{{.Name}}' 2>/dev/null | grep -x "${LIMA_VM_NAME}" || true)"

  if [[ -z "${existing}" ]]; then
    if [[ ! -f "${LIMA_CONFIG}" ]]; then
      # No rendered config (setup never ran on this host) — render with the
      # default API server port so the VM can still be created. Run
      # 'sandbox setup --apiserver-port <PORT>' to pick a different port.
      mkdir -p "${HOME}/.sandbox"
      sed "s/__APISERVER_PORT__/${SANDBOX_APISERVER_PORT:-6443}/g" \
        "${LIMA_TEMPLATE}" > "${LIMA_CONFIG}"
    fi
    echo "==> Creating Lima VM '${LIMA_VM_NAME}' from ${LIMA_CONFIG}..."
    limactl start --name "${LIMA_VM_NAME}" "${LIMA_CONFIG}"
  else
    echo "==> Starting Lima VM '${LIMA_VM_NAME}'..."
    limactl start "${LIMA_VM_NAME}"
  fi

  # Wait for k3s inside VM to become ready. Uses sudo: k3s writes its
  # kubeconfig root-only (mode 0600), so a non-root kubectl in the VM
  # cannot read it.
  echo "==> Waiting for k3s inside Lima VM..."
  local retries=30
  local i=0
  until limactl shell "${LIMA_VM_NAME}" -- sudo kubectl get nodes &>/dev/null; do
    (( i++ )) || true
    if [[ "${i}" -ge "${retries}" ]]; then
      echo "ERROR: k3s inside Lima VM did not become ready after ${retries} attempts." >&2
      exit 1
    fi
    sleep 5
  done
  echo "==> Lima VM and k3s ready."
}

# lima_kubectl — run kubectl inside Lima VM (macOS helper). Uses sudo in the
# VM because k3s writes its kubeconfig root-only (mode 0600).
lima_kubectl() {
  if is_macos; then
    limactl shell "${LIMA_VM_NAME}" -- sudo kubectl "$@"
  else
    kubectl "$@"
  fi
}

# prepare_agent_home <agent> — ensure the agent-home directory the pod mounts
# exists and is writable by the pod's uid 1000 BEFORE the pod starts (hostPath
# type: Directory requires it to pre-exist on the node).
#
# macOS: create the VM-local working dir and chown it to 1000:1000 so the agent
# owns every file it later writes. Seed it from the host staging dir (onboard's
# output, visible inside the VM at the same absolute path via the 9p home mount)
# with cp -u: a file is (re)seeded only when the working copy lacks it OR the
# staged copy is newer. So `sandbox onboard --force` (which rewrites staging with
# a fresh token) takes effect on the next launch, while a token refreshed by an
# in-session /login — newer in the working copy, which persists on the VM disk —
# is never clobbered by older staged state. Teardown sync-back preserves mtimes,
# so staging and the working copy stay in step across sessions.
#
# Linux/WSL: the host dir IS the mount. chown to 1000:1000 where we are
# privileged enough (root in a WSL distro; a harmless no-op for the uid-1000
# Linux operator) and fall back to the historical world-writable chmod for the
# uncommon non-root, non-1000 operator.
prepare_agent_home() {
  local agent="$1"
  local mount_home staging
  mount_home="$(resolve_agent_home "${agent}")"
  staging="$(host_agent_home "${agent}")"
  mkdir -p "${staging}"

  if is_macos; then
    limactl shell "${LIMA_VM_NAME}" -- sudo sh -c '
      set -e
      mount_home="$1"; staging="$2"
      mkdir -p "$mount_home"
      if [ -d "$staging" ]; then
        for f in .credentials.json settings.json .claude.json auth.json config.toml; do
          if [ -f "$staging/$f" ]; then cp -u "$staging/$f" "$mount_home/$f"; fi
        done
      fi
      chown -R 1000:1000 "$mount_home"
      chmod 700 "$mount_home"
      [ -f "$mount_home/.credentials.json" ] && chmod 600 "$mount_home/.credentials.json" || true
      [ -f "$mount_home/auth.json" ] && chmod 600 "$mount_home/auth.json" || true
    ' _ "${mount_home}" "${staging}" \
      || die "Failed to prepare VM-local agent-home for '${agent}' inside ${LIMA_VM_NAME}."
  else
    chown -R 1000:1000 "${staging}" 2>/dev/null \
      || find "${staging}" -exec chmod u+rwX,go+rwX {} + 2>/dev/null \
      || true
  fi
}

# sync_agent_home_back <agent> — macOS only; best-effort. Copy the in-VM
# working copy of the agent-home back to the host staging dir
# (~/.sandbox/agent-home/<agent>) so host-side tooling sees current state: the
# audit transcript capture (which reads the host path), and a durable backup of
# the OAuth token that survives even a VM rebuild (prepare_agent_home re-seeds
# from it). cp -au is incremental (only newer files) and preserves modes and
# timestamps, so the transcript capture's -newer filter still works. Writes land
# owned by the Mac user (the 9p server's uid), readable by host tooling. A no-op
# on Linux/WSL, where the mount already IS the host staging dir.
sync_agent_home_back() {
  is_macos || return 0
  local agent="$1"
  local mount_home staging
  mount_home="$(resolve_agent_home "${agent}")"
  staging="$(host_agent_home "${agent}")"
  mkdir -p "${staging}"

  if ! limactl shell "${LIMA_VM_NAME}" -- sudo sh -c '
    mount_home="$1"; staging="$2"
    [ -d "$mount_home" ] || exit 0
    cp -au "$mount_home/." "$staging/" 2>/dev/null || true
  ' _ "${mount_home}" "${staging}" 2>/dev/null; then
    warn "Could not sync agent-home back to ${staging} (VM stopped?); transcript/backup may be stale."
  fi
}

# ensure_mutagen_in_vm — macOS only. Make the `mutagen` binary available inside
# the Lima VM, installing it once if absent. Mutagen drives the tier 2/3
# workspace sync (prepare_workspace); it runs in the VM, not on the host, so
# adopting this feature needs no host-side Homebrew dependency and no VM
# recreate. Idempotent: a no-op once installed. Mirrors install_lima_if_needed.
ensure_mutagen_in_vm() {
  is_macos || return 0
  if limactl shell "${LIMA_VM_NAME}" -- sh -c 'command -v mutagen >/dev/null 2>&1'; then
    return 0
  fi
  echo "==> Installing Mutagen into ${LIMA_VM_NAME} (one-time)..."
  # Resolve the latest release tag via the GitHub redirect (same trick the Lima
  # template uses for nerdctl), then fetch the linux asset for the VM's arch.
  # Mutagen's release assets use Go-style arch names (amd64 / arm64). Only the
  # `mutagen` binary is needed — the agent tarball is for remote endpoints, and
  # our sync is local-to-local inside the VM.
  limactl shell "${LIMA_VM_NAME}" -- sudo sh -c '
    set -e
    ver="$(curl -fsSL -o /dev/null -w "%{url_effective}" \
      https://github.com/mutagen-io/mutagen/releases/latest | sed -E "s#.*/tag/##")"
    arch="$(uname -m | sed "s/x86_64/amd64/; s/aarch64/arm64/")"
    tmp="$(mktemp -d)"
    curl -fsSL "https://github.com/mutagen-io/mutagen/releases/download/${ver}/mutagen_linux_${arch}_${ver}.tar.gz" \
      | tar -xz -C "$tmp"
    install -m 0755 "$tmp/mutagen" /usr/local/bin/mutagen
    rm -rf "$tmp"
  ' || die "Failed to install Mutagen inside ${LIMA_VM_NAME}."
}

# prepare_workspace <session> <repo>... — macOS only; a no-op on Linux/WSL,
# where the repo is mounted directly and writes already work. For each tier 2/3
# repo, create the per-session VM-local ext4 working copy the pod mounts
# (resolve_workspace_mount) owned by uid 1000, then start an in-VM Mutagen
# daemon (as uid 1000) that keeps that copy in near-live two-way sync with the
# host repo. The host repo is reachable inside the VM at its own absolute path
# via the writable 9p home mount, so both sync endpoints are VM-local — no
# host-side Mutagen and no SSH. Because Mutagen is an ordinary VM process (not
# the gVisor gofer), it writes the 9p mount normally and mapped-xattr keeps the
# host's real file ownership intact (see [[project_macos_9p_over_virtiofs]]).
#
# The masked secret paths (lib/filesystem.sh) are excluded from the sync so
# .env / kubeconfig / .kube/ / *-openrc.sh never reach the VM-local copy —
# reinforcing the mount-layer masking. The initial sync is flushed (blocking)
# before returning, because the pod's hostPath (type: Directory) must pre-exist
# and be populated when the pod starts.
# _ensure_vm_sync_user — echo the VM username that owns uid 1000, creating a
# dedicated SANDBOX_VM_SYNC_USER (uid 1000, no login) if the uid is free. The
# in-VM Mutagen process runs as this user so the ext4 copy is owned by the same
# uid the pod runs as. Idempotent; echoes the resolved username on stdout.
_ensure_vm_sync_user() {
  limactl shell "${LIMA_VM_NAME}" -- sudo sh -c '
    set -e
    want="$1"
    u="$(getent passwd 1000 | cut -d: -f1)"
    if [ -z "$u" ]; then
      useradd -u 1000 -M -s /bin/sh "$want" >/dev/null 2>&1 || true
      u="$(getent passwd 1000 | cut -d: -f1)"
    fi
    printf "%s" "$u"
  ' _ "${SANDBOX_VM_SYNC_USER}"
}

prepare_workspace() {
  is_macos || return 0
  local session="$1"; shift
  [[ "$#" -gt 0 ]] || return 0

  ensure_mutagen_in_vm

  local syncuser
  syncuser="$(_ensure_vm_sync_user)"
  [[ -n "${syncuser}" ]] \
    || die "Could not resolve or create a uid-1000 sync user in ${LIMA_VM_NAME}."

  # Build root-anchored ignore flags from the single source of truth so the sync
  # exclusions cannot drift from the pod-level mask. `set -f` in the VM script
  # below stops the shell from glob-expanding the *-openrc.sh pattern. The
  # built-in flags are shared; per-repo configured masked_paths are appended
  # inside the loop so each repo's mask matches its own config.
  local base_ignore_flags="" f
  for f in "${MASKED_FILE_PATHS[@]}"; do base_ignore_flags+=" --ignore=/${f}"; done
  base_ignore_flags+=" --ignore=/${MASKED_DIR_PATH}/"
  base_ignore_flags+=" --ignore=/${MASKED_OPENRC_PATTERN}"

  local repo bname ext4 ignore_flags mp
  for repo in "$@"; do
    bname="$(basename "${repo}")"
    ext4="$(resolve_workspace_mount "${session}" "${repo}")"
    ignore_flags="${base_ignore_flags}"
    while IFS= read -r mp; do
      [[ -n "${mp}" ]] && ignore_flags+=" --ignore=/${mp}"
    done < <(load_repo_masked_paths "${repo}")
    limactl shell "${LIMA_VM_NAME}" -- sudo sh -c '
      set -ef
      ext4="$1"; repo_in_vm="$2"; session="$3"; bname="$4"; mhome="$5"; ignores="$6"; syncuser="$7"
      mkdir -p "$ext4" "$mhome"
      chown 1000:1000 "$ext4" "$(dirname "$ext4")" "$mhome"
      sudo -u "$syncuser" env HOME="$mhome" /usr/local/bin/mutagen sync create \
        --label=sandbox-session="$session" \
        --label=sandbox-repo="$bname" \
        --sync-mode=two-way-safe \
        $ignores \
        "$repo_in_vm" "$ext4"
    ' _ "${ext4}" "${repo}" "${session}" "${bname}" "${SANDBOX_VM_MUTAGEN_HOME}" "${ignore_flags}" "${syncuser}" \
      || die "Failed to start workspace sync for '${bname}' inside ${LIMA_VM_NAME}."
  done

  # Block until every just-created session has completed one synchronization
  # cycle, so the pod sees a fully populated workspace at start.
  limactl shell "${LIMA_VM_NAME}" -- sudo -u "${syncuser}" \
    env HOME="${SANDBOX_VM_MUTAGEN_HOME}" /usr/local/bin/mutagen sync flush \
    --label-selector="sandbox-session=${session}" \
    || warn "Initial workspace sync did not flush cleanly for session ${session}; the workspace may be incomplete."
}

# teardown_workspace_sync <session> — macOS only; best-effort. Flush the final
# agent edits back to the host repo (so capture_workspace_diff, which reads the
# host path, sees them), terminate the session's Mutagen sessions, and remove
# the VM-local working copy. Must run BEFORE the workspace-diff capture in
# cmd_stop. A stopped VM or an already-gone session must not block teardown, so
# every step is error-tolerant — matching sync_agent_home_back.
teardown_workspace_sync() {
  is_macos || return 0
  local session="$1"
  local sel="sandbox-session=${session}"
  local syncuser
  syncuser="$(_ensure_vm_sync_user)"
  [[ -n "${syncuser}" ]] || syncuser="${SANDBOX_VM_SYNC_USER}"
  limactl shell "${LIMA_VM_NAME}" -- sudo -u "${syncuser}" env HOME="${SANDBOX_VM_MUTAGEN_HOME}" \
    /usr/local/bin/mutagen sync flush --label-selector="${sel}" 2>/dev/null \
    || warn "Could not flush workspace sync for session ${session} (VM stopped?); host repo may be missing the agent's final edits."
  limactl shell "${LIMA_VM_NAME}" -- sudo -u "${syncuser}" env HOME="${SANDBOX_VM_MUTAGEN_HOME}" \
    /usr/local/bin/mutagen sync terminate --label-selector="${sel}" 2>/dev/null || true
  limactl shell "${LIMA_VM_NAME}" -- sudo rm -rf "${SANDBOX_VM_WORKSPACE_BASE}/${session}" 2>/dev/null || true
}

# stop_lima_vm — gracefully stop Lima VM
stop_lima_vm() {
  if is_macos && lima_vm_running; then
    echo "==> Stopping Lima VM '${LIMA_VM_NAME}'..."
    limactl stop "${LIMA_VM_NAME}"
  fi
}
