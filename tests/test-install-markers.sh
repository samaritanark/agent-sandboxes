#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-install-markers.sh — install-ownership markers (setup/common.sh).
# Cluster-free.
#
# These markers are what lets `sandbox uninstall` remove ONLY the host
# components setup installed itself (k3s, gVisor, nerdctl/buildkit, Helm, the
# masquerade service, firewalld CIDRs) and never clobber a pre-existing install
# of the same thing. This locks in:
#   - mark_installed / installed_by_sandbox / unmark_installed round-trip,
#     including the optional detail line uninstall parses for firewalld CIDRs
#   - backup_preexisting / restore_preexisting (used for the shared config files
#     an installer must rewrite: buildkitd.toml, runsc.toml), including the
#     "already ours -> don't re-backup" guard that protects the stashed original
#   - the content-signature detectors that backfill markers on hosts set up by
#     an older sandbox (k3s unit, buildkitd.toml, runsc.toml)
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- Shim harness --------------------------------------------------------
# sudo -> exec-through, so the helpers' `sudo mkdir/tee/cp/rm` operate as this
# test user inside the temp dirs below rather than touching the real host.
SHIMBIN="$(mktemp -d)"
cat > "${SHIMBIN}/sudo" <<'EOF'
#!/usr/bin/env bash
exec "$@"
EOF
chmod +x "${SHIMBIN}/sudo"
PATH="${SHIMBIN}:${PATH}"

# Redirect every host path the helpers touch into a throwaway tree.
WORK="$(mktemp -d)"
export SANDBOX_MARKER_DIR="${WORK}/markers"
export SANDBOX_K3S_SERVICE_UNIT="${WORK}/k3s.service"
export SANDBOX_BUILDKIT_CONFIG="${WORK}/buildkitd.toml"
export SANDBOX_RUNSC_CONFIG="${WORK}/runsc.toml"

trap 'rm -rf "${SHIMBIN}" "${WORK}"' EXIT

# common.sh defines the marker helpers (and sources the lib/* it needs). It only
# defines functions / sets vars at source time, so this is side-effect free.
# shellcheck disable=SC1091
source "${SANDBOX_ROOT}/setup/common.sh"

# --- Assertions ----------------------------------------------------------
ok_true()  { if "$@"; then pass "$* (true)"; else fail "expected true: $*"; fi; }
ok_false() { if "$@"; then fail "expected false: $*"; else pass "$* (false)"; fi; }

# --- mark / installed / unmark round-trip --------------------------------
ok_false installed_by_sandbox k3s
mark_installed k3s
ok_true installed_by_sandbox k3s
[[ -f "${SANDBOX_MARKER_DIR}/k3s" ]] || fail "marker file not created"
grep -q '^installed-by=ai-agent-sandboxes$' "${SANDBOX_MARKER_DIR}/k3s" \
  || fail "marker missing provenance stamp"
unmark_installed k3s
ok_false installed_by_sandbox k3s

# --- detail line (firewalld CIDR list rides here) ------------------------
mark_installed firewalld-cidrs "100.64.0.0/10 10.43.0.0/16"
detail="$(sed -n 's/^detail=//p' "${SANDBOX_MARKER_DIR}/firewalld-cidrs")"
[[ "${detail}" == "100.64.0.0/10 10.43.0.0/16" ]] \
  || fail "detail round-trip: got '${detail}'"
pass "detail line round-trips the CIDR list"
# No detail => no detail line.
mark_installed gvisor
grep -q '^detail=' "${SANDBOX_MARKER_DIR}/gvisor" && fail "unexpected detail line"
pass "marker without detail omits the detail line"
unmark_installed gvisor
unmark_installed firewalld-cidrs

# --- backup_preexisting / restore_preexisting ----------------------------
CFG="${WORK}/etc/buildkitd.toml"
mkdir -p "$(dirname "${CFG}")"
printf 'ORIGINAL OPERATOR CONFIG\n' > "${CFG}"

# Not owned + file present => a backup is taken.
ok_true backup_preexisting nerdctl-buildkit "${CFG}"
[[ -f "${SANDBOX_MARKER_DIR}/nerdctl-buildkit.orig" ]] || fail "no .orig stashed"
grep -q 'ORIGINAL OPERATOR CONFIG' "${SANDBOX_MARKER_DIR}/nerdctl-buildkit.orig" \
  || fail ".orig content wrong"

# Simulate setup overwriting the operator's config with ours.
printf 'SANDBOX CONFIG\n' > "${CFG}"

# Re-running setup must NOT re-backup once we own it, or the real original is
# lost. Emulate "we now own it" via the full marker and confirm the guard holds.
mark_installed nerdctl-buildkit
ok_false backup_preexisting nerdctl-buildkit "${CFG}"
grep -q 'ORIGINAL OPERATOR CONFIG' "${SANDBOX_MARKER_DIR}/nerdctl-buildkit.orig" \
  || fail "stashed original was clobbered by a re-backup"
unmark_installed nerdctl-buildkit

# Restore puts the operator's file back and drops the backup.
ok_true restore_preexisting nerdctl-buildkit "${CFG}"
grep -q 'ORIGINAL OPERATOR CONFIG' "${CFG}" || fail "restore did not bring back original"
[[ ! -e "${SANDBOX_MARKER_DIR}/nerdctl-buildkit.orig" ]] || fail ".orig not cleaned up"

# Restore with no backup => 1, caller falls back to deleting its own file.
ok_false restore_preexisting nerdctl-buildkit "${CFG}"

# Backup of an absent path => 1 (nothing to protect).
ok_false backup_preexisting runsc-cfg "${WORK}/does-not-exist"

# --- k3s unit signature --------------------------------------------------
ok_false k3s_unit_looks_like_ours                       # unit file absent
printf 'ExecStart=/usr/local/bin/k3s server --node-name x\n' > "${SANDBOX_K3S_SERVICE_UNIT}"
ok_false k3s_unit_looks_like_ours                       # a foreign k3s
printf 'ExecStart=... --flannel-backend=none --disable=traefik --service-cidr=10.43.0.0/16\n' \
  > "${SANDBOX_K3S_SERVICE_UNIT}"
ok_true  k3s_unit_looks_like_ours                       # our flag signature

# --- buildkit config signature -------------------------------------------
ok_false buildkit_config_looks_like_ours
printf '[worker.oci]\n  enabled = true\n' > "${SANDBOX_BUILDKIT_CONFIG}"
ok_false buildkit_config_looks_like_ours                # operator's own config
cat > "${SANDBOX_BUILDKIT_CONFIG}" <<'EOF'
[worker.containerd]
  enabled = true
  address = "/run/k3s/containerd/containerd.sock"
  namespace = "k8s.io"
EOF
ok_true buildkit_config_looks_like_ours

# --- gVisor runsc config signature ---------------------------------------
ok_false gvisor_config_looks_like_ours
printf '[runsc_config]\n  net-raw = "true"\n' > "${SANDBOX_RUNSC_CONFIG}"
ok_false gvisor_config_looks_like_ours                  # operator's own runsc.toml
cat > "${SANDBOX_RUNSC_CONFIG}" <<'EOF'
[runsc_config]
  debug = "false"
  debug-log = "/tmp/runsc-%ID%.log"
EOF
ok_true gvisor_config_looks_like_ours

echo "All install-marker tests passed."
