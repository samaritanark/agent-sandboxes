#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-probe.sh — Inside-out sandbox boundary validation via sandbox-probe
#
# Most of tests/ is white-box: it checks that we *author* the controls correctly
# (policy YAML, RuntimeClass present, masking configured). This test is the
# black-box complement — it runs ControlPlane's sandbox-probe
# (https://github.com/controlplaneio/sandbox-probe, Apache-2.0) FROM INSIDE a
# session pod and measures what the agent can actually read, reach, and see.
#
# IMPORTANT — the pod under test is the REAL pod. Earlier revisions of this test
# launched a hand-written, volume-less fixture via `kubectl run --overrides`,
# which meant the filesystem/credential assertions ran against a pod that
# mounted nothing and passed trivially. They never exercised the production
# volume set (agent-home hostPath, repo hostPaths, the overlay-empty/.kube
# masks, gitconfig) — which is exactly where the credential and masking risk
# lives. This test now builds its probe pod with build_pod_manifest (lib/
# manifest.sh), the SAME generator bin/sandbox uses, with the same argument
# shape (see bin/sandbox cmd_run). So the boundary measured here is the boundary
# the platform actually ships.
#
# To stay hermetic and to plant tripwires, the manifest is built with HOME
# pointed at a staged fake-home (FAKE_HOME): every host path build_pod_manifest
# derives from $HOME — the agent-home hostPath (resolve_agent_home ->
# host_agent_home -> $HOME/.sandbox/agent-home/<agent>), the read-only
# ~/.gitconfig, and the $HOME/.sandbox/overlay-empty mask file — then resolves
# under a directory we control and seed with known-secret content. On Linux the
# CLI and the k3s node share one filesystem (lib/platform.sh), so those staged
# host paths are mountable by the node exactly as the operator's real ones are.
#
# Methodology (the probe's own thesis): run the probe unconfined on the host to
# get a baseline, run the same binary inside the sandbox, and treat the diff as
# the measured boundary. We then assert the boundary holds where it must:
#   - the agent's OWN config (agent-home) is present and readable — that is by
#     design, not a leak (the agent authenticates from it); and
#   - NO credential outside that legitimate set is readable (no operator ~/.ssh,
#     ~/.aws, host kubeconfig, etc. leaked in);
#   - the Docker daemon socket is not reachable;
#   - socket namespace is isolated (≪ host sockets visible);
#   - PID namespace is isolated (≪ host processes visible);
#   - (Tier 2) the file-masking machinery actually masks: the secrets staged in
#     the mounted repo (.env, .npmrc, kubeconfig, *-openrc.sh, .kube/, …) read
#     EMPTY inside the pod, a normal source file survives, and ~/.gitconfig is
#     read-only. This is the runtime control protecting mounted repos; the old
#     volume-less fixture could not touch it.
# The full host-vs-sandbox finding diff is written out for human review.
#
# Probe-coverage caveats found empirically on a live gVisor pod (they shape
# which checks lean on the probe vs. direct exec):
#   - sensitive_readable_paths is a FIXED list of well-known paths (/etc/passwd,
#     /proc/self/*, ~/.npmrc, …), not a home-dir walk — it never surfaces the
#     agent's mounted .credentials.json. So the "real volume set is in effect"
#     proof and the credential boundary are verified by direct `kubectl exec`,
#     and the probe's credential scan is kept only as a secondary regression net
#     over standard credential locations.
#   - mounted_volumes_detections returns [] under gVisor — so we do NOT assert on
#     it; the masking/volume boundary is measured by exec instead.
#
# NOT asserted here: egress filtering. At this probe commit, external_host_*
# findings come from DNS resolution alone (no TCP connect), so the probe can't
# measure our Cilium L3/L4 enforcement — test-tier2-network.sh covers egress.
# gVisor runtime detection is emitted as INFO only (probe heuristic we don't
# control). The network taskset is skipped entirely: its UDP scan OOM-kills the
# pod under the 6Gi LimitRange.
#
# This is a LIVE test: it needs a running sandbox k3s cluster with the agent
# image loaded (`sandbox setup`), jq, and either a prebuilt probe binary
# (SANDBOX_PROBE_BIN) or `go` to build one. It is NOT part of `task test`
# (cluster-free only); run it manually like the other live tests. It targets a
# Linux single-node cluster (the staged-host-path technique above assumes the
# CLI and node share a filesystem; on macOS the pod mounts VM-local copies).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

TEST_NAME="test-probe"
SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Production manifest generator + everything it depends on. Sourced in the same
# dependency order bin/sandbox uses; SANDBOX_NAMESPACE/SANDBOX_SERVICE_ACCOUNT
# are set by bin/sandbox (not a lib), so we set them here to match.
SANDBOX_NAMESPACE="${NAMESPACE}"
SANDBOX_SERVICE_ACCOUNT="sandbox-agent"
# shellcheck source=../lib/platform.sh
source "${SANDBOX_ROOT}/lib/platform.sh"
# shellcheck source=../lib/resources.sh
source "${SANDBOX_ROOT}/lib/resources.sh"
# shellcheck source=../lib/filesystem.sh
source "${SANDBOX_ROOT}/lib/filesystem.sh"
# shellcheck source=../lib/manifest.sh
source "${SANDBOX_ROOT}/lib/manifest.sh"

# The agent whose real pod shape we measure. claude mounts agent-home at
# /home/agent/.claude and persists OAuth/.credentials.json there by design.
AGENT="${SANDBOX_PROBE_AGENT:-claude}"
AGENT_CONFIG_MOUNT="/home/agent/.${AGENT}"   # mirrors build_pod_manifest's case

# --- sandbox-probe source pinning ---------------------------------------------
# Mirror the repo's action-pinning discipline (commits da06578/3281b9f): pin to
# an immutable commit SHA, never a moving branch. The default below is the
# commit this test was reviewed and live-validated against (2026-06-29, then
# the tip of controlplaneio/sandbox-probe main). Bump it deliberately after
# re-reviewing upstream, never to a moving ref. Override via SANDBOX_PROBE_REF.
PROBE_REPO="${SANDBOX_PROBE_REPO:-https://github.com/controlplaneio/sandbox-probe}"
PROBE_REF="${SANDBOX_PROBE_REF:-684d09675264d0d42490a86f5f585e33ea2dea6e}"

# Task selection. We deliberately DO NOT run baseline_network_task:
#   - its UDP port scan OOM-kills the pod under the namespace LimitRange (6Gi
#     ceiling) when run on gVisor's netstack, and
#   - its external_host_connectivity finding is derived from DNS resolution
#     alone (no actual TCP connect at this commit), so it does not measure our
#     Cilium egress filtering. Real egress is covered by test-tier2-network.sh.
# The 'ps' taskset gives process-visibility findings (pid-namespace isolation).
PROBE_TASKSETS="ps"
PROBE_TASKS="baseline_path_task,baseline_socket_task,baseline_sandbox_task,baseline_mount_task"

# Scratch + retrieved-report locations. Probe binary/reports live under TMPDIR;
# staged HOST PATHS the pod mounts live under $HOME/.sandbox (same place the
# real hostPaths live, proven mountable by the gVisor node) so the technique
# matches production exactly.
SCRATCH="${TMPDIR:-/tmp}/sandbox-probe-test-$$"
STAGE_BASE="${HOME}/.sandbox/probe-stage-$$"
FAKE_HOME="${STAGE_BASE}/home"        # $HOME used only when building the manifest
SECRET_REPO="${STAGE_BASE}/repo"      # tier 2 workspace, seeded with secrets
PROBE_BIN=""          # resolved by resolve_probe_bin()
HOST_REPORT=""        # host baseline JSON
declare -a TRACKED_PODS=()
declare -a TRACKED_POLICIES=()

cleanup() {
  local pod policy
  for pod in "${TRACKED_PODS[@]:-}"; do
    [[ -n "${pod}" ]] && kubectl delete pod -n "${NAMESPACE}" "${pod}" \
      --ignore-not-found=true --wait=false &>/dev/null || true
  done
  for policy in "${TRACKED_POLICIES[@]:-}"; do
    [[ -n "${policy}" ]] && kubectl delete ciliumnetworkpolicy -n "${NAMESPACE}" \
      "${policy}" --ignore-not-found=true &>/dev/null || true
  done
  rm -rf "${SCRATCH}" "${STAGE_BASE}" 2>/dev/null || true
}
trap cleanup EXIT

###############################################################################
# Preflight: cluster reachable, jq present, probe binary resolvable, host
# fixtures staged
###############################################################################
preflight() {
  command -v jq &>/dev/null || skip "jq not found — required to parse probe reports"

  kubectl get namespace "${NAMESPACE}" &>/dev/null \
    || skip "sandbox cluster/namespace unreachable — run 'sandbox setup' first"
  kubectl get runtimeclass gvisor &>/dev/null \
    || skip "RuntimeClass 'gvisor' not found — run 'sandbox setup' first"
  kubectl get serviceaccount -n "${NAMESPACE}" "${SANDBOX_SERVICE_ACCOUNT}" &>/dev/null \
    || skip "ServiceAccount '${SANDBOX_SERVICE_ACCOUNT}' not found — run 'sandbox setup' first"

  mkdir -p "${SCRATCH}"
  resolve_probe_bin
  stage_host_fixtures
}

# stage_host_fixtures — build the fake $HOME + secret repo the manifest mounts.
# Every file here is a tripwire: known secret content we then assert is either
# legitimately readable (the agent's own config) or masked to empty (repo
# secrets). World-readable so the uid-1000 probe can read what it's allowed to.
stage_host_fixtures() {
  # Fake operator home: agent-home (with the agent's own credentials), the
  # read-only gitconfig, and the empty-file overlay used to mask repo secrets.
  local agent_home="${FAKE_HOME}/.sandbox/agent-home/${AGENT}"
  mkdir -p "${agent_home}"
  printf '{"oauth":"AGENT-OWN-CREDENTIAL-legitimately-present"}\n' \
    > "${agent_home}/.credentials.json"
  printf '[user]\n\tname = Operator\n\temail = op@example.com\n' \
    > "${FAKE_HOME}/.gitconfig"
  mkdir -p "${FAKE_HOME}/.sandbox"
  : > "${FAKE_HOME}/.sandbox/overlay-empty"   # the shared empty mask file

  # Secret repo for the Tier 2 masking tripwire. Seed every masked file path
  # (kept in sync with lib/filesystem.sh) plus an openrc script and a .kube dir,
  # each with content we must NOT be able to read inside the pod, and one normal
  # source file we MUST still be able to read.
  mkdir -p "${SECRET_REPO}/${MASKED_DIR_PATH}"
  local f
  for f in "${MASKED_FILE_PATHS[@]}"; do
    printf 'SECRET-%s-must-be-masked\n' "${f}" > "${SECRET_REPO}/${f}"
  done
  printf 'SECRET-openrc-must-be-masked\n' > "${SECRET_REPO}/cloud-openrc.sh"
  printf 'SECRET-kubeconfig-must-be-masked\n' > "${SECRET_REPO}/${MASKED_DIR_PATH}/config"
  printf '# normal source file — must survive masking\n' > "${SECRET_REPO}/README.md"

  chmod -R a+rX "${STAGE_BASE}"
}

# resolve_probe_bin — use a prebuilt binary if provided, else build from pinned
# source if `go` is available, else skip the whole test.
resolve_probe_bin() {
  if [[ -n "${SANDBOX_PROBE_BIN:-}" ]]; then
    [[ -x "${SANDBOX_PROBE_BIN}" ]] \
      || fail "SANDBOX_PROBE_BIN=${SANDBOX_PROBE_BIN} is not an executable file"
    PROBE_BIN="${SANDBOX_PROBE_BIN}"
    info "Using prebuilt probe: ${PROBE_BIN}"
    return
  fi

  command -v go &>/dev/null \
    || skip "no SANDBOX_PROBE_BIN and 'go' not installed — cannot obtain probe"
  command -v git &>/dev/null \
    || skip "no SANDBOX_PROBE_BIN and 'git' not installed — cannot fetch probe"

  [[ "${PROBE_REF}" == "main" ]] && warn \
    "SANDBOX_PROBE_REF unset — building from moving branch 'main'. Pin a SHA for CI."

  info "Cloning sandbox-probe @ ${PROBE_REF} ..."
  local src="${SCRATCH}/src"
  git clone --quiet "${PROBE_REPO}" "${src}" \
    || skip "could not clone ${PROBE_REPO} (no network?)"
  git -C "${src}" checkout --quiet "${PROBE_REF}" \
    || fail "could not check out ref '${PROBE_REF}'"

  info "Building probe (linux/amd64 static) ..."
  PROBE_BIN="${SCRATCH}/sandbox-probe"
  # The entrypoint is the module root (Makefile: `go build -o bin/sandbox-probe .`).
  # Static, matching the agent image arch. k3s nodes here are linux/amd64.
  ( cd "${src}" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -o "${PROBE_BIN}" . ) &>"${SCRATCH}/build.log" \
    || { cat "${SCRATCH}/build.log" >&2; fail "probe build failed"; }
  [[ -x "${PROBE_BIN}" ]] || fail "probe build produced no binary"
  chmod +x "${PROBE_BIN}"
}

###############################################################################
# JSON helpers — tolerant of snake_case/camelCase and scalar-or-array values
###############################################################################
finding_values() {  # <report.json> <finding_type> -> one value per line
  jq -r --arg t "$2" '
    [ .findings[]? | select((.finding_type // .findingType // .type) == $t) | .value ]
    | map(if type == "array" then .[] else . end)
    | .[]? // empty
  ' "$1" 2>/dev/null
}

# Number of FINDINGS of a type (one per row) — correct for object-valued
# findings like process_detection, where each process is its own finding.
finding_count() {   # <report.json> <finding_type> -> integer
  jq -r --arg t "$2" '[ .findings[]? | select((.finding_type // .findingType // .type) == $t) ] | length' \
    "$1" 2>/dev/null || echo 0
}

# Number of VALUES across array-valued findings of a type (e.g. one per socket
# path). Values are strings here, so a line count is accurate.
value_count() {     # <report.json> <finding_type> -> integer
  finding_values "$1" "$2" | grep -c . || true
}

total_findings() {  # <report.json> -> integer
  jq -r '(.findings // []) | length' "$1" 2>/dev/null || echo 0
}

###############################################################################
# Run the probe inside a REAL session pod and retrieve its report
###############################################################################
# build_session_pod_yaml <session_id> <tier> [repo ...] -> pod YAML on stdout
# Builds the production manifest with HOME staged so all $HOME-derived hostPaths
# resolve under our seeded fixtures. Argument shape matches bin/sandbox cmd_run.
build_session_pod_yaml() {
  local session_id="$1" tier="$2"
  shift 2
  local image="docker.io/library/sandbox:${AGENT}"
  # HOME scoped to this single call: resolve_agent_home, the gitconfig path, and
  # the overlay-empty path all read $HOME. No other side effects (build_pod_
  # manifest only emits YAML; it runs no kubectl).
  HOME="${FAKE_HOME}" build_pod_manifest \
    "${session_id}" \
    "${AGENT}" \
    "${tier}" \
    "${image}" \
    "" \
    "probe-test" \
    "" \
    "sandbox-${session_id}" \
    "" \
    "" \
    "" \
    "$@"
}

# launch_probe_pod <session_id> <tier> [repo ...]
# Applies the real manifest and waits for Running. Leaves the pod alive so the
# caller can exec into it (probe scan, masking checks); cleanup() reaps it.
launch_probe_pod() {
  local session_id="$1" tier="$2"
  shift 2
  local pod_name="sandbox-${session_id}"
  TRACKED_PODS+=("${pod_name}")

  build_session_pod_yaml "${session_id}" "${tier}" "$@" \
    | kubectl apply -f - &>/dev/null \
    || fail "failed to apply session pod manifest for ${pod_name}"

  # Wait for Running. Surface the common "image not loaded" failure as a skip
  # (the agent image must be built/imported by `sandbox setup`), not an opaque
  # timeout.
  local retries=45 i=0 phase reason
  while :; do
    phase="$(kubectl get pod -n "${NAMESPACE}" "${pod_name}" \
      -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    [[ "${phase}" == "Running" ]] && break
    reason="$(kubectl get pod -n "${NAMESPACE}" "${pod_name}" \
      -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || true)"
    case "${reason}" in
      ErrImageNeverPull|ImagePullBackOff|ErrImagePull)
        skip "agent image 'docker.io/library/sandbox:${AGENT}' not present on the node — build/import it ('sandbox setup') before running this test" ;;
    esac
    (( i++ )) || true
    [[ "${i}" -ge "${retries}" ]] \
      && fail "probe pod ${pod_name} never reached Running (phase=${phase:-unknown}, waiting=${reason:-none})"
    sleep 2
  done
}

# run_probe_scan <pod_name> <out_report_path> — cp the probe in and scan.
run_probe_scan() {
  local pod_name="$1" out_report="$2"
  kubectl cp "${PROBE_BIN}" "${NAMESPACE}/${pod_name}:/tmp/sandbox-probe" &>/dev/null \
    || fail "kubectl cp of probe into ${pod_name} failed"
  kubectl exec -n "${NAMESPACE}" "${pod_name}" -- chmod +x /tmp/sandbox-probe &>/dev/null || true
  kubectl exec -n "${NAMESPACE}" "${pod_name}" -- \
    /tmp/sandbox-probe scan \
      --tasksets "${PROBE_TASKSETS}" --tasks "${PROBE_TASKS}" \
      --output_path /tmp/probe.json &>/dev/null \
    || fail "probe scan failed inside ${pod_name}"
  kubectl exec -n "${NAMESPACE}" "${pod_name}" -- cat /tmp/probe.json > "${out_report}" \
    || fail "could not retrieve probe report from ${pod_name}"
}

delete_probe_pod() {  # <pod_name> — free the quota before the next tier
  kubectl delete pod -n "${NAMESPACE}" "$1" \
    --ignore-not-found=true --wait=false &>/dev/null || true
}

# Credential-file patterns that must NEVER be readable inside a session pod.
# (Baseline OS files like /etc/passwd or /proc/self/cgroup legitimately appear
# in sensitive_readable_paths inside any container — we only care about secrets
# that would let the agent impersonate the operator or reach infra.)
CRED_PATTERN='/\.ssh/|id_rsa|id_ed25519|/\.kube/|/\.aws/|/\.docker/|/\.gnupg|/\.config/gh|credentials|\.pem$|kubeconfig'

# The agent's OWN config is mounted by design and IS legitimately readable — the
# agent authenticates from it. So a credential-looking path UNDER the agent
# config mount, the read-only gitconfig, or (Tier 3) the agent's mounted .kube
# is expected, not a leak. CRED_PATTERN flags secrets; this carves out the ones
# the platform deliberately provides. Anything matching CRED_PATTERN but NOT
# this allowlist is an operator/infra credential that should never have leaked.
LEGIT_READABLE_CRED="^${AGENT_CONFIG_MOUNT}(/|\$)|^/home/agent/\\.gitconfig\$|^/home/agent/\\.kube(/|\$)"

# Max Unix sockets the probe may see inside a session pod. Observed: 0 (no host
# /run is mounted). A small ceiling guards against host-socket leakage; the host
# itself typically shows 100+ (docker.sock, cilium, dbus, systemd, …).
SOCK_CEILING="${SANDBOX_PROBE_SOCK_CEILING:-5}"

# Shared boundary assertions that must hold for every tier.
# <report> <label> <pod_name>
assert_core_boundary() {
  local report="$1" label="$2" pod_name="$3"

  # Proof the REAL volume set is in effect — done by direct exec, NOT the probe.
  # Empirically (verified on this cluster), the probe's sensitive_readable_paths
  # is a fixed list of well-known paths (/etc/passwd, /proc/self/*, ~/.npmrc, …),
  # not a home-dir walk: it never surfaces the agent's mounted .credentials.json.
  # So we confirm the agent-home hostPath mounted by reading the credential
  # directly. This is also the guard against the old failure mode — a volume-
  # less pod that passed every boundary check trivially: if the real mount isn't
  # here, FAIL, because nothing below would be measuring the production pod.
  if kubectl exec -n "${NAMESPACE}" "${pod_name}" -- \
      cat "${AGENT_CONFIG_MOUNT}/.credentials.json" 2>/dev/null | grep -q .; then
    pass "${label}: agent's own config mount present and readable — the real production volume set is in effect"
  else
    fail "${label}: agent-home mount (${AGENT_CONFIG_MOUNT}) missing/unreadable — boundary checks would be measuring an empty pod, not the real one"
  fi

  # gVisor detection is a probe heuristic we don't control — informational only.
  # The subset checks below are the hard regression guard.
  local sb; sb="$(finding_values "${report}" sandbox_detection)"
  if echo "${sb}" | grep -qi 'gvisor\|runsc'; then
    pass "${label}: probe identified the runtime as gVisor (sandbox_detection=${sb})"
  else
    warn "${label}: probe did not name gVisor (sandbox_detection='${sb}') — likely a probe heuristic gap, not a regression"
  fi

  # Credentials (probe scan — SECONDARY net). The probe sweeps a fixed set of
  # well-known credential locations and reports the readable ones; it is NOT a
  # full filesystem walk (see note above). So this catches a regression that
  # exposes a STANDARD operator/infra credential path (a mounted ~/.aws, ~/.ssh,
  # host kubeconfig, …) but is not the primary control — the mount-set proof
  # above and the Tier-2 masking checks are. We assert the precise property:
  # nothing credential-like is readable OUTSIDE the platform-provided allowlist
  # (the agent's own config/gitconfig are mounted by design and are expected).
  local readable leaked
  readable="$(finding_values "${report}" sensitive_readable_paths)"
  leaked="$(echo "${readable}" | grep -Ei "${CRED_PATTERN}" | grep -Ev "${LEGIT_READABLE_CRED}" || true)"
  [[ -z "${leaked}" ]] \
    && pass "${label}: no standard operator/infra credential paths readable (probe scan)" \
    || fail "${label}: credential file(s) readable beyond the agent's own config: ${leaked//$'\n'/, }"

  # Socket isolation: host-side Unix sockets (docker.sock, cilium, dbus, …) must
  # not be visible. The Docker daemon socket is the headline escape vector.
  local host_socks pod_socks
  host_socks="$(value_count "${HOST_REPORT}" unix_socket_detection)"
  pod_socks="$(value_count "${report}" unix_socket_detection)"
  if finding_values "${report}" unix_socket_detection | grep -q 'docker\.sock'; then
    fail "${label}: Docker daemon socket (docker.sock) reachable inside the sandbox"
  fi
  if [[ "${pod_socks}" -le "${SOCK_CEILING}" && "${pod_socks}" -lt "${host_socks}" ]]; then
    pass "${label}: socket namespace isolated — ${pod_socks} Unix socket(s) visible inside vs ${host_socks} on host"
  else
    fail "${label}: socket isolation weak — ${pod_socks} socket(s) visible inside (host: ${host_socks}, ceiling: ${SOCK_CEILING})"
  fi

  # PID-namespace isolation: the probe must see only a handful of processes
  # (its own), never the host's process table. Counts fluctuate, so we assert
  # the pod sees DRAMATICALLY fewer than the host (< half) rather than a tight
  # absolute number — robust on both quiet and busy hosts.
  local host_procs pod_procs
  host_procs="$(finding_count "${HOST_REPORT}" process_detection)"
  pod_procs="$(finding_count "${report}" process_detection)"
  if [[ "${pod_procs}" -lt 1 ]]; then
    fail "${label}: probe saw 0 processes — scan likely incomplete"
  elif (( pod_procs * 2 < host_procs )); then
    pass "${label}: PID namespace isolated — ${pod_procs} processes visible inside vs ${host_procs} on host"
  else
    fail "${label}: process table not isolated — ${pod_procs} processes visible inside (host: ${host_procs})"
  fi

  # The host-vs-sandbox finding diff IS the measured boundary — too context-
  # dependent (home paths, /proc) to assert by strict subset, so we emit it for
  # human review in each tier's caller instead.
}

# probe_file_state <pod_name> <path> — classify a path INSIDE the pod as
# MISSING (not present at all), EMPTY (present and zero-length), or NONEMPTY
# (present with content). Prints EXECFAIL if the exec could not run. This is
# what lets the masking asserts tell "masked to empty" apart from "never
# there": a bare `cat` whose error is swallowed reads empty in BOTH cases, so
# a mount/staging regression that dropped the file would pass the mask check
# for the wrong reason. See the loop below.
probe_file_state() {
  kubectl exec -n "${NAMESPACE}" "$1" -- sh -c '
    if [ ! -e "$1" ]; then echo MISSING
    elif [ -s "$1" ]; then echo NONEMPTY
    else echo EMPTY; fi' _ "$2" 2>/dev/null || echo EXECFAIL
}

# assert_repo_masking <pod_name> <label> — the runtime control the old fixture
# never exercised. The mounted repo's secrets must read EMPTY inside the pod
# (overlay-empty-file / .kube emptyDir), a normal file must survive, and the
# operator's ~/.gitconfig mount must be read-only. Uses direct exec, so it does
# not depend on any probe heuristic.
assert_repo_masking() {
  local pod_name="$1" label="$2" f leaked content

  for f in "${MASKED_FILE_PATHS[@]}"; do
    # All MASKED_FILE_PATHS were staged, so each MUST exist in the pod; an empty
    # read only proves masking if the file is actually present. MISSING means
    # the mount/overlay never placed it — a regression, not a successful mask —
    # so we fail loudly instead of inferring a mask from an absent file.
    case "$(probe_file_state "${pod_name}" "/workspace/${f}")" in
      EMPTY)    pass "${label}: masked file /workspace/${f} exists and reads empty (host secret hidden)" ;;
      NONEMPTY) leaked="$(kubectl exec -n "${NAMESPACE}" "${pod_name}" -- cat "/workspace/${f}" 2>/dev/null || true)"
                fail "${label}: masked file /workspace/${f} leaked host content: ${leaked}" ;;
      MISSING)  fail "${label}: masked file /workspace/${f} is absent — mount/staging regression, mask NOT verified" ;;
      *)        fail "${label}: could not read /workspace/${f} inside the pod" ;;
    esac
  done

  # openrc script (matched by pattern, not a fixed name).
  case "$(probe_file_state "${pod_name}" /workspace/cloud-openrc.sh)" in
    EMPTY)    pass "${label}: masked /workspace/cloud-openrc.sh exists and reads empty" ;;
    NONEMPTY) leaked="$(kubectl exec -n "${NAMESPACE}" "${pod_name}" -- cat /workspace/cloud-openrc.sh 2>/dev/null || true)"
              fail "${label}: openrc script leaked host content: ${leaked}" ;;
    MISSING)  fail "${label}: /workspace/cloud-openrc.sh is absent — mount/staging regression, mask NOT verified" ;;
    *)        fail "${label}: could not read /workspace/cloud-openrc.sh inside the pod" ;;
  esac

  # .kube directory must be an empty overlay, not the host's secret config — and
  # it must actually EXIST as a directory. A missing dir also lists zero
  # entries, which the old `wc -l == 0` mistook for a successful mask.
  local kube_state
  kube_state="$(kubectl exec -n "${NAMESPACE}" "${pod_name}" -- sh -c '
    if [ ! -d "$1" ]; then echo MISSING
    elif [ -n "$(ls -A "$1" 2>/dev/null)" ]; then echo NONEMPTY
    else echo EMPTY; fi' _ "/workspace/${MASKED_DIR_PATH}" 2>/dev/null || echo EXECFAIL)"
  case "${kube_state}" in
    EMPTY)    pass "${label}: /workspace/${MASKED_DIR_PATH} exists and is an empty overlay (host kube config hidden)" ;;
    NONEMPTY) leaked="$(kubectl exec -n "${NAMESPACE}" "${pod_name}" -- ls -A "/workspace/${MASKED_DIR_PATH}" 2>/dev/null | tr '\n' ' ' || true)"
              fail "${label}: /workspace/${MASKED_DIR_PATH} exposed host entr(y/ies): ${leaked}" ;;
    MISSING)  fail "${label}: /workspace/${MASKED_DIR_PATH} is absent — mount/staging regression, empty overlay NOT verified" ;;
    *)        fail "${label}: could not inspect /workspace/${MASKED_DIR_PATH} inside the pod" ;;
  esac

  # A normal source file must NOT be masked.
  content="$(kubectl exec -n "${NAMESPACE}" "${pod_name}" -- \
    cat /workspace/README.md 2>/dev/null || true)"
  echo "${content}" | grep -q 'normal source file' \
    && pass "${label}: normal repo file /workspace/README.md is intact (masking is surgical)" \
    || fail "${label}: normal repo file /workspace/README.md was unexpectedly empty/altered"

  # ~/.gitconfig is mounted read-only — a write must be rejected.
  if kubectl exec -n "${NAMESPACE}" "${pod_name}" -- \
      sh -c 'echo x >> /home/agent/.gitconfig' &>/dev/null; then
    fail "${label}: /home/agent/.gitconfig is writable inside the pod (should be read-only)"
  else
    pass "${label}: /home/agent/.gitconfig is read-only inside the pod"
  fi
}

###############################################################################
# Policies (inline, matching the live network tests)
###############################################################################
apply_tier1_policy() {  # DNS only — default-deny everything else
  local session_id="$1"
  TRACKED_POLICIES+=("policy-${session_id}")
  cat <<EOF | kubectl apply -f - &>/dev/null
---
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: "policy-${session_id}"
  namespace: "${NAMESPACE}"
spec:
  endpointSelector:
    matchLabels:
      sandbox-session: "${session_id}"
  egress:
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
  ingress: []
EOF
}

apply_tier2_policy() {  # DNS + a small project egress allowlist (mirrors test-tier2-network.sh)
  local session_id="$1"
  TRACKED_POLICIES+=("policy-${session_id}")
  cat <<EOF | kubectl apply -f - &>/dev/null
---
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: "policy-${session_id}"
  namespace: "${NAMESPACE}"
spec:
  endpointSelector:
    matchLabels:
      sandbox-session: "${session_id}"
  egress:
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: kube-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: UDP
            - port: "53"
              protocol: TCP
          rules:
            dns:
              - matchName: "api.anthropic.com"
              - matchName: "github.com"
              - matchName: "pypi.org"
              - matchName: "registry.npmjs.org"
    - toFQDNs:
        - matchName: "api.anthropic.com"
        - matchName: "github.com"
        - matchName: "pypi.org"
        - matchName: "registry.npmjs.org"
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
  ingress: []
EOF
}

###############################################################################
# Tests
###############################################################################
test_host_baseline() {
  info "Running probe on the host (unconfined baseline)..."
  HOST_REPORT="${SCRATCH}/host.json"
  # Same task selection as the in-pod runs, so the diff is apples-to-apples.
  "${PROBE_BIN}" scan \
    --tasksets "${PROBE_TASKSETS}" --tasks "${PROBE_TASKS}" \
    --output_path "${HOST_REPORT}" &>/dev/null \
    || fail "host probe scan failed"

  local n; n="$(total_findings "${HOST_REPORT}")"
  [[ "${n}" -gt 0 ]] \
    || skip "host baseline produced 0 parseable findings — probe schema may have changed"
  pass "host baseline collected (${n} findings)"
}

test_tier1_boundary() {
  echo ""
  info "--- Tier 1 (ephemeral, agent-only egress) ---"
  local session_id="probe-t1-$$-$(head -c 2 /dev/urandom | xxd -p | head -c 4)"
  local pod_name="sandbox-${session_id}"
  apply_tier1_policy "${session_id}"
  launch_probe_pod "${session_id}" 1     # Tier 1: no repos

  local report="${SCRATCH}/tier1.json"
  run_probe_scan "${pod_name}" "${report}"
  assert_core_boundary "${report}" "tier1" "${pod_name}"

  # NOTE: egress filtering (default-deny) is NOT asserted here — sandbox-probe
  # derives external_host_connectivity from DNS resolution alone, so it cannot
  # measure our Cilium L3/L4 enforcement. test-tier2-network.sh covers egress.

  local diff_file="${SCRATCH}/tier1.diff"
  diff <(jq -S . "${HOST_REPORT}") <(jq -S . "${report}") > "${diff_file}" 2>/dev/null || true
  info "tier1 host-vs-sandbox diff written to ${diff_file}"

  delete_probe_pod "${pod_name}"          # free the quota before Tier 2
}

test_tier2_boundary() {
  echo ""
  info "--- Tier 2 (project egress + mounted repo with masked secrets) ---"
  local session_id="probe-t2-$$-$(head -c 2 /dev/urandom | xxd -p | head -c 4)"
  local pod_name="sandbox-${session_id}"
  apply_tier2_policy "${session_id}"
  launch_probe_pod "${session_id}" 2 "${SECRET_REPO}"

  local report="${SCRATCH}/tier2.json"
  run_probe_scan "${pod_name}" "${report}"

  # Filesystem/runtime/socket boundary is identical to Tier 1 plus a mounted
  # repo — more network reach must NOT have bought more filesystem/socket
  # exposure, and the agent's own creds must still be the only readable secret.
  assert_core_boundary "${report}" "tier2" "${pod_name}"

  # The headline addition: the masking machinery (overlay-empty-file, .kube
  # overlay, read-only gitconfig) actually masks the repo secrets at runtime.
  assert_repo_masking "${pod_name}" "tier2"

  local diff_file="${SCRATCH}/tier2.diff"
  diff <(jq -S . "${HOST_REPORT}") <(jq -S . "${report}") > "${diff_file}" 2>/dev/null || true
  info "tier2 host-vs-sandbox diff written to ${diff_file}"

  delete_probe_pod "${pod_name}"
}

# NOTE: A Tier 3 case (infra credentials present) is a natural extension but
# needs an --infra-token / --infra-kubeconfig fixture; left for follow-up.

main() {
  echo "=== ${TEST_NAME} ==="
  echo ""
  preflight
  test_host_baseline
  test_tier1_boundary
  test_tier2_boundary
  echo ""
  echo "All probe boundary tests passed."
}

main "$@"
