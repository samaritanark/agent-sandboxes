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
# Methodology (the probe's own thesis): run the probe unconfined on the host to
# get a baseline, run the same binary inside the sandbox, and treat the diff as
# the measured boundary. We then assert the boundary holds where it must:
#   - no operator credential files are readable (host home didn't leak in)
#   - the Docker daemon socket is not reachable
#   - socket namespace is isolated (≪ host sockets visible)
#   - PID namespace is isolated (≪ host processes visible)
#   - no operator-home/credential host volume is mounted
# The full host-vs-sandbox finding diff is written out for human review.
#
# NOT asserted here: egress filtering. At this probe commit, external_host_*
# findings come from DNS resolution alone (no TCP connect), so the probe can't
# measure our Cilium L3/L4 enforcement — test-tier2-network.sh covers egress.
# gVisor runtime detection is emitted as INFO only (probe heuristic we don't
# control). The network taskset is skipped entirely: its UDP scan OOM-kills the
# pod under the 6Gi LimitRange.
#
# This is a LIVE test: it needs a running sandbox k3s cluster, jq, and either a
# prebuilt probe binary (SANDBOX_PROBE_BIN) or `go` to build one. It is NOT part
# of `task test` (cluster-free only); run it manually like the other live tests.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

TEST_NAME="test-probe"

# --- sandbox-probe source pinning ---------------------------------------------
# Mirror the repo's action-pinning discipline (commits da06578/3281b9f): pin to
# an immutable commit SHA, never a moving branch. Set SANDBOX_PROBE_REF to the
# reviewed commit before relying on this in CI.
PROBE_REPO="${SANDBOX_PROBE_REPO:-https://github.com/controlplaneio/sandbox-probe}"
PROBE_REF="${SANDBOX_PROBE_REF:-main}"   # TODO: pin to a reviewed commit SHA

# Task selection. We deliberately DO NOT run baseline_network_task:
#   - its UDP port scan OOM-kills the pod under the namespace LimitRange (6Gi
#     ceiling) when run on gVisor's netstack, and
#   - its external_host_connectivity finding is derived from DNS resolution
#     alone (no actual TCP connect at this commit), so it does not measure our
#     Cilium egress filtering. Real egress is covered by test-tier2-network.sh.
# The 'ps' taskset gives process-visibility findings (pid-namespace isolation).
PROBE_TASKSETS="ps"
PROBE_TASKS="baseline_path_task,baseline_socket_task,baseline_sandbox_task,baseline_mount_task"

# Scratch + retrieved-report locations.
SCRATCH="${TMPDIR:-/tmp}/sandbox-probe-test-$$"
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
  rm -rf "${SCRATCH}" 2>/dev/null || true
}
trap cleanup EXIT

###############################################################################
# Preflight: cluster reachable, jq present, probe binary resolvable
###############################################################################
preflight() {
  command -v jq &>/dev/null || skip "jq not found — required to parse probe reports"

  kubectl get namespace "${NAMESPACE}" &>/dev/null \
    || skip "sandbox cluster/namespace unreachable — run 'sandbox setup' first"
  kubectl get runtimeclass gvisor &>/dev/null \
    || skip "RuntimeClass 'gvisor' not found — run 'sandbox setup' first"

  mkdir -p "${SCRATCH}"
  resolve_probe_bin
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
# Run the probe inside a session pod and retrieve its report
###############################################################################
# run_probe_in_pod <session_id> <labels_csv> <out_report_path>
# Caller must have applied the CiliumNetworkPolicy for <session_id> first.
run_probe_in_pod() {
  local session_id="$1" labels="$2" out_report="$3"
  local pod_name="sandbox-${session_id}"
  TRACKED_PODS+=("${pod_name}")

  # A long-lived pod we can cp into and exec — the probe scans locally, so its
  # findings are unaffected by the (API-server-routed) cp/exec traffic.
  kubectl run "${pod_name}" \
    --namespace "${NAMESPACE}" \
    --image "sandbox:base" \
    --image-pull-policy IfNotPresent \
    --restart Never \
    --labels "${labels}" \
    --overrides '{
      "spec": {
        "runtimeClassName": "gvisor",
        "serviceAccountName": "sandbox-agent",
        "automountServiceAccountToken": false,
        "securityContext": {"runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000, "runAsNonRoot": true},
        "containers": [{
          "name": "agent",
          "image": "sandbox:base",
          "command": ["sleep", "300"],
          "securityContext": {"allowPrivilegeEscalation": false, "capabilities": {"drop": ["ALL"]}}
        }]
      }
    }' 2>/dev/null

  # Wait for Running (not Succeeded — this pod sleeps).
  local retries=30 i=0
  until [[ "$(kubectl get pod -n "${NAMESPACE}" "${pod_name}" \
        -o jsonpath='{.status.phase}' 2>/dev/null)" == "Running" ]]; do
    (( i++ )) || true
    [[ "${i}" -ge "${retries}" ]] && fail "probe pod ${pod_name} never reached Running"
    sleep 2
  done

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

  kubectl delete pod -n "${NAMESPACE}" "${pod_name}" \
    --ignore-not-found=true --wait=false &>/dev/null || true
}

# Credential-file patterns that must NEVER be readable inside a session pod.
# (Baseline OS files like /etc/passwd or /proc/self/cgroup legitimately appear
# in sensitive_readable_paths inside any container — we only care about secrets
# that would let the agent impersonate the operator or reach infra.)
CRED_PATTERN='/\.ssh/|id_rsa|id_ed25519|/\.kube/|/\.aws/|/\.docker/|/\.gnupg|/\.config/gh|credentials|\.pem$|kubeconfig'

# Max Unix sockets the probe may see inside a session pod. Observed: 0 (no host
# /run is mounted). A small ceiling guards against host-socket leakage; the host
# itself typically shows 100+ (docker.sock, cilium, dbus, systemd, …).
SOCK_CEILING="${SANDBOX_PROBE_SOCK_CEILING:-5}"

# Shared boundary assertions that must hold for every tier.
assert_core_boundary() {
  local report="$1" label="$2"

  # gVisor detection is a probe heuristic we don't control — informational only.
  # The subset checks below are the hard regression guard.
  local sb; sb="$(finding_values "${report}" sandbox_detection)"
  if echo "${sb}" | grep -qi 'gvisor\|runsc'; then
    pass "${label}: probe identified the runtime as gVisor (sandbox_detection=${sb})"
  else
    warn "${label}: probe did not name gVisor (sandbox_detection='${sb}') — likely a probe heuristic gap, not a regression"
  fi

  # Operator credentials must not have leaked into the pod.
  local creds
  creds="$(finding_values "${report}" sensitive_readable_paths | grep -Ei "${CRED_PATTERN}" || true)"
  [[ -z "${creds}" ]] \
    && pass "${label}: no operator credential files readable inside the sandbox" \
    || fail "${label}: credential file(s) readable inside: ${creds//$'\n'/, }"

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

  # No operator-home or credential path should appear as a host volume mount.
  local bad_mounts
  bad_mounts="$(jq -c '.findings[]? | select(.findingType=="mounted_volumes_detections") | .value' \
    "${report}" 2>/dev/null | grep -Ei "${HOME}|${CRED_PATTERN}" || true)"
  [[ -z "${bad_mounts}" ]] \
    && pass "${label}: no operator-home/credential host volumes mounted" \
    || fail "${label}: suspicious host volume mounted: ${bad_mounts}"

  # The host-vs-sandbox finding diff IS the measured boundary — too context-
  # dependent (home paths, /proc) to assert by strict subset, so we emit it for
  # human review in each tier's caller instead.
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
  apply_tier1_policy "${session_id}"

  local report="${SCRATCH}/tier1.json"
  run_probe_in_pod "${session_id}" \
    "sandbox-session=${session_id},sandbox-agent=claude,sandbox-tier=1" \
    "${report}"

  assert_core_boundary "${report}" "tier1"

  # NOTE: egress filtering (default-deny) is NOT asserted here — sandbox-probe
  # derives external_host_connectivity from DNS resolution alone, so it cannot
  # measure our Cilium L3/L4 enforcement. test-tier2-network.sh covers egress
  # with real curl probes.

  # Emit the measured boundary for human review.
  local diff_file="${SCRATCH}/tier1.diff"
  diff <(jq -S . "${HOST_REPORT}") <(jq -S . "${report}") > "${diff_file}" 2>/dev/null || true
  info "tier1 host-vs-sandbox diff written to ${diff_file}"
}

test_tier2_boundary() {
  echo ""
  info "--- Tier 2 (project egress: GitHub, package registries) ---"
  local session_id="probe-t2-$$-$(head -c 2 /dev/urandom | xxd -p | head -c 4)"
  # Reuse the Tier 2 Claude policy from test-tier2-network.sh.
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

  local report="${SCRATCH}/tier2.json"
  run_probe_in_pod "${session_id}" \
    "sandbox-session=${session_id},sandbox-agent=claude,sandbox-tier=2" \
    "${report}"

  # Filesystem/runtime/socket boundary is identical to Tier 1 — only egress
  # widens. So the core assertions must still hold: more network reach must NOT
  # have bought the agent more filesystem or socket exposure.
  assert_core_boundary "${report}" "tier2"

  local diff_file="${SCRATCH}/tier2.diff"
  diff <(jq -S . "${HOST_REPORT}") <(jq -S . "${report}") > "${diff_file}" 2>/dev/null || true
  info "tier2 host-vs-sandbox diff written to ${diff_file}"
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
