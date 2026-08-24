#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-resume.sh — 'sandbox resume' recreate/guide decision (cluster-free).
#
# When a session's pod was torn down, resume either recreates it from
# session.json or guides the operator to relaunch (issue #70). The kubectl apply
# / wait path in recreate_session_pod needs a live cluster and is exercised
# manually. What's testable cluster-free:
#   - _resume_recreate_blocker: which sessions may be auto-recreated vs guided
#   - _resume_guide_command: the reconstructed 'sandbox run' invocation
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-resume"
TEST_DIR="$(mktemp -d /tmp/sandbox-resume-test-XXXXXX)"

fail() { echo "FAIL: $*" >&2; exit 1; }
cleanup() { rm -rf "${TEST_DIR}"; }
trap cleanup EXIT

# Pull in the resume helpers (and the domain/tier libs they call). bin/sandbox is
# source-guarded, so this defines its functions without running main.
# shellcheck disable=SC1090
source "${SANDBOX_ROOT}/bin/sandbox" >/dev/null 2>&1

# Override detect_platform so the macOS branch can be exercised on a Linux host
# (is_macos reads through it). Defaults to linux.
_set_platform() { eval "detect_platform() { echo '$1'; }"; }
_set_platform linux

# Write a synthetic session.json and echo its path.
mk_session() {
  local name="$1" json="$2"
  local p="${TEST_DIR}/${name}.json"
  printf '%s\n' "${json}" > "${p}"
  echo "${p}"
}

contains() {
  local label="$1" haystack="$2" needle="$3"
  if [[ "${haystack}" == *"${needle}"* ]]; then
    pass "${label}"
  else
    fail "${label}: '${needle}' not found in: ${haystack}"
  fi
}

is_empty() {
  local label="$1" val="$2"
  if [[ -z "${val}" ]]; then pass "${label}"; else fail "${label}: expected empty, got '${val}'"; fi
}

test_blocker_allows_simple_sessions() {
  info "Testing recreatable sessions clear the blocker (tier 1/2, no profile, non-opencode)..."
  _set_platform linux
  local sj
  sj="$(mk_session tier1 '{"agent":"claude","tier":1,"profile":"","repos":[]}')"
  is_empty "tier1 claude recreatable" "$(_resume_recreate_blocker "${sj}")"
  sj="$(mk_session tier2 '{"agent":"codex","tier":2,"profile":"","repos":["/x/y"]}')"
  is_empty "tier2 codex recreatable" "$(_resume_recreate_blocker "${sj}")"
}

test_blocker_guides_the_rest() {
  info "Testing sessions needing unpersisted state are guided, not recreated..."
  _set_platform linux
  local sj
  sj="$(mk_session tier3 '{"agent":"claude","tier":3,"profile":"","repos":[]}')"
  contains "tier3 blocked" "$(_resume_recreate_blocker "${sj}")" "tier 3"
  sj="$(mk_session prof '{"agent":"claude","tier":2,"profile":"payments","repos":[]}')"
  contains "profile blocked" "$(_resume_recreate_blocker "${sj}")" "payments"
  sj="$(mk_session oc '{"agent":"opencode","tier":1,"profile":"","repos":[]}')"
  contains "opencode blocked" "$(_resume_recreate_blocker "${sj}")" "opencode"
  # macOS blocks even an otherwise-simple session.
  _set_platform macos
  sj="$(mk_session mac '{"agent":"claude","tier":1,"profile":"","repos":[]}')"
  contains "macOS blocked" "$(_resume_recreate_blocker "${sj}")" "macOS"
  _set_platform linux
}

test_guide_command_reconstructs_run() {
  info "Testing _resume_guide_command reconstructs the launch invocation..."
  _set_platform linux
  local sj cmd
  sj="$(mk_session guide '{"agent":"opencode","tier":2,"profile":"","repos":["/home/moo/app","/home/moo/lib"],"name":"payments-demo/opencode","allowed_domains":["totally-extra.example.com"]}')"
  cmd="$(_resume_guide_command "${sj}")"
  contains "names agent"        "${cmd}" "--agent opencode"
  contains "names tier"         "${cmd}" "--tier 2"
  contains "first repo"         "${cmd}" "--repo /home/moo/app"
  contains "second repo"        "${cmd}" "--repo /home/moo/lib"
  contains "session name"       "${cmd}" "--name 'payments-demo/opencode'"
  contains "extra allow-domain" "${cmd}" "--allow-domain totally-extra.example.com"
}

# recreate_session_pod must re-run the Tier 2 workspace launch gates and, on a
# gate refusal, abort BEFORE touching the cluster — resume must never relaunch a
# workspace a fresh 'sandbox run' would refuse (security review finding, #70).
test_recreate_reruns_gates_before_apply() {
  info "Testing recreate_session_pod re-runs the tier-2 gates and a refusal aborts before apply..."
  _set_platform linux
  local gatelog="${TEST_DIR}/gatelog" applied="${TEST_DIR}/applied"
  : > "${gatelog}"; : > "${applied}"

  SANDBOX_LOGS_DIR="${TEST_DIR}/logs"
  local sdir="${SANDBOX_LOGS_DIR}/ses-gate-test"
  mkdir -p "${sdir}" "${TEST_DIR}/repoA"
  printf '{"agent":"claude","tier":2,"name":"t","user":"u","repos":["%s"],"allowed_domains":[],"kube_api_cidr":"","kube_api_port":""}\n' \
    "${TEST_DIR}/repoA" > "${sdir}/session.json"

  # Stub cluster + build steps so nothing hits a real cluster; kubectl records
  # that an apply happened. resolve_* are pinned so the path is deterministic.
  prepare_agent_home() { :; }
  build_cilium_policy() { echo policy; }
  build_pod_manifest() { echo pod; }
  wait_for_pod() { :; }
  resolve_pod_name() { echo sandbox-x; }
  resolve_vetting_posture() { echo off; }
  resolve_inference_endpoint() { echo ""; }
  kubectl() { echo apply >> "${applied}"; }
  # Gate stubs record invocation; all pass for the first case.
  workspace_prescan()   { echo prescan >> "${gatelog}"; }
  check_masking_paths() { echo masking >> "${gatelog}"; }
  vetting_gate_repos()  { echo vetting >> "${gatelog}"; }
  secret_gate_repos()   { echo secret  >> "${gatelog}"; }

  # Case A — all gates pass: every gate runs, then the apply happens.
  ( recreate_session_pod "ses-gate-test" ) >/dev/null 2>&1 || true
  local ran; ran="$(tr '\n' ',' < "${gatelog}")"
  { grep -q prescan "${gatelog}" && grep -q masking "${gatelog}" \
    && grep -q vetting "${gatelog}" && grep -q secret "${gatelog}"; } \
    && pass "all four workspace gates run on recreate" || fail "missing gate(s): ${ran}"
  [[ -s "${applied}" ]] && pass "apply proceeds once gates pass" || fail "apply did not run when gates passed"

  # Case B — a gate refuses: apply must NOT run. The real gates fail closed via
  # die (exit), so the stub does the same; recreate_session_pod calls it as a
  # bare statement, so the exit aborts before any build/apply.
  : > "${applied}"
  secret_gate_repos() { die "secret gate refused (test)"; }
  ( recreate_session_pod "ses-gate-test" ) >/dev/null 2>&1 || true
  [[ ! -s "${applied}" ]] && pass "a gate refusal aborts before any cluster apply" \
    || fail "apply ran despite a gate refusal — resume would relaunch an ungated workspace"
}

# A pod that never becomes Ready must be torn down, not left orphaned in
# Pending/Running/Error for the operator to clean up by hand. recreate_session_pod
# runs wait_for_pod in a subshell and calls cmd_stop on failure.
test_recreate_tears_down_on_pod_failure() {
  info "Testing a recreated pod that fails to become Ready is torn down..."
  _set_platform linux
  local stoplog="${TEST_DIR}/stoplog"
  : > "${stoplog}"

  SANDBOX_LOGS_DIR="${TEST_DIR}/logs"
  local sdir="${SANDBOX_LOGS_DIR}/ses-fail-test"
  mkdir -p "${sdir}" "${TEST_DIR}/repoB"
  printf '{"agent":"claude","tier":2,"name":"t","user":"u","repos":["%s"],"allowed_domains":[],"kube_api_cidr":"","kube_api_port":""}\n' \
    "${TEST_DIR}/repoB" > "${sdir}/session.json"

  # Stub the build/cluster steps; gates all pass so the path reaches the wait.
  prepare_agent_home() { :; }
  build_cilium_policy() { echo policy; }
  build_pod_manifest() { echo pod; }
  resolve_pod_name() { echo sandbox-x; }
  resolve_vetting_posture() { echo off; }
  resolve_inference_endpoint() { echo ""; }
  # `get pod` returns non-zero so teardown_partial_session sees the pod as gone
  # (the happy path); every other kubectl call is a harmless no-op.
  kubectl() { case "$1" in get) return 1 ;; *) return 0 ;; esac; }
  workspace_prescan()   { :; }
  check_masking_paths() { :; }
  vetting_gate_repos()  { :; }
  secret_gate_repos()   { :; }
  # The pod never becomes Ready: wait_for_pod exits non-zero (as the real one
  # does via exit 1). cmd_stop records that teardown ran.
  wait_for_pod() { return 1; }
  cmd_stop() { echo "stopped $1" >> "${stoplog}"; }

  ( recreate_session_pod "ses-fail-test" ) >/dev/null 2>&1 || true
  grep -q "stopped ses-fail-test" "${stoplog}" \
    && pass "failed pod triggers cmd_stop teardown" \
    || fail "pod-start failure did not tear down the session — pod would be orphaned"
}

# teardown_partial_session must (F1) let cmd_stop's stderr through — the infra-
# token and kubeconfig revocation reminders and the Hubble-export warning all
# live there — while dropping only the routine stdout chatter, and (F2) report a
# non-zero result when the pod is still present afterward so the caller cannot
# tell the operator a partial teardown was clean.
test_teardown_partial_session_integrity() {
  info "Testing teardown_partial_session preserves reminders and flags a lingering pod..."
  SANDBOX_NAMESPACE="sandbox"
  local outf="${TEST_DIR}/tps.out" errf="${TEST_DIR}/tps.err" rc

  # cmd_stop writes routine progress to stdout and a revocation reminder to
  # stderr, exactly as the real one does (echo vs warn).
  cmd_stop() {
    echo "  Pod deleted."
    warn "REMINDER: Revoke infra token used in this session."
  }

  # Case 1: pod gone after teardown (`get` -> not found). Helper returns 0.
  kubectl() { case "$1" in get) return 1 ;; *) return 0 ;; esac; }
  teardown_partial_session ses-x sandbox-x >"${outf}" 2>"${errf}" && rc=0 || rc=$?
  [[ "${rc}" -eq 0 ]] \
    && pass "gone pod: teardown reports success" \
    || fail "gone pod: expected rc 0, got ${rc}"
  grep -q "REMINDER: Revoke infra token" "${errf}" \
    && pass "revocation reminder reaches stderr (F1)" \
    || fail "revocation reminder was swallowed (F1 regression)"
  grep -q "Pod deleted" "${errf}" \
    && fail "routine stdout chatter leaked onto stderr" \
    || pass "routine chatter stays off stderr"

  # Case 2: pod still present (`get` -> found). Helper returns 1 and warns.
  kubectl() { return 0; }
  teardown_partial_session ses-x sandbox-x >"${outf}" 2>"${errf}" && rc=0 || rc=$?
  [[ "${rc}" -eq 1 ]] \
    && pass "lingering pod: teardown reports failure (F2)" \
    || fail "lingering pod: expected rc 1, got ${rc}"
  grep -q "Teardown did not remove pod" "${errf}" \
    && pass "lingering pod: operator is warned" \
    || fail "lingering pod produced no warning (F2 regression)"
}

# adopt_session_secrets must ownerReference the pod onto every session Secret
# that exists (so a kubelet eviction, which bypasses cmd_stop, still gets them
# GC'd — PR #92 finding F3), skip the ones that don't, and no-op entirely when
# the pod UID is unknown.
test_adopt_session_secrets_ownerrefs() {
  info "Testing adopt_session_secrets patches only present secrets with the pod ownerReference..."
  SANDBOX_NAMESPACE="sandbox"
  local patchlog="${TEST_DIR}/patchlog"
  : > "${patchlog}"

  # Two of the four candidate secrets exist for this session.
  local present=" infra-token-sess1 opencode-apikey-sess1 "
  kubectl() {
    case "$1" in
      get)   case "${present}" in *" $5 "*) return 0 ;; *) return 1 ;; esac ;;
      patch) printf '%s|%s\n' "$5" "$8" >> "${patchlog}" ;;
      *)     return 0 ;;
    esac
  }

  adopt_session_secrets "sess1" "sandbox-sess1" "uid-123"

  grep -q '^infra-token-sess1|' "${patchlog}" \
    && pass "present secret infra-token is adopted" \
    || fail "infra-token-sess1 was not patched"
  grep -q '^opencode-apikey-sess1|' "${patchlog}" \
    && pass "present secret opencode-apikey is adopted" \
    || fail "opencode-apikey-sess1 was not patched"
  grep -q 'kubeconfig-sess1\|session-secrets-sess1' "${patchlog}" \
    && fail "an absent secret was patched" \
    || pass "absent secrets are skipped"
  grep -q 'uid-123' "${patchlog}" && grep -q 'sandbox-sess1' "${patchlog}" \
    && pass "ownerReference carries the pod name and uid" \
    || fail "patch payload missing pod name/uid"

  # No UID (pod not yet created / lookup failed): adopt must not patch anything,
  # but because a credential Secret is present it must WARN rather than skip
  # silently (R6) — those Secrets now rely on 'sandbox stop' for revocation.
  : > "${patchlog}"
  local warnout
  warnout="$(adopt_session_secrets "sess1" "sandbox-sess1" "" 2>&1 >/dev/null)"
  [[ ! -s "${patchlog}" ]] \
    && pass "empty pod uid is a no-op (no patch)" \
    || fail "adopt patched with an unknown owner uid"
  case "${warnout}" in
    *"Could not resolve pod UID"*) pass "empty pod uid with a present secret warns" ;;
    *) fail "empty pod uid did not warn despite a present secret" ;;
  esac

  # ...and with NO Secrets present the empty-UID path stays quiet (tier-1 case).
  present=" "
  warnout="$(adopt_session_secrets "sess1" "sandbox-sess1" "" 2>&1 >/dev/null)"
  [[ -z "${warnout}" ]] \
    && pass "empty pod uid with no secrets is silent" \
    || fail "empty pod uid warned with no secrets present"
}

# R2: the preStop breadcrumb must be written INSIDE the host-mounted agent-home
# (agent_config_mount), not $HOME=/home/agent, or it lands in the ephemeral
# container layer and dies with the pod. Invisible without a live cluster, so
# assert it against the rendered manifest: the breadcrumb path must be a prefix
# match on one of the container's volumeMount paths.
test_prestop_breadcrumb_persists() {
  info "Testing preStop breadcrumb is written into a mounted volume path..."
  SANDBOX_NAMESPACE="sandbox"
  # Earlier tests stub build_pod_manifest() globally; restore the real one.
  # shellcheck disable=SC1090
  source "${SANDBOX_ROOT}/lib/manifest.sh"
  # Stub the environment-sensitive helpers so build_pod_manifest renders
  # deterministically without touching the host filesystem or a live cluster.
  # (bash dynamic scoping makes these locals/overrides visible to the callee.)
  resolve_agent_home() { echo "/host/agent-home/${1}"; }
  resolve_pod_uid() { echo 1000; }
  local POD_CPU_LIMIT="1" POD_MEM_LIMIT_GI="2" POD_EPHEMERAL_LIMIT_GI="4"
  local POD_CPU_REQUEST="500m" POD_MEM_REQUEST_GI="1" POD_EPHEMERAL_REQUEST_GI="2"

  local yaml
  yaml="$(build_pod_manifest sess-bc claude 1 img 2>/dev/null)" || true

  local bc_path
  bc_path="$(printf '%s\n' "${yaml}" | grep -o '/[^"]*/.sandbox-termination' | head -1 || true)"
  bc_path="${bc_path%/.sandbox-termination}"
  if [[ -z "${bc_path}" ]]; then
    fail "no .sandbox-termination breadcrumb path found in the rendered manifest"
    return
  fi

  # Find the volumeMount whose mountPath is the DEEPEST prefix of the breadcrumb
  # path, then resolve that mount's volume name and assert the volume is backed
  # by a hostPath (persists), NOT an emptyDir (ephemeral). Matching "some
  # mountPath" is too weak: /tmp is an emptyDir mount, so a regression pointing
  # the breadcrumb at /tmp/.sandbox-termination would pass a prefix-only check
  # and silently reintroduce the exact bug this test guards (PR #93 finding F5).
  local vol_name="" best_len=-1 cur_name="" line mp
  while IFS= read -r line; do
    case "${line}" in
      *"- name: "*) cur_name="${line#*- name: }" ;;
      *"mountPath: "*)
        mp="${line#*mountPath: }"
        case "${bc_path}/" in
          "${mp}"/*|"${mp}")
            (( ${#mp} > best_len )) && { best_len=${#mp}; vol_name="${cur_name}"; } ;;
        esac ;;
    esac
  done < <(printf '%s\n' "${yaml}")

  if [[ -z "${vol_name}" ]]; then
    fail "breadcrumb path ${bc_path} is under NO volumeMount (ephemeral container layer)"
    return
  fi

  # What backs the volume of that name — hostPath or emptyDir?
  local vol_kind
  vol_kind="$(printf '%s\n' "${yaml}" | awk -v n="${vol_name}" '
    $1=="-" && $2=="name:" && $3==n {inblk=1; next}
    inblk && $1=="-" && $2=="name:" {inblk=0}
    inblk && $1=="hostPath:" {print "hostPath"; exit}
    inblk && $1=="emptyDir:" {print "emptyDir"; exit}
  ')"

  [[ "${vol_kind}" == "hostPath" ]] \
    && pass "breadcrumb path ${bc_path} is on volume '${vol_name}' (hostPath, persists past the pod)" \
    || fail "breadcrumb path ${bc_path} is on volume '${vol_name}' backed by '${vol_kind:-unknown}', not hostPath (ephemeral)"
}

# F3: a remediated eviction must be distinguishable from a clean teardown.
# audit_record_end_reason stamps end_reason/end_detail when (and only when) a
# reason is present, so a normal stop leaves the field absent.
test_audit_record_end_reason() {
  info "Testing audit_record_end_reason marks abnormal endings, no-ops otherwise..."
  local d="${TEST_DIR}/endreason"
  mkdir -p "${d}"
  printf '%s\n' '{"session_id":"s1","end_time":null}' > "${d}/session.json"

  # Clean-teardown path: empty reason must NOT add the field.
  audit_record_end_reason "${d}" "" ""
  [[ "$(jq -r '.end_reason // "ABSENT"' "${d}/session.json")" == "ABSENT" ]] \
    && pass "empty reason leaves end_reason absent (clean teardown indistinguishable only from clean)" \
    || fail "empty reason wrote an end_reason"

  # Eviction path: records the token and the kubelet detail.
  audit_record_end_reason "${d}" "evicted" "Evicted: The node was low on resource: ephemeral-storage"
  [[ "$(jq -r '.end_reason' "${d}/session.json")" == "evicted" ]] \
    && pass "eviction records end_reason=evicted" \
    || fail "end_reason not recorded"
  case "$(jq -r '.end_detail' "${d}/session.json")" in
    *"ephemeral-storage"*) pass "kubelet detail preserved in end_detail" ;;
    *) fail "end_detail did not preserve the kubelet message" ;;
  esac
}

# N7 (corrects N3): cmd_stop must delete the POD — the containment action that
# stops an adversarial agent's execution — BEFORE the credential-Secret deletes
# (namespace bookkeeping; the agent already holds the projected token) and the
# slow best-effort capture (workspace diff, transcript, Hubble export). Teardown
# is now reachable at moments the operator didn't choose (a signalled disconnect)
# where the process may be killed again mid-run; if that happens partway, the
# agent must already be stopped rather than left live behind the capture. Run the
# REAL cmd_stop with recording stubs and assert the order.
test_cmd_stop_deletes_pod_before_capture() {
  info "Testing cmd_stop deletes the pod (containment) before the Secret deletes + capture (N7)..."
  # Earlier tests globally redefine cmd_stop (and other helpers) with stubs; this
  # test drives the REAL cmd_stop, so restore the genuine definitions first.
  # bin/sandbox is source-guarded, so this only redefines functions.
  # shellcheck disable=SC1090
  source "${SANDBOX_ROOT}/bin/sandbox" >/dev/null 2>&1
  SANDBOX_NAMESPACE="sandbox"
  SANDBOX_LOGS_DIR="${TEST_DIR}/logs-n3"
  local sid="ses-n3"
  local sdir="${SANDBOX_LOGS_DIR}/${sid}"
  mkdir -p "${sdir}"
  # Tier 2 with a repo so the workspace-diff capture runs; agent set so the
  # transcript capture runs.
  printf '%s\n' '{"agent":"claude","tier":2,"repos":["/repo/a"],"agent_session_id":"as1"}' \
    > "${sdir}/session.json"

  local order="${TEST_DIR}/n3-order"
  : > "${order}"

  resolve_pod_name() { echo "sandbox-${1}"; }
  # All session Secrets and the pod are "present". Record credential deletions and
  # the pod delete; keep the end-reason probe on the clean (Running) path.
  kubectl() {
    case "$1 $2" in
      "get secret")   return 0 ;;
      "delete secret") echo "SECRET:${5}" >> "${order}"; return 0 ;;
      "get pod")
        case "$*" in
          *jsonpath*phase*) echo "Running" ;;
          *jsonpath*)       echo "" ;;
          *)                return 0 ;;
        esac ;;
      "delete pod")               echo "PODDELETE"  >> "${order}"; return 0 ;;
      "delete ciliumnetworkpolicy") return 0 ;;
      *) return 0 ;;
    esac
  }
  # Credential-delete helpers (record as SECRET markers).
  delete_kubeconfig_secret()      { echo "SECRET:kubeconfig"   >> "${order}"; }
  delete_opencode_apikey_secret() { echo "SECRET:opencode"     >> "${order}"; }
  delete_session_secrets()        { echo "SECRET:session-bndl" >> "${order}"; }
  # Capture steps (record as CAPTURE markers) — the slow best-effort work.
  teardown_workspace_sync()  { :; }
  capture_workspace_diff()   { echo "CAPTURE:workspace"  >> "${order}"; }
  sync_agent_home_back()     { :; }
  host_agent_home()          { echo "/host/agent-home/$1"; }
  audit_capture_transcript() { echo "CAPTURE:transcript" >> "${order}"; }
  export_hubble_flows()      { echo "CAPTURE:hubble"     >> "${order}"; }
  # Remaining teardown tail — no-ops for this test.
  teardown_dependencies()          { :; }
  audit_update_end_time()          { :; }
  audit_record_end_reason()        { :; }
  audit_record_dependencies_down() { :; }

  cmd_stop "${sid}" >/dev/null 2>&1

  # Containment first (N7): the PODDELETE must precede every SECRET marker and
  # every CAPTURE marker. Deleting the pod stops an adversarial agent's execution;
  # the Secret deletes are namespace bookkeeping and the capture steps are slow
  # best-effort work, so both come after execution is already gone.
  local first_secret first_capture pod_delete
  first_secret="$(grep -n '^SECRET:'  "${order}" | head -1 | cut -d: -f1)"
  first_capture="$(grep -n '^CAPTURE:' "${order}" | head -1 | cut -d: -f1)"
  pod_delete="$(grep -n '^PODDELETE'  "${order}" | head -1 | cut -d: -f1)"

  local n_secret n_capture
  n_secret="$(grep -c '^SECRET:'  "${order}")"
  n_capture="$(grep -c '^CAPTURE:' "${order}")"

  if [[ "${n_secret}" -lt 4 ]]; then
    fail "expected 4 credential deletions, saw ${n_secret}: $(tr '\n' ' ' < "${order}")"
  fi
  [[ "${n_capture}" -ge 1 && -n "${pod_delete}" ]] \
    || fail "capture/pod-delete markers missing: $(tr '\n' ' ' < "${order}")"

  [[ "${pod_delete}" -lt "${first_secret}" ]] \
    && pass "pod deleted before any credential Secret deletion" \
    || fail "a credential deletion ran before the pod delete: $(tr '\n' ' ' < "${order}")"
  [[ "${pod_delete}" -lt "${first_capture}" ]] \
    && pass "pod deleted before any capture step" \
    || fail "a capture step ran before the pod delete: $(tr '\n' ' ' < "${order}")"
}

# N7 follow-up: the pod delete is now the FIRST step in cmd_stop and the only
# delete that can exit non-zero (a TOCTOU NotFound race, a transient API error).
# It MUST be `|| true`/`--ignore-not-found`-guarded, or under `set -e` on the
# direct `sandbox stop` path a failed pod delete aborts cmd_stop BEFORE the
# credential-Secret deletes it now precedes — leaving them live.
#
# Faithfully reproducing that means running cmd_stop as a BARE command under
# errexit (exactly the `stop)` dispatch path). We cannot call it inline with a
# `|| true`/`if` guard here: putting a function in a `&&`/`||` list DISABLES
# errexit inside the whole function (a bash rule), which would mask the very bug.
# So run it in a child `bash -c` (its own `set -euo pipefail`, cmd_stop bare) and
# inspect the order file it wrote plus the child's exit code. With the guard the
# child exits 0 and revokes all four Secrets; without it the child aborts on the
# failing pod delete (exit non-zero, zero Secret markers).
test_cmd_stop_revokes_even_if_pod_delete_fails() {
  info "Testing a non-zero pod delete does NOT abort cmd_stop before revocation (N7 guard)..."
  local logs="${TEST_DIR}/logs-n7guard"
  local sid="ses-n7g"
  mkdir -p "${logs}/${sid}"
  printf '%s\n' '{"agent":"claude","tier":3,"repos":[],"agent_session_id":"as1"}' \
    > "${logs}/${sid}/session.json"
  local order="${TEST_DIR}/n7g-order"
  : > "${order}"

  local rc=0
  ORDER_FILE="${order}" SANDBOX_LOGS_DIR="${logs}" \
  bash -c '
    set -euo pipefail
    source "'"${SANDBOX_ROOT}"'/bin/sandbox" >/dev/null 2>&1
    SANDBOX_NAMESPACE="sandbox"
    resolve_pod_name() { echo "sandbox-$1"; }
    # Pod present so the delete runs; the delete FAILS (return 1) to simulate the
    # NotFound/transient-error race. All session Secrets present.
    kubectl() {
      case "$1 $2" in
        "get secret")    return 0 ;;
        "delete secret") echo "SECRET:$5" >> "${ORDER_FILE}"; return 0 ;;
        "get pod")
          case "$*" in
            *jsonpath*phase*) echo "Running" ;;
            *jsonpath*)       echo "" ;;
            *)                return 0 ;;
          esac ;;
        "delete pod")                 echo "PODDELETE" >> "${ORDER_FILE}"; return 1 ;;
        "delete ciliumnetworkpolicy") return 0 ;;
        *) return 0 ;;
      esac
    }
    delete_kubeconfig_secret()      { echo "SECRET:kubeconfig"   >> "${ORDER_FILE}"; }
    delete_opencode_apikey_secret() { echo "SECRET:opencode"     >> "${ORDER_FILE}"; }
    delete_session_secrets()        { echo "SECRET:session-bndl" >> "${ORDER_FILE}"; }
    teardown_workspace_sync()  { :; }; capture_workspace_diff()   { :; }
    sync_agent_home_back()     { :; }; host_agent_home()          { echo "/h/$1"; }
    audit_capture_transcript() { :; }; export_hubble_flows()      { :; }
    teardown_dependencies()          { :; }; audit_update_end_time() { :; }
    audit_record_end_reason()        { :; }; audit_record_dependencies_down() { :; }
    cmd_stop "'"${sid}"'" >/dev/null 2>&1
  ' >/dev/null 2>&1 || rc=$?

  local n_secret
  n_secret="$(grep -c '^SECRET:' "${order}" 2>/dev/null || echo 0)"
  [[ "${rc}" -eq 0 && "${n_secret}" -ge 4 ]] \
    && pass "all 4 credential Secrets revoked despite a failing pod delete (rc=${rc})" \
    || fail "a failing pod delete aborted cmd_stop before revocation (rc=${rc}, saw ${n_secret}/4 secrets): $(tr '\n' ' ' < "${order}")"
}

# PR #93 P1: the issuer-side revoke reminders must NOT depend on the credential
# Secret still existing at stop time. adopt_session_secrets puts a pod
# ownerReference on those Secrets, so the (now-first) pod delete triggers
# cascading GC of them — a `kubectl get secret` probe afterward races that GC and
# a reminder gated on it fires nondeterministically. cmd_stop now keys the
# reminder off the session RECORD (infra_token/infra_kubeconfig booleans) OR the
# existence captured before the pod delete. Here we simulate GC having already
# won: every `get secret` returns NotFound, yet the record says the session had
# both credentials, so BOTH reminders must still reach stderr.
test_cmd_stop_reminds_even_if_secret_gc_won() {
  info "Testing revoke reminders fire off the record when GC already deleted the Secret (P1)..."
  # shellcheck disable=SC1090
  source "${SANDBOX_ROOT}/bin/sandbox" >/dev/null 2>&1
  SANDBOX_NAMESPACE="sandbox"
  SANDBOX_LOGS_DIR="${TEST_DIR}/logs-p1"
  local sid="ses-p1"
  local sdir="${SANDBOX_LOGS_DIR}/${sid}"
  mkdir -p "${sdir}"
  printf '%s\n' '{"agent":"claude","tier":3,"repos":[],"infra_token":true,"infra_kubeconfig":true}' \
    > "${sdir}/session.json"

  resolve_pod_name() { echo "sandbox-${1}"; }
  # Pod present (delete succeeds); ALL `get secret` probes return NotFound to
  # model ownerReference GC having already reaped the Secrets by stop time.
  kubectl() {
    case "$1 $2" in
      "get secret")   return 1 ;;
      "delete secret") return 0 ;;
      "get pod")
        case "$*" in
          *jsonpath*phase*) echo "Running" ;;
          *jsonpath*)       echo "" ;;
          *)                return 0 ;;
        esac ;;
      "delete pod")                 return 0 ;;
      "delete ciliumnetworkpolicy") return 0 ;;
      *) return 0 ;;
    esac
  }
  delete_kubeconfig_secret()      { :; }
  delete_opencode_apikey_secret() { :; }
  delete_session_secrets()        { :; }
  teardown_workspace_sync()  { :; }; capture_workspace_diff()   { :; }
  sync_agent_home_back()     { :; }; host_agent_home()          { echo "/h/$1"; }
  audit_capture_transcript() { :; }; export_hubble_flows()      { :; }
  teardown_dependencies()          { :; }; audit_update_end_time() { :; }
  audit_record_end_reason()        { :; }; audit_record_dependencies_down() { :; }

  local err="${TEST_DIR}/p1-err"
  cmd_stop "${sid}" >/dev/null 2>"${err}"

  grep -q "REMINDER: Revoke infra token" "${err}" \
    && pass "infra-token revoke reminder fires despite the Secret being GC'd" \
    || fail "infra-token reminder suppressed by GC race: $(tr '\n' ' ' < "${err}")"
  grep -q "REMINDER: kubeconfig credentials" "${err}" \
    && pass "kubeconfig rotate reminder fires despite the Secret being GC'd" \
    || fail "kubeconfig reminder suppressed by GC race: $(tr '\n' ' ' < "${err}")"
}

# PR #93 P2: `--ignore-not-found` already makes the NotFound race exit 0, so a
# non-zero pod-delete rc is a GENUINE failure (RBAC denial, API down, stuck
# finalizer) where containment did NOT happen. cmd_stop must NOT print
# "Pod deleted." in that case and must record end_reason=teardown-incomplete so
# the audit record and cmd_list don't read as a clean stop.
test_cmd_stop_flags_failed_pod_delete() {
  info "Testing a failed pod delete suppresses 'Pod deleted.' and records teardown-incomplete (P2)..."
  # shellcheck disable=SC1090
  source "${SANDBOX_ROOT}/bin/sandbox" >/dev/null 2>&1
  SANDBOX_NAMESPACE="sandbox"
  SANDBOX_LOGS_DIR="${TEST_DIR}/logs-p2"
  local sid="ses-p2"
  local sdir="${SANDBOX_LOGS_DIR}/${sid}"
  mkdir -p "${sdir}"
  printf '%s\n' '{"agent":"claude","tier":3,"repos":[]}' > "${sdir}/session.json"

  local reasonf="${TEST_DIR}/p2-reason"
  : > "${reasonf}"

  resolve_pod_name() { echo "sandbox-${1}"; }
  kubectl() {
    case "$1 $2" in
      "get secret")   return 1 ;;
      "get pod")
        case "$*" in
          *jsonpath*phase*) echo "Running" ;;
          *jsonpath*)       echo "" ;;
          *)                return 0 ;;
        esac ;;
      # The delete FAILS with a forbidden-style error on stdout (captured into
      # the warning) — a genuine failure, not the ignored NotFound race.
      "delete pod")                 echo 'Error from server (Forbidden): pods "x" is forbidden'; return 1 ;;
      "delete ciliumnetworkpolicy") return 0 ;;
      *) return 0 ;;
    esac
  }
  delete_kubeconfig_secret()      { :; }
  delete_opencode_apikey_secret() { :; }
  delete_session_secrets()        { :; }
  teardown_workspace_sync()  { :; }; capture_workspace_diff()   { :; }
  sync_agent_home_back()     { :; }; host_agent_home()          { echo "/h/$1"; }
  audit_capture_transcript() { :; }; export_hubble_flows()      { :; }
  teardown_dependencies()          { :; }; audit_update_end_time() { :; }
  audit_record_dependencies_down() { :; }
  # Capture the reason cmd_stop stamps.
  audit_record_end_reason() { printf '%s' "${2:-}" > "${reasonf}"; }

  local out="${TEST_DIR}/p2-out"
  cmd_stop "${sid}" >"${out}" 2>/dev/null

  grep -q "Pod deleted." "${out}" \
    && fail "'Pod deleted.' printed after a failed delete: $(tr '\n' ' ' < "${out}")" \
    || pass "'Pod deleted.' suppressed when the delete failed"
  [[ "$(cat "${reasonf}")" == "teardown-incomplete" ]] \
    && pass "failed delete records end_reason=teardown-incomplete" \
    || fail "end_reason not set to teardown-incomplete (got '$(cat "${reasonf}")')"
}

main() {
  info "Running ${TEST_NAME} tests..."
  # NOTE: this suite is ORDER-DEPENDENT. Earlier tests globally stub cmd_stop and
  # its teardown helpers; test_cmd_stop_deletes_pod_before_capture re-sources
  # bin/sandbox mid-suite (source-guarded, so only function defs are restored) to
  # drive the REAL cmd_stop. Keep that test after the stubbing ones.
  test_blocker_allows_simple_sessions
  test_blocker_guides_the_rest
  test_guide_command_reconstructs_run
  test_recreate_reruns_gates_before_apply
  test_recreate_tears_down_on_pod_failure
  test_teardown_partial_session_integrity
  test_adopt_session_secrets_ownerrefs
  test_prestop_breadcrumb_persists
  test_audit_record_end_reason
  test_cmd_stop_deletes_pod_before_capture
  test_cmd_stop_revokes_even_if_pod_delete_fails
  test_cmd_stop_reminds_even_if_secret_gc_won
  test_cmd_stop_flags_failed_pod_delete
  echo "All ${TEST_NAME} tests passed."
}

main "$@"
