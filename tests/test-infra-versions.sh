#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-infra-versions.sh — infra pinning + lifecycle helpers. Cluster-free.
# Verifies: setup/versions.sh defines/overrides the pins; the canonical
# sandbox_image_tags() list matches what build_images actually builds (the drift
# that let copilot leak on uninstall); uninstall derives its removal list from
# that same source; and bin/sandbox's version-inspection helpers parse and
# compare versions correctly (incl. digest-pinned Cilium images).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# eq <label> <expected> <actual>
eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    pass "${label}"
  else
    fail "${label}: expected '${expected}', got '${actual}'"
  fi
}
contains() {
  local label="$1" haystack="$2" needle="$3"
  case "${haystack}" in
    *"${needle}"*) pass "${label}" ;;
    *) fail "${label}: '${needle}' not found in output" ;;
  esac
}

###############################################################################
# setup/versions.sh — pins are defined and environment-overridable
###############################################################################
test_versions_defined() {
  info "Testing setup/versions.sh pin definitions..."
  (
    source "${SANDBOX_ROOT}/setup/versions.sh"
    [[ -n "${SANDBOX_K3S_VERSION}"     ]] || fail "SANDBOX_K3S_VERSION empty"
    [[ -n "${SANDBOX_CILIUM_VERSION}"  ]] || fail "SANDBOX_CILIUM_VERSION empty"
    [[ -n "${SANDBOX_GVISOR_RELEASE}"  ]] || fail "SANDBOX_GVISOR_RELEASE empty"
    [[ -n "${SANDBOX_HELM_VERSION}"    ]] || fail "SANDBOX_HELM_VERSION empty"
    [[ -n "${SANDBOX_NERDCTL_VERSION}" ]] || fail "SANDBOX_NERDCTL_VERSION empty"
    pass "all five pins defined and non-empty"
  )
}

test_versions_overridable() {
  info "Testing environment override of a pin..."
  (
    export SANDBOX_K3S_VERSION="v9.9.9+k3s9"
    source "${SANDBOX_ROOT}/setup/versions.sh"
    eq "preset SANDBOX_K3S_VERSION honored" "v9.9.9+k3s9" "${SANDBOX_K3S_VERSION}"
  )
}

###############################################################################
# renovate.json5 — annotation field order matches the custom-manager regex
###############################################################################
test_renovate_annotation_order() {
  info "Testing renovate.json5 annotation field order..."
  # The custom manager captures the optional annotation fields
  # (registryUrl/extractVersion/versioning) positionally. Renovate's regex
  # engine is re2, which has no lookahead, so the pattern can't be made
  # order-independent while still capturing those as named groups. Reordering a
  # field would therefore make Renovate silently stop matching (and bumping)
  # that pin. This guard turns that silent failure into a loud one: every
  # `# renovate:` line must keep fields in the canonical order the regex expects.
  local canonical="datasource depName registryUrl extractVersion versioning"
  local line count=0
  while IFS= read -r line; do
    line="${line#*# renovate: }"
    count=$((count + 1))

    # Collect the field keys (text before '=') in the order they appear.
    local keys="" f fields=()
    read -ra fields <<<"${line}"
    for f in "${fields[@]}"; do keys="${keys}${f%%=*} "; done

    # Every key must be one the regex knows about (catches typos too).
    local k
    for k in ${keys}; do
      case " ${canonical} " in
        *" ${k} "*) ;;
        *) fail "renovate annotation has unknown field '${k}': ${line}" ;;
      esac
    done

    # The present keys, in appearance order, must equal the canonical order
    # filtered to just those keys — i.e. no field is out of sequence.
    local expected="" c
    for c in ${canonical}; do
      case " ${keys} " in *" ${c} "*) expected="${expected}${c} " ;; esac
    done
    [[ "${keys}" == "${expected}" ]] \
      || fail "renovate annotation fields out of order (breaks the regex): ${line}"

    # datasource + depName are the two required leading fields.
    case "${keys}" in
      "datasource depName"*) ;;
      *) fail "renovate annotation must start 'datasource depName': ${line}" ;;
    esac
  done < <(grep '# renovate:' "${SANDBOX_ROOT}/setup/versions.sh")

  [[ "${count}" -gt 0 ]] || fail "no '# renovate:' annotations found in versions.sh"
  pass "all ${count} renovate annotations keep the canonical field order"
}

###############################################################################
# Image list: canonical sandbox_image_tags() == what build_images builds
###############################################################################
test_image_list_no_drift() {
  info "Testing image-list drift guard..."
  local canonical built_linux built_macos
  canonical="$(cd "${SANDBOX_ROOT}"; source setup/common.sh >/dev/null 2>&1; sandbox_image_tags | sort -u)"

  # What build_images (Linux) and build_images_macos actually build, normalized
  # from `_build_image "docker.io/library/sandbox:X"` / `_vm_build_image "..."`.
  built_linux="$(grep -oE '_build_image "docker.io/library/(sandbox:[a-z-]+)"' "${SANDBOX_ROOT}/setup/common.sh" \
    | sed -E 's#.*(sandbox:[a-z-]+).*#\1#' | sort -u)"
  built_macos="$(grep -oE '_vm_build_image "docker.io/library/(sandbox:[a-z-]+)"' "${SANDBOX_ROOT}/setup/common.sh" \
    | sed -E 's#.*(sandbox:[a-z-]+).*#\1#' | sort -u)"

  eq "canonical list matches Linux build_images" "${canonical}" "${built_linux}"
  eq "canonical list matches build_images_macos" "${canonical}" "${built_macos}"

  # The specific regression: copilot images must be in the canonical set.
  contains "canonical includes sandbox:copilot"       "${canonical}" "sandbox:copilot"
  contains "canonical includes sandbox:copilot-infra"  "${canonical}" "sandbox:copilot-infra"
}

test_uninstall_derives_list() {
  info "Testing uninstall derives its removal list from the canonical source..."
  # Reproduce uninstall.sh's derivation (source common.sh, read the loop) and
  # assert it yields copilot — the image that previously leaked.
  local derived
  derived="$(cd "${SANDBOX_ROOT}"; source setup/common.sh >/dev/null 2>&1
    imgs=()
    while IFS= read -r _img; do [[ -n "${_img}" ]] && imgs+=("${_img}"); done < <(sandbox_image_tags)
    printf '%s\n' "${imgs[@]}")"
  contains "uninstall list includes copilot"       "${derived}" "sandbox:copilot"
  contains "uninstall list includes copilot-infra"  "${derived}" "sandbox:copilot-infra"
  # uninstall.sh itself no longer hardcodes the array
  if grep -qE '^\s*sandbox:claude-infra' "${SANDBOX_ROOT}/uninstall.sh"; then
    fail "uninstall.sh still hardcodes an image array (should derive from sandbox_image_tags)"
  fi
  pass "uninstall.sh no longer hardcodes the image list"
}

###############################################################################
# bin/sandbox version-inspection helpers (sourced without running main)
###############################################################################
test_cli_version_helpers() {
  info "Testing bin/sandbox version helpers..."
  # Source the CLI; the source-guard keeps main() from running. Then shadow
  # kubectl with canned responses for the two jsonpath queries the helpers make.
  # shellcheck disable=SC1090
  source "${SANDBOX_ROOT}/bin/sandbox" >/dev/null 2>&1

  kubectl() {
    case "$*" in
      *"ds cilium"*image*)        echo "quay.io/cilium/cilium:v1.19.4@sha256:2eb67991eaa9368ba199c2fac2c573cb0ffdeb79184533344f42fc9a7ff6af3c" ;;
      *"get nodes"*kubeletVersion*) echo "v1.35.5+k3s1" ;;
      *) return 1 ;;
    esac
  }

  eq "cilium digest-pinned image parses to tag" "v1.19.4" "$(infra_installed_cilium)"
  eq "k3s kubeletVersion parsed"                "v1.35.5+k3s1" "$(infra_installed_k3s)"

  # Drift logic: v-prefix mismatch tolerated; real mismatch flagged; empty=unknown.
  contains "matching versions => ok"      "$(infra_version_line k3s v1.35.5+k3s1 v1.35.5+k3s1)" "ok"
  contains "v-prefix match => ok"         "$(infra_version_line Cilium 1.19.4 v1.19.4)"          "ok"
  contains "real mismatch => drift"       "$(infra_version_line gVisor 20240101.0 20260601.0)"   "drift"
  contains "empty installed => unknown"   "$(infra_version_line k3s v1.35.5+k3s1 '')"            "installed unknown"
}

test_version_stamp_generator() {
  info "Testing scripts/stamp-version.sh (embed once)..."
  local tmp; tmp="$(mktemp -d /tmp/sandbox-stamp-XXXXXX)"

  # Explicit version (release path) is used verbatim; git facts captured.
  STAMP_VERSION_OUT="${tmp}/.version" \
    bash "${SANDBOX_ROOT}/scripts/stamp-version.sh" 2.3.1 >/dev/null
  local gen; gen="$(cat "${tmp}/.version")"
  contains "generator writes explicit VERSION" "${gen}" "VERSION=2.3.1"
  contains "generator captures COMMIT"          "${gen}" "COMMIT="
  contains "generator records TREE_STATE"        "${gen}" "TREE_STATE="

  # No explicit version (install/dev path) derives a non-empty label from git.
  STAMP_VERSION_OUT="${tmp}/.version2" \
    bash "${SANDBOX_ROOT}/scripts/stamp-version.sh" >/dev/null
  local derived; derived="$(grep '^VERSION=' "${tmp}/.version2" | cut -d= -f2-)"
  [[ -n "${derived}" && "${derived}" != "dev" ]] \
    && pass "git-derived VERSION is meaningful (${derived})" \
    || fail "git-derived VERSION was empty/dev inside a checkout"
  rm -rf "${tmp}"
}

test_version_command() {
  info "Testing sandbox version reader/formatter..."
  # shellcheck disable=SC1090
  source "${SANDBOX_ROOT}/bin/sandbox" >/dev/null 2>&1

  # The runtime must never shell out to git — it only reads embedded .version.
  if declare -f cmd_version | grep -qE '\bgit '; then
    fail "cmd_version invokes git at runtime (must read embedded .version only)"
  fi
  pass "cmd_version does not call git at runtime"

  # Drive the globals the reader would have populated from .version.
  SANDBOX_VERSION="1.2.3"; SANDBOX_COMMIT="abc1234"; SANDBOX_COMMIT_DATE="2026-01-01"
  SANDBOX_BUILD_DATE="2026-01-02"; SANDBOX_TREE_STATE="clean"
  eq       "version --short == VERSION" "1.2.3" "$(cmd_version --short)"
  contains "full shows version"  "$(cmd_version)"        "sandbox 1.2.3"
  contains "full shows commit"   "$(cmd_version)"        "abc1234 (2026-01-01)"
  contains "full shows built"    "$(cmd_version)"        "2026-01-02 (clean)"
  contains "json carries version" "$(cmd_version --json)" '"version":"1.2.3"'

  # An unstamped checkout reports a static, honest "dev" with no provenance.
  SANDBOX_VERSION="dev"; SANDBOX_COMMIT=""; SANDBOX_COMMIT_DATE=""
  SANDBOX_BUILD_DATE=""; SANDBOX_TREE_STATE=""
  eq "unstamped reports dev" "dev" "$(cmd_version --short)"
  case "$(cmd_version)" in
    *"commit:"*) fail "dev output should not show a commit line" ;;
    *) pass "dev output omits provenance lines" ;;
  esac
}

test_versions_defined
test_versions_overridable
test_renovate_annotation_order
test_image_list_no_drift
test_uninstall_derives_list
test_cli_version_helpers
test_version_stamp_generator
test_version_command

echo "All infra-versions tests passed."
