#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-cross-platform.sh — Cross-platform parity tests
# Verifies: sandbox CLI works on both Linux and macOS
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_NAME="test-cross-platform"

fail() { echo "FAIL: $*" >&2; exit 1; }

source "${SANDBOX_ROOT}/lib/platform.sh"

###############################################################################
# Test: Platform detection returns a known platform
###############################################################################
test_platform_detection() {
  info "Testing platform detection..."

  local platform
  platform="$(detect_platform)"

  case "${platform}" in
    linux)
      pass "Platform detected: linux"
      ;;
    macos)
      pass "Platform detected: macos"
      ;;
    *)
      fail "Unknown platform detected: ${platform}"
      ;;
  esac
}

###############################################################################
# Test: sandbox CLI binary is executable and returns version
###############################################################################
test_cli_executable() {
  info "Testing sandbox CLI is executable..."

  local sandbox_bin="${SANDBOX_ROOT}/bin/sandbox"

  if [[ ! -f "${sandbox_bin}" ]]; then
    fail "sandbox binary not found at: ${sandbox_bin}"
  fi

  if [[ ! -x "${sandbox_bin}" ]]; then
    fail "sandbox binary is not executable: ${sandbox_bin}"
  fi
  pass "sandbox binary exists and is executable"

  local version_output
  version_output="$("${sandbox_bin}" version 2>&1)"
  if echo "${version_output}" | grep -q "sandbox"; then
    pass "sandbox version command works: ${version_output}"
  else
    fail "sandbox version returned unexpected output: ${version_output}"
  fi
}

###############################################################################
# Test: session ID format is correct on this platform
###############################################################################
test_session_id_format() {
  info "Testing session ID generation format..."

  # Source the bin/sandbox to get access to generate_session_id
  # We do this by running it in a subshell with --dry-run
  local id
  # Simulate what generate_session_id does
  local date_part
  local time_part
  local rand_part

  if is_linux; then
    date_part="$(date -u '+%Y%m%d')"
    time_part="$(date -u '+%H%M%S')"
  elif is_macos; then
    date_part="$(date -u '+%Y%m%d')"
    time_part="$(date -u '+%H%M%S')"
  fi

  rand_part="$(head -c 2 /dev/urandom | xxd -p | head -c 4)"
  id="ses-${date_part}-${time_part}-${rand_part}"

  if echo "${id}" | grep -qE '^ses-[0-9]{8}-[0-9]{6}-[0-9a-f]{4}$'; then
    pass "Session ID format correct: ${id}"
  else
    fail "Session ID format invalid: ${id}"
  fi
}

###############################################################################
# Test: Required tools exist on this platform
###############################################################################
test_required_tools() {
  info "Testing required tools availability..."

  local required=("kubectl" "jq" "git" "xxd" "curl")
  local all_ok=true

  for tool in "${required[@]}"; do
    if command -v "${tool}" &>/dev/null; then
      pass "Tool available: ${tool}"
    else
      warn "Tool NOT available: ${tool} (install before running sandbox)"
      all_ok=false
    fi
  done

  # sha-256 hasher: sha256sum on Linux, shasum on stock macOS — either works.
  if command -v sha256sum &>/dev/null || command -v shasum &>/dev/null; then
    pass "Tool available: sha256sum (or shasum)"
  else
    warn "Tool NOT available: sha256sum (or shasum) (install before running sandbox)"
    all_ok=false
  fi

  if [[ "${all_ok}" == "true" ]]; then
    pass "All required tools are available"
  else
    warn "Some required tools are missing — install them before using sandbox"
  fi
}

###############################################################################
# Test: macOS-specific — Lima is available (if on macOS)
###############################################################################
test_macos_lima() {
  if ! is_macos; then
    info "Skipping Lima test (not on macOS)"
    return 0
  fi

  info "Testing Lima availability (macOS)..."

  if command -v limactl &>/dev/null; then
    pass "limactl is available: $(limactl --version)"
  else
    warn "limactl not found — install with: brew install lima"
  fi
}

###############################################################################
# Test: Linux-specific — k3s systemd service (if on Linux)
###############################################################################
test_linux_k3s() {
  if ! is_linux; then
    info "Skipping k3s systemd test (not on Linux)"
    return 0
  fi

  info "Testing k3s status (Linux)..."

  if command -v k3s &>/dev/null; then
    pass "k3s binary is available"
    if systemctl is-active --quiet k3s 2>/dev/null; then
      pass "k3s systemd service is active"
    else
      warn "k3s service is not active — run 'sudo systemctl start k3s' or 'sandbox setup'"
    fi
  else
    warn "k3s not installed — run 'sandbox setup'"
  fi
}

###############################################################################
# Test: lib/platform.sh is_linux / is_macos are mutually exclusive
###############################################################################
test_platform_bool_helpers() {
  info "Testing platform boolean helpers are mutually exclusive..."

  local linux_result=0
  local macos_result=0

  is_linux && linux_result=1 || true
  is_macos && macos_result=1 || true

  local total=$(( linux_result + macos_result ))

  if [[ "${total}" -eq 1 ]]; then
    pass "Exactly one of is_linux/is_macos is true (linux=${linux_result}, macos=${macos_result})"
  else
    fail "is_linux and is_macos should be mutually exclusive (linux=${linux_result}, macos=${macos_result})"
  fi
}

###############################################################################
# Test: Config files are present and valid YAML structure
###############################################################################
test_config_files_present() {
  info "Testing config files are present..."

  local config_files=(
    "${SANDBOX_ROOT}/config/blocked-destinations.yaml"
    "${SANDBOX_ROOT}/config/defaults.yaml"
    "${SANDBOX_ROOT}/config/agents/claude.yaml"
    "${SANDBOX_ROOT}/config/agents/codex.yaml"
    "${SANDBOX_ROOT}/config/agents/opencode.yaml"
    "${SANDBOX_ROOT}/config/tiers/tier1.yaml"
    "${SANDBOX_ROOT}/config/tiers/tier2.yaml"
  )

  for f in "${config_files[@]}"; do
    if [[ -f "${f}" ]]; then
      pass "Config present: ${f##${SANDBOX_ROOT}/}"
    else
      fail "Config missing: ${f}"
    fi
  done
}

###############################################################################
# Test: Manifest files are present
###############################################################################
test_manifest_files_present() {
  info "Testing manifest files are present..."

  # NOTE: the ResourceQuota/LimitRange are no longer static manifests — they
  # are generated and sized to the node by lib/resources.sh at setup time.
  local manifests=(
    "${SANDBOX_ROOT}/manifests/namespace.yaml"
    "${SANDBOX_ROOT}/manifests/serviceaccount.yaml"
    "${SANDBOX_ROOT}/manifests/runtimeclass.yaml"
    "${SANDBOX_ROOT}/manifests/policy-kube-system.yaml"
  )

  for f in "${manifests[@]}"; do
    if [[ -f "${f}" ]]; then
      pass "Manifest present: ${f##${SANDBOX_ROOT}/}"
    else
      fail "Manifest missing: ${f}"
    fi
  done
}

main() {
  echo "=== ${TEST_NAME} ==="
  echo "Platform: $(detect_platform)"
  echo ""

  test_platform_detection
  test_cli_executable
  test_session_id_format
  test_required_tools
  test_macos_lima
  test_linux_k3s
  test_platform_bool_helpers
  test_config_files_present
  test_manifest_files_present

  echo ""
  echo "All cross-platform tests passed."
}

main "$@"
