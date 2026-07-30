#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-vm-sizing.sh — Lima VM sizing resolvers (lib/resources.sh).
#
# On macOS the sandbox cluster runs inside a Lima VM, so concurrency is bounded
# by the VM's resources. lima_vm_cpus / lima_vm_memory_gib / lima_vm_disk_gib
# resolve that size: an explicit --vm-* / SANDBOX_VM_* override wins, otherwise
# the value is derived host-relative (host cores/RAM minus a macOS reserve),
# floored so the cluster stack always fits and capped at the physical hardware.
# These are unit-testable without a cluster; the host-reading helpers
# (_host_cpus / _host_mem_gib) are shell functions the test overrides to inject
# deterministic host sizes across platforms.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

assert_eq() {
  # assert_eq <label> <got> <want>
  if [[ "$2" == "$3" ]]; then
    pass "$1 (= $2)"
  else
    fail "$1: got '$2', want '$3'"
  fi
}

# --- Explicit overrides win --------------------------------------------------
(
  SANDBOX_VM_CPUS=7 SANDBOX_VM_MEMORY_GI=13 SANDBOX_VM_DISK_GI=100
  # shellcheck disable=SC1090
  source "${SANDBOX_ROOT}/lib/resources.sh"
  # An override must be returned verbatim, without ever consulting the host.
  _host_cpus() { echo 999; }
  _host_mem_gib() { echo 999; }
  assert_eq "explicit --vm-cpus wins"   "$(lima_vm_cpus)"       "7"
  assert_eq "explicit --vm-memory wins" "$(lima_vm_memory_gib)" "13"
  assert_eq "explicit --vm-disk wins"   "$(lima_vm_disk_gib)"   "100"
)

# --- Disk default ------------------------------------------------------------
(
  # shellcheck disable=SC1090
  source "${SANDBOX_ROOT}/lib/resources.sh"
  assert_eq "disk defaults to 60GiB" "$(lima_vm_disk_gib)" "60"
)

# --- Host-relative CPU sizing ------------------------------------------------
(
  # shellcheck disable=SC1090
  source "${SANDBOX_ROOT}/lib/resources.sh"
  SANDBOX_VM_CPUS=""                 # auto
  SANDBOX_VM_HOST_RESERVE_CPU=2
  SANDBOX_VM_CPUS_MIN=4

  _host_cpus() { echo 10; }
  assert_eq "10 cores - 2 reserve = 8" "$(lima_vm_cpus)" "8"

  _host_cpus() { echo 4; }           # 4-2=2 < floor 4, but capped at 4 cores
  assert_eq "small host floors to core count" "$(lima_vm_cpus)" "4"

  _host_cpus() { echo 3; }           # floor 4 exceeds physical, cap at 3
  assert_eq "floor never exceeds physical cores" "$(lima_vm_cpus)" "3"

  _host_cpus() { echo 0; }           # unreadable host
  assert_eq "unreadable host CPU falls back to floor" "$(lima_vm_cpus)" "4"
)

# --- Host-relative memory sizing ---------------------------------------------
(
  # shellcheck disable=SC1090
  source "${SANDBOX_ROOT}/lib/resources.sh"
  SANDBOX_VM_MEMORY_GI=""            # auto
  SANDBOX_VM_HOST_RESERVE_MEM_GI=6
  SANDBOX_VM_MEMORY_MIN_GI=8

  _host_mem_gib() { echo 32; }
  assert_eq "32Gi - 6 reserve = 26" "$(lima_vm_memory_gib)" "26"

  _host_mem_gib() { echo 16; }
  assert_eq "16Gi - 6 reserve = 10" "$(lima_vm_memory_gib)" "10"

  _host_mem_gib() { echo 8; }        # 8-6=2 < floor 8, but must leave 2Gi (cap 6)
  assert_eq "small host floors under the 2Gi macOS headroom" "$(lima_vm_memory_gib)" "6"

  _host_mem_gib() { echo 0; }        # unreadable host
  assert_eq "unreadable host RAM falls back to floor" "$(lima_vm_memory_gib)" "8"
)

# --- Off-macOS the host readers report 0 (so auto-sizing hits the floor) -----
# This test host is Linux; the real _host_cpus/_host_mem_gib must short-circuit.
if [[ "$(uname -s)" != "Darwin" ]]; then
  (
    # shellcheck disable=SC1090
    source "${SANDBOX_ROOT}/lib/resources.sh"
    assert_eq "real _host_cpus is 0 off-macOS"    "$(_host_cpus)"    "0"
    assert_eq "real _host_mem_gib is 0 off-macOS" "$(_host_mem_gib)" "0"
  )
fi

# --- In-VM host reserve is smaller on macOS and WSL --------------------------
# The reserve is chosen at source time from uname + the osrelease file. A uname
# shim plus the overridable _RESOURCES_OSRELEASE_FILE let us exercise every
# branch on one platform. Command substitution runs in a subshell that inherits
# shell functions, so resources.sh's `$(uname -s)` sees the shim.
(
  uname() { if [[ "${1:-}" == "-s" ]]; then echo Darwin; else command uname "$@"; fi; }
  unset HOST_RESERVE_CPU HOST_RESERVE_MEM_GI
  # shellcheck disable=SC1090
  source "${SANDBOX_ROOT}/lib/resources.sh"
  assert_eq "macOS in-VM CPU reserve" "${HOST_RESERVE_CPU}"    "1"
  assert_eq "macOS in-VM mem reserve" "${HOST_RESERVE_MEM_GI}" "2"
)
(
  # WSL2 utility VM: Linux uname, but a microsoft-stamped osrelease -> the
  # smaller in-VM reserve, same as macOS's Lima VM.
  uname() { if [[ "${1:-}" == "-s" ]]; then echo Linux; else command uname "$@"; fi; }
  osr="$(mktemp)"; echo "5.15.153.1-microsoft-standard-WSL2" > "${osr}"
  _RESOURCES_OSRELEASE_FILE="${osr}"
  unset HOST_RESERVE_CPU HOST_RESERVE_MEM_GI
  # shellcheck disable=SC1090
  source "${SANDBOX_ROOT}/lib/resources.sh"
  assert_eq "WSL in-VM CPU reserve" "${HOST_RESERVE_CPU}"    "1"
  assert_eq "WSL in-VM mem reserve" "${HOST_RESERVE_MEM_GI}" "2"
  rm -f "${osr}"
)
(
  # Bare-metal Linux: a non-WSL osrelease -> the larger reserve. Pointed at a
  # temp file so the result never depends on whether this test host is WSL.
  uname() { if [[ "${1:-}" == "-s" ]]; then echo Linux; else command uname "$@"; fi; }
  osr="$(mktemp)"; echo "6.12.0-211.37.1.el10_2.x86_64" > "${osr}"
  _RESOURCES_OSRELEASE_FILE="${osr}"
  unset HOST_RESERVE_CPU HOST_RESERVE_MEM_GI
  # shellcheck disable=SC1090
  source "${SANDBOX_ROOT}/lib/resources.sh"
  assert_eq "Linux host CPU reserve" "${HOST_RESERVE_CPU}"    "2"
  assert_eq "Linux host mem reserve" "${HOST_RESERVE_MEM_GI}" "6"
  rm -f "${osr}"
)

# --- Environment override of the in-VM reserve is honored --------------------
(
  HOST_RESERVE_MEM_GI=9
  # shellcheck disable=SC1090
  source "${SANDBOX_ROOT}/lib/resources.sh"
  assert_eq "explicit HOST_RESERVE_MEM_GI honored" "${HOST_RESERVE_MEM_GI}" "9"
)

echo "All VM sizing tests passed."
