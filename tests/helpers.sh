#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/helpers.sh — Shared boilerplate for all sandbox test scripts
# Source this at the top of every test: source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"
set -euo pipefail

NAMESPACE="sandbox"

# Canonical kubeconfig — must match lib/platform.sh and setup/common.sh.
# All kubectl calls in tests use the wrapper below so they always target the
# sandbox k3s cluster, regardless of the user's default ~/.kube/config.
SANDBOX_KUBECONFIG="${SANDBOX_KUBECONFIG:-${HOME}/.sandbox/kubeconfig}"

# kubectl wrapper — always targets the sandbox cluster explicitly.
kubectl() {
  command kubectl --kubeconfig "${SANDBOX_KUBECONFIG}" "$@"
}

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
info() { echo "INFO: $*"; }
warn() { echo "WARN: $*" >&2; }
# skip — bail out of a test that can't run in this environment. Exits 0 so
# the test runner counts it as non-failing; the SKIP: prefix makes it
# distinguishable from PASS in logs.
skip() { echo "SKIP: $*"; exit 0; }
