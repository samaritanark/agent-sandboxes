#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-platform.sh — k3s_bin (lib/platform.sh) PATH-independence.
# sudo's secure_path exists to stop a caller-controlled PATH from choosing
# which binary runs as root; k3s_bin's result is handed straight to sudo, so
# it must resolve only fixed, known install locations and never consult PATH,
# a shell function, or an alias named k3s.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1090
source "${SANDBOX_ROOT}/lib/platform.sh"

SHIMBIN="$(mktemp -d)"
trap 'rm -rf "${SHIMBIN}"' EXIT

# --- Case 1: a PATH-earlier k3s must not be what gets resolved -----------
printf '#!/usr/bin/env bash\nexit 0\n' > "${SHIMBIN}/k3s"
chmod +x "${SHIMBIN}/k3s"
got="$(PATH="${SHIMBIN}:${PATH}" k3s_bin 2>/dev/null || true)"
if [[ "${got}" != "${SHIMBIN}/k3s" ]]; then
  pass "k3s_bin ignores a PATH-earlier k3s shim"
else
  fail "k3s_bin resolved from PATH: ${got}"
fi

# --- Case 2: a shell function named k3s must not shadow the lookup ------
k3s() { :; }
got="$(k3s_bin 2>/dev/null || true)"
unset -f k3s
if [[ "${got}" != "k3s" ]]; then
  pass "k3s_bin ignores a k3s shell function"
else
  fail "k3s_bin returned a bare name: ${got}"
fi

echo "All platform tests passed."
