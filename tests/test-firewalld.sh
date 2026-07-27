#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-firewalld.sh — configure_firewalld (setup/linux.sh) and its
# uninstall sibling remove_firewalld_trusted_cidrs (uninstall.sh).
# Cluster-free. Verifies the RHEL/Alma datapath fix without touching the real
# host firewall by shimming firewall-cmd / systemctl / sudo onto PATH.
#
# configure_firewalld:
#   - absent firewalld  -> clean no-op (the Ubuntu-without-firewalld case)
#   - inactive firewalld-> clean no-op (the Ubuntu-with-firewalld-stopped case)
#   - active + untrusted-> both CIDRs added to the trusted zone, one reload
#   - active + trusted  -> idempotent: no add-source, no reload
#
# remove_firewalld_trusted_cidrs:
#   - recovers the ACTUAL CIDRs from the installed k3s unit, so a custom-CIDR
#     (`setup.sh --pod-cidr ...`) install is cleaned up instead of leaving a
#     stale accept-all trusted-zone source behind
#   - falls back to the common.sh defaults only when the k3s unit is gone
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The function reads these; setup normally exports them from common.sh.
SANDBOX_POD_CIDR="100.64.0.0/10"
SANDBOX_SERVICE_CIDR="10.43.0.0/16"

# setup/linux.sh only defines functions at source time (setup_linux is called
# explicitly), so sourcing it is side-effect free.
# shellcheck disable=SC1090
source "${SANDBOX_ROOT}/setup/linux.sh"

# --- Shim harness --------------------------------------------------------
# A throwaway bin dir prepended to PATH. Each shim logs its argv to CALLS so
# assertions can inspect exactly what the function invoked. Behaviour of the
# firewalld/systemctl shims is steered by env vars set per case.
SHIMBIN="$(mktemp -d)"
CALLS="$(mktemp)"
trap 'rm -rf "${SHIMBIN}" "${CALLS}"' EXIT

# sudo shim: transparently drop the sudo and run the rest (so firewall-cmd/
# systemctl resolve to our shims, not the real binaries).
cat > "${SHIMBIN}/sudo" <<'EOF'
#!/usr/bin/env bash
exec "$@"
EOF

# systemctl shim: `is-active --quiet firewalld` exits per FWD_ACTIVE.
cat > "${SHIMBIN}/systemctl" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == "is-active" ]]; then
  [[ "${FWD_ACTIVE:-0}" == "1" ]] && exit 0 || exit 3
fi
exit 0
EOF

# firewall-cmd shim: logs argv; --query-source exits per FWD_TRUSTED.
cat > "${SHIMBIN}/firewall-cmd" <<EOF
#!/usr/bin/env bash
echo "firewall-cmd \$*" >> "${CALLS}"
case " \$* " in
  *" --query-source="*) [[ "\${FWD_TRUSTED:-0}" == "1" ]] && exit 0 || exit 1 ;;
esac
exit 0
EOF
chmod +x "${SHIMBIN}"/*

run_case() {
  : > "${CALLS}"
  PATH="${SHIMBIN}:${PATH}" "$@" >/dev/null 2>&1 || true
}
calls() { cat "${CALLS}"; }

# --- Case 1: firewalld binary absent (Ubuntu default) --------------------
# Run with a PATH that lacks firewall-cmd entirely. The `command -v` guard must
# short-circuit before any other command runs, so CALLS stays empty.
: > "${CALLS}"
( PATH="${SHIMBIN}_missing" configure_firewalld ) >/dev/null 2>&1 || true
if [[ ! -s "${CALLS}" ]]; then pass "absent firewalld: no firewall-cmd calls"; \
  else fail "absent firewalld should be a no-op, saw:"$'\n'"$(calls)"; fi

# --- Case 2: firewalld present but inactive (Ubuntu w/ pkg, stopped) -----
FWD_ACTIVE=0 run_case configure_firewalld
if ! grep -q -- "--add-source" "${CALLS}"; then \
  pass "inactive firewalld: no --add-source"; \
  else fail "inactive firewalld should not modify rules, saw:"$'\n'"$(calls)"; fi
if ! grep -q -- "--reload" "${CALLS}"; then pass "inactive firewalld: no --reload"; \
  else fail "inactive firewalld should not reload, saw:"$'\n'"$(calls)"; fi

# --- Case 3: active + CIDRs not yet trusted (fresh RHEL/Alma) ------------
FWD_ACTIVE=1 FWD_TRUSTED=0 run_case configure_firewalld
if grep -q -- "--add-source=100.64.0.0/10" "${CALLS}"; then \
  pass "active/untrusted: pod CIDR added"; \
  else fail "expected pod CIDR add-source, saw:"$'\n'"$(calls)"; fi
if grep -q -- "--add-source=10.43.0.0/16" "${CALLS}"; then \
  pass "active/untrusted: service CIDR added"; \
  else fail "expected service CIDR add-source, saw:"$'\n'"$(calls)"; fi
if [[ "$(grep -c -- "--reload" "${CALLS}")" == "1" ]]; then \
  pass "active/untrusted: reloaded exactly once"; \
  else fail "expected one --reload, saw:"$'\n'"$(calls)"; fi

# --- Case 4: active + already trusted (idempotent re-run) ----------------
FWD_ACTIVE=1 FWD_TRUSTED=1 run_case configure_firewalld
if ! grep -q -- "--add-source" "${CALLS}"; then \
  pass "active/trusted: no redundant add-source"; \
  else fail "trusted re-run should not add-source, saw:"$'\n'"$(calls)"; fi
if ! grep -q -- "--reload" "${CALLS}"; then \
  pass "active/trusted: no needless reload"; \
  else fail "trusted re-run should not reload, saw:"$'\n'"$(calls)"; fi

# --- Uninstall side: remove_firewalld_trusted_cidrs ----------------------
# uninstall.sh runs its main body at source time, so we can't source it whole.
# Extract just the CIDR-recovery helper and the removal function (a contiguous
# block) and eval them, backed by stub versions of the log/try helpers they
# call. K3S_SERVICE_UNIT is a plain (non-readonly) assignment, so we repoint it
# at a fake unit per case.
skip() { :; }
info() { :; }
ok()   { :; }
try()  { "$@"; }
eval "$(awk '
  /^# Canonical k3s systemd unit/ {cap=1}
  cap {print}
  /^remove_firewalld_trusted_cidrs\(\)/ {infn=1}
  infn && /^}/ {exit}
' "${SANDBOX_ROOT}/uninstall.sh")"

FAKE_UNIT="$(mktemp)"
trap 'rm -rf "${SHIMBIN}" "${CALLS}" "${FAKE_UNIT}"' EXIT

# --- Case 5: custom-CIDR install — recover from the k3s unit, not defaults --
# The unit records the non-default CIDRs setup baked into INSTALL_K3S_EXEC.
cat > "${FAKE_UNIT}" <<'EOF'
ExecStart=/usr/local/bin/k3s \
    server \
	'--flannel-backend=none' \
	'--cluster-cidr=10.99.0.0/16' \
	'--service-cidr=10.200.0.0/16' \
EOF
K3S_SERVICE_UNIT="${FAKE_UNIT}"
FWD_ACTIVE=1 FWD_TRUSTED=1 run_case remove_firewalld_trusted_cidrs
if grep -q -- "--remove-source=10.99.0.0/16" "${CALLS}"; then \
  pass "custom-CIDR uninstall: recovered pod CIDR removed"; \
  else fail "expected --remove-source=10.99.0.0/16, saw:"$'\n'"$(calls)"; fi
if grep -q -- "--remove-source=10.200.0.0/16" "${CALLS}"; then \
  pass "custom-CIDR uninstall: recovered service CIDR removed"; \
  else fail "expected --remove-source=10.200.0.0/16, saw:"$'\n'"$(calls)"; fi
if ! grep -q -- "100.64.0.0/10" "${CALLS}"; then \
  pass "custom-CIDR uninstall: default pod CIDR never touched"; \
  else fail "must not act on the default CIDR, saw:"$'\n'"$(calls)"; fi

# --- Case 6: k3s unit missing — fall back to the common.sh defaults ---------
K3S_SERVICE_UNIT="${FAKE_UNIT}.gone"
FWD_ACTIVE=1 FWD_TRUSTED=1 run_case remove_firewalld_trusted_cidrs
if grep -q -- "--remove-source=100.64.0.0/10" "${CALLS}"; then \
  pass "missing unit: falls back to default pod CIDR"; \
  else fail "expected default pod CIDR fallback, saw:"$'\n'"$(calls)"; fi
if grep -q -- "--remove-source=10.43.0.0/16" "${CALLS}"; then \
  pass "missing unit: falls back to default service CIDR"; \
  else fail "expected default service CIDR fallback, saw:"$'\n'"$(calls)"; fi

# --- Case 7: firewalld inactive — clean no-op on the uninstall side too -----
K3S_SERVICE_UNIT="${FAKE_UNIT}"
FWD_ACTIVE=0 run_case remove_firewalld_trusted_cidrs
if ! grep -q -- "--remove-source" "${CALLS}"; then \
  pass "inactive firewalld uninstall: no --remove-source"; \
  else fail "inactive firewalld should not modify rules, saw:"$'\n'"$(calls)"; fi

echo "All firewalld tests passed."
