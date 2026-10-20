#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan's Purse
# tests/test-buildkit-gc.sh — buildkit GC policy vs kubelet disk eviction.
# Cluster-free. buildkit's cache shares a filesystem with every pod's ephemeral
# storage and is lease-held (kubelet image GC can't reclaim it), so an unbounded
# cache ends in the kubelet evicting a running sandbox. Verifies: the Linux and
# macOS (Lima) buildkitd.toml carry the same explicit GC policy, and buildkit's
# free-space floor sits above the kubelet's nodefs eviction-soft threshold on
# both platforms.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

SANDBOX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LINUX="${SANDBOX_ROOT}/setup/linux.sh"
LIMA="${SANDBOX_ROOT}/lima/sandbox-vm.yaml.tmpl"

# gc_lines <file> <start-regex> <end-regex> — the GC keys inside that file's
# buildkitd.toml heredoc, whitespace-stripped, one per line.
gc_lines() {
  sed -n "/$2/,/$3/p" "$1" \
    | grep -E '^[[:space:]]*(gc|reservedSpace|maxUsedSpace|minFreeSpace)[[:space:]]*=' \
    | tr -d ' \t' | sort
}

linux_gc="$(gc_lines "${LINUX}" 'tee \/etc\/buildkit\/buildkitd.toml' '^EOF$')"
lima_gc="$(gc_lines "${LIMA}" 'cat > \/etc\/buildkit\/buildkitd.toml' 'BUILDKITD_EOF$')"

for key in gc reservedSpace maxUsedSpace minFreeSpace; do
  grep -q "^${key}=" <<<"${linux_gc}" || fail "setup/linux.sh buildkitd.toml lacks ${key}"
done
pass "Linux buildkitd.toml sets gc, reservedSpace, maxUsedSpace, minFreeSpace"

[[ "${linux_gc}" == "${lima_gc}" ]] \
  || fail "Linux and Lima buildkit GC policy differ:"$'\n'"linux:"$'\n'"${linux_gc}"$'\n'"lima:"$'\n'"${lima_gc}"
pass "Lima buildkitd.toml GC policy matches Linux"

# minFreeSpace must be a percentage strictly above the kubelet's nodefs
# eviction-soft percentage, or buildkit may legally leave the disk inside the
# eviction zone.
min_free="$(sed -n 's/^minFreeSpace="\([0-9]*\)%"$/\1/p' <<<"${linux_gc}")"
[[ -n "${min_free}" ]] || fail "minFreeSpace is not a percentage: ${linux_gc}"

# evict_pct <file> — the nodefs.available<N% default in that file's k3s args.
evict_pct() {
  grep -o 'nodefs\.available<[0-9]*%' "$1" | head -1 \
    | sed 's/nodefs\.available<\([0-9]*\)%/\1/'
}
for f in "${LINUX}" "${LIMA}"; do
  pct="$(evict_pct "${f}")"
  [[ -n "${pct}" ]] || fail "no nodefs eviction-soft threshold found in ${f}"
  (( min_free > pct )) \
    || fail "buildkit minFreeSpace ${min_free}% is not above kubelet nodefs.available<${pct}% in ${f##*/}"
  pass "buildkit minFreeSpace ${min_free}% > kubelet nodefs eviction ${pct}% (${f##*/})"
done

echo "All buildkit GC tests passed."
