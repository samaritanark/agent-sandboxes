#!/usr/bin/env bash
# Build a dev appliance image in a Linux Lima VM from this checkout, and copy it here.
#   image/build-in-lima.sh [LIMA_VM] [IMAGE_VERSION] [OUT]
# LIMA_VM defaults to v3-spike (Ubuntu 24.04 with mkosi v27.1 in /opt/mkosi and Go in
# /usr/local/go; see image/build.sh). The tracked files of go/, config/, image/, and docker/ are
# copied to /var/tmp/imgbuild in the VM, so uncommitted changes to tracked files are included and
# untracked files are not. OUT defaults to ./sandbox-appliance.raw.
set -euo pipefail
vm="${1:-v3-spike}"
version="${2:-3.0.0-dev.$(date -u +%Y%m%d%H%M)}"
out="${3:-./sandbox-appliance.raw}"
repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "${repo}"
limactl shell "${vm}" -- bash -lc 'sudo mkdir -p /var/tmp/imgbuild && sudo rm -rf /var/tmp/imgbuild/go /var/tmp/imgbuild/config /var/tmp/imgbuild/docker /var/tmp/imgbuild/image/mkosi.extra'
git ls-files go config image docker | tar -cf - -T - | limactl shell "${vm}" -- bash -lc "cd /var/tmp/imgbuild && sudo tar -xf - && sudo env -u SUDO_UID -u SUDO_GID -u SUDO_USER -u SUDO_COMMAND HOME=/root PATH=/usr/local/go/bin:\$PATH IMAGE_COMMIT=$(git rev-parse HEAD) SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) nice -n 10 image/build.sh ${version} > /var/tmp/imgbuild.log 2>&1 || { tail -20 /var/tmp/imgbuild.log; exit 1; }"
limactl shell "${vm}" -- sudo cat /var/tmp/imgbuild/image/mkosi.output/sandbox-appliance.raw > "${out}"
echo "Built ${version}: ${out}"
