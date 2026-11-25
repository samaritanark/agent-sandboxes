#!/usr/bin/env bash
# Build the v3 appliance image (design 5.3). Run on Linux as root, from the repository:
#   sudo image/build.sh [IMAGE_VERSION]
# Needs mkosi v27.1 (MKOSI, default /opt/mkosi/bin/mkosi: Ubuntu 24.04's packaged 20.2 cannot build
# a noble initrd, and v24.3's initrd differed between builds), systemd-ukify, dosfstools, mtools,
# qemu-utils, and Go:
#   python3 -m venv /opt/mkosi && /opt/mkosi/bin/pip install "git+https://github.com/systemd/mkosi@v27.1"
# Writes image/mkosi.output/sandbox-appliance.raw (the vfkit and qemu drivers) and .qcow2 (Lima).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${here}/.." && pwd)"
cd "${repo}"

# IMAGE_COMMIT and SOURCE_DATE_EPOCH may be given when the tree is not a git checkout.
commit="${IMAGE_COMMIT:-$(git rev-parse HEAD)}"
version="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
[[ "${version}" =~ ^[0-9A-Za-z.+_-]{1,64}$ ]] || { echo "invalid IMAGE_VERSION: ${version}" >&2; exit 1; }
# Reproducible content: every timestamp mkosi writes comes from the commit.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"

case "$(uname -m)" in
  aarch64) goarch=arm64 ;;
  x86_64) goarch=amd64 ;;
  *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
GO="${GO:-$(command -v go || echo /usr/local/go/bin/go)}"

stage="${here}/mkosi.extra"
lib="${stage}/usr/lib/sandbox"
rm -rf "${lib:?}/bin" "${lib:?}/config" "${lib:?}/setup" "${stage:?}/etc/sandbox"
install -d "${lib}/bin" "${lib}/setup" "${stage}/etc/sandbox"

# The in-VM sandbox: the Go policy layer, the command the host binary proxies to.
(cd go && CGO_ENABLED=0 GOOS=linux GOARCH="${goarch}" "${GO}" build -trimpath -buildvcs=false \
  -ldflags "-s -w -X main.version=${version} -X main.commit=${commit}" \
  -o "${lib}/bin/sandbox" ./cmd/sandbox-vm)
# What it reads from its install root (two levels above the binary).
cp -a config "${lib}/config"
cp -a setup/versions.sh "${lib}/setup/versions.sh"

printf 'IMAGE_VERSION=%s\nCONTROL_API=1\n' "${version}" > "${stage}/etc/sandbox/release"

# Packages come only from the lockfile (image/packages.<arch>.lock, owner decision 6): lock.py
# fetches each .deb, checks its SHA-256 against the lock, and writes a local repository that mkosi
# uses instead of Ubuntu's archive, so a rebuild installs exactly the locked packages.
# SANDBOX_IMAGE_UNLOCKED=1 builds from the live archive instead, only to regenerate the lock
# (see image/README.md); such an image is not reproducible.
lock="${here}/packages.${goarch}.lock"
mirror=()
if [[ "${SANDBOX_IMAGE_UNLOCKED:-}" == 1 ]]; then
  echo "WARNING: unlocked build from the live archive; this image is not reproducible." >&2
else
  [[ -f "${lock}" ]] || { echo "no package lock ${lock} (see image/README.md)" >&2; exit 1; }
  repo="${here}/mkosi.cache/locked-${goarch}"
  python3 -I "${here}/lock.py" repo --lock "${lock}" --out "${repo}"
  mirror=(--local-mirror "file://${repo}")
fi

cd "${here}"
"${MKOSI:-/opt/mkosi/bin/mkosi}" --force "${mirror[@]}" build
qemu-img convert -f raw -O qcow2 mkosi.output/sandbox-appliance.raw mkosi.output/sandbox-appliance.qcow2
ls -l mkosi.output/
