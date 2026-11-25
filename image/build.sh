#!/usr/bin/env bash
# Build the v3 appliance image (design 5.3). Run on Linux as root, from the repository:
#   sudo image/build.sh [IMAGE_VERSION]
# Needs mkosi v24.3 (MKOSI, default /opt/mkosi/bin/mkosi: Ubuntu 24.04's packaged 20.2 cannot build
# a noble initrd), systemd-ukify, dosfstools, mtools, qemu-utils, and Go:
#   python3 -m venv /opt/mkosi && /opt/mkosi/bin/pip install "git+https://github.com/systemd/mkosi@v24.3"
# Writes image/mkosi.output/sandbox-appliance.raw (Lima vz) and .qcow2 (Lima qemu).
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

cd "${here}"
"${MKOSI:-/opt/mkosi/bin/mkosi}" --force build
qemu-img convert -f raw -O qcow2 mkosi.output/sandbox-appliance.raw mkosi.output/sandbox-appliance.qcow2
ls -l mkosi.output/
