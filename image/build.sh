#!/usr/bin/env bash
# Build the v3 appliance image (design 5.3). Run on Linux as root, from the repository:
#   sudo image/build.sh [IMAGE_VERSION]
# Needs mkosi v27.1 (MKOSI, default /opt/mkosi/bin/mkosi: Ubuntu 24.04's packaged 20.2 cannot build
# a noble initrd, and v24.3's initrd differed between builds), systemd-ukify, systemd-boot
# (bootctl), dosfstools, mtools, qemu-utils, dpkg, Python 3, and Go:
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
# sandboxd, the session supervisor (design 5.4.3), a root systemd service.
(cd go && CGO_ENABLED=0 GOOS=linux GOARCH="${goarch}" "${GO}" build -trimpath -buildvcs=false \
  -ldflags "-s -w" -o "${lib}/bin/sandboxd" ./cmd/sandboxd)
# Each session's egress gateway (design 5.8): the resolver, the connection check, and Envoy's parent.
(cd go && CGO_ENABLED=0 GOOS=linux GOARCH="${goarch}" "${GO}" build -trimpath -buildvcs=false \
  -ldflags "-s -w" -o "${lib}/bin/sandbox-gateway" ./cmd/sandbox-gateway)
# What it reads from its install root (two levels above the binary).
cp -a config "${lib}/config"
cp -a setup/versions.sh "${lib}/setup/versions.sh"
# v2's agent image Dockerfiles, which `sandbox rebuild` builds in the VM.
rm -rf "${lib:?}/docker"
cp -a docker "${lib}/docker"

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

# The runtime (design 5.3.1, 5.5): containerd, runc, nerdctl, and buildkit from nerdctl-full, and Kata
# with Cloud Hypervisor from kata-go-static (S1: kata-static holds only the Rust shim), each fetched
# and checked against image/artifacts.lock. Only what the image uses is unpacked: no QEMU,
# Firecracker, rootless or stargz tools, or GPU and confidential guest images.
art="${here}/mkosi.cache/artifacts-${goarch}"
python3 -I "${here}/lock.py" artifacts --lock "${here}/artifacts.lock" --arch "${goarch}" --out "${art}"
tree="${here}/mkosi.cache/runtime-tree-${goarch}"
unpack="$(mktemp -d /var/tmp/sandbox-unpack.XXXXXX)"
trap 'rm -rf "${unpack}"' EXIT
rm -rf "${tree}"
install -d "${tree}/opt/kata/bin" "${tree}/opt/kata/libexec" "${tree}/opt/kata/share/defaults/kata-containers" \
  "${tree}/opt/kata/share/kata-containers" "${tree}/usr/local/bin" "${tree}/usr/local/lib/systemd/system" \
  "${tree}/opt/cni/bin"

install -d "${unpack}/kata"
tar -I zstd -C "${unpack}/kata" -xf "${art}"/kata-go-static-*-"${goarch}".tar.zst
k="${unpack}/kata/opt/kata"
cp -a "${k}/VERSION" "${tree}/opt/kata/"
cp -a "${k}/bin/cloud-hypervisor" "${k}/bin/containerd-shim-kata-v2" "${tree}/opt/kata/bin/"
cp -a "${k}/libexec/virtiofsd" "${tree}/opt/kata/libexec/"
cp -a "${k}/share/defaults/kata-containers/configuration-clh.toml" "${tree}/opt/kata/share/defaults/kata-containers/"
for link in vmlinux.container kata-containers.img; do # the links the configuration names, and their targets
  target="$(readlink "${k}/share/kata-containers/${link}")"
  [[ "${target}" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "unexpected Kata link ${link} -> ${target}" >&2; exit 1; }
  cp -a "${k}/share/kata-containers/${link}" "${k}/share/kata-containers/${target}" "${tree}/opt/kata/share/kata-containers/"
done
# Guest seccomp is off in the shipped configuration; design 5.5.2 requires it on.
clh="${tree}/opt/kata/share/defaults/kata-containers/configuration-clh.toml"
sed -i 's/^disable_guest_seccomp = true$/disable_guest_seccomp = false/' "${clh}"
grep -qx 'disable_guest_seccomp = false' "${clh}" || { echo "cannot enable guest seccomp in ${clh}" >&2; exit 1; }
# containerd finds the runtime io.containerd.kata.v2 as containerd-shim-kata-v2 on its PATH.
ln -s /opt/kata/bin/containerd-shim-kata-v2 "${tree}/usr/local/bin/containerd-shim-kata-v2"

install -d "${unpack}/nerdctl"
tar -C "${unpack}/nerdctl" -xzf "${art}"/nerdctl-full-*-linux-"${goarch}".tar.gz
n="${unpack}/nerdctl"
for b in containerd containerd-shim-runc-v2 ctr runc nerdctl buildkitd buildctl; do
  cp -a "${n}/bin/${b}" "${tree}/usr/local/bin/"
done
cp -a "${n}/lib/systemd/system/containerd.service" "${n}/lib/systemd/system/buildkit.service" \
  "${tree}/usr/local/lib/systemd/system/"
# The CNI plugins design 5.8 names (ptp, bridge, firewall) and the IPAM and loopback they need.
for p in ptp bridge firewall host-local static loopback; do
  cp -a "${n}/libexec/cni/${p}" "${tree}/opt/cni/bin/"
done
# Envoy, each session's gateway data plane (design 5.8.4; owner decision: the official static
# release, pinned like Kata).
envoy_bin="$(ls "${art}"/envoy-*-linux-* 2>/dev/null | head -1)"
[[ -n "${envoy_bin}" ]] || { echo "no Envoy artifact for ${goarch}" >&2; exit 1; }
install -m 0755 "${envoy_bin}" "${tree}/usr/local/bin/envoy"

# betterleaks, the secret scanner the in-VM gates run before every tier 2 and 3 launch (v2's pin).
install -d "${unpack}/betterleaks"
tar -C "${unpack}/betterleaks" -xzf "${art}"/betterleaks_*_linux_*.tar.gz betterleaks
install -m 0755 "${unpack}/betterleaks/betterleaks" "${tree}/usr/local/bin/betterleaks"

# Fixed owner and times, so the tree is the same on every build.
chown -R -h root:root "${tree}"
find "${tree}" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

cd "${here}"
"${MKOSI:-/opt/mkosi/bin/mkosi}" --force "${mirror[@]}" --extra-tree "${tree}" build
qemu-img convert -f raw -O qcow2 mkosi.output/sandbox-appliance.raw mkosi.output/sandbox-appliance.qcow2
ls -l mkosi.output/
