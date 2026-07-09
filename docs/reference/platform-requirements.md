# Platform Requirements

[← Documentation](../index.md)

**Linux**: k3s, gVisor, Cilium, kubectl, helm, jq, xxd, sha256sum,
curl, git. Also betterleaks (the Tier 2/3 pre-launch secret gate fails
closed without it) — `sandbox setup` installs the pinned version
(`setup/versions.sh`) if it is missing or older, so it is not a manual
prerequisite.

**macOS**: Lima (`brew install lima`) — provisions an Ubuntu 24.04 VM
with identical stack

**Windows**: WSL2 (`wsl --install`) plus an installed Ubuntu-24.04 distro
(`wsl --install -d Ubuntu-24.04`) used as a one-time seed. See the
[Windows / WSL2 setup](../how-to/platforms/windows.md) guide.
