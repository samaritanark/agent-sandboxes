# Platform Requirements

[← Documentation](../index.md)

**Linux**: k3s, gVisor, Cilium, kubectl, helm, jq, xxd, sha256sum,
curl, git. Also nerdctl + buildkit (the image builder — `sandbox setup`
installs the pinned `nerdctl-full` release and wires buildkit to k3s's
containerd, so **no host Docker or Podman is required**) and betterleaks
(the Tier 2/3 pre-launch secret gate fails closed without it). Both are
installed from the pins in `setup/versions.sh` if missing, so neither is a
manual prerequisite.

**macOS**: Lima (`brew install lima`) — provisions an Ubuntu 24.04 VM
with identical stack

**Windows**: WSL2 (`wsl --install`) plus an installed Ubuntu-24.04 distro
(`wsl --install -d Ubuntu-24.04`) used as a one-time seed. See the
[Windows / WSL2 setup](../how-to/platforms/windows.md) guide.
