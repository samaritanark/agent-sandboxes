# The appliance image

The v3 appliance VM's disk (design 5.3): Ubuntu 24.04 built by mkosi from `mkosi.conf`, with the
in-VM `sandbox` and its configuration staged by `build.sh`.

## Building

On Linux, as root, from the repository (the output is for the build machine's architecture):

    sudo image/build.sh [IMAGE_VERSION]

It needs mkosi v27.1 at `/opt/mkosi` (or `MKOSI=`), systemd-ukify, systemd-boot (bootctl),
dosfstools, mtools, qemu-utils, dpkg, Python 3, and Go. It writes `mkosi.output/sandbox-appliance.raw` (the vfkit and qemu drivers)
and `.qcow2` (Lima).

## The package lock

Every package the image and its initrd install is pinned in `packages.<arch>.lock`: name,
version, architecture, SHA-256, size, and archive path. `build.sh` runs `lock.py repo`, which
fetches each `.deb` (from the Ubuntu archive, or from Launchpad's permanent file URLs once the
archive has dropped a superseded version), refuses any whose size or hash differs from the lock,
and writes a local repository that mkosi installs from instead of the archive. Nothing else is
installed, so a rebuild installs the same bytes.

To update the packages (for security updates, or after changing `Packages=` in `mkosi.conf`):

    # 1. an unlocked build from the live archive, with an empty package cache
    sudo rm -rf image/mkosi.cache/packages
    sudo SANDBOX_IMAGE_UNLOCKED=1 image/build.sh
    # 2. the names it installed, resolved for both architectures against Ubuntu's signed indexes
    sudo python3 -I image/lock.py names image/mkosi.cache/packages > /tmp/names.txt
    python3 -I image/lock.py resolve --arch arm64 /tmp/names.txt > image/packages.arm64.lock
    python3 -I image/lock.py resolve --arch amd64 /tmp/names.txt > image/packages.amd64.lock
    # 3. a locked build, which must succeed, then review the lock diff like any other change
    sudo image/build.sh

Review the lock diff: every changed line is a package that changes in the image.
