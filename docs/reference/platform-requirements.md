# Platform Requirements

[← Documentation](../index.md)

**macOS**: macOS 15 or later on Apple M3 or later, and [vfkit](https://github.com/crc-org/vfkit)
(`brew install vfkit`) for the default driver. `--driver lima` needs Lima
instead. The sandbox VM needs nested virtualization (Kata, the default
runtime, runs a microVM per session inside it; gVisor does not need it), which Apple's Virtualization framework offers on M3 and
later.

**Linux**: arm64 or x86_64, `qemu-system-<arch>` for the default driver, and
`/dev/kvm` with nested virtualization enabled; your user must be in the `kvm`
group. `--driver lima` needs Lima instead. Only the arm64 image has been tested
end to end so far (the qemu driver, a gVisor session, and the sync, on an arm64 Linux host). Your
home directory and the repositories you launch must not be in the VM's own system directories
(`/var`, `/usr`, `/etc`, `/tmp`, ...): the VM mirrors their paths. Homes in `/var/home/<user>`
(Fedora Atomic and its kin) are the exception and work.

**Windows**: not available in v3 yet. See [Windows](../how-to/platforms/windows.md).

**The VM**: at least 4 CPUs and 8 GiB of memory (defaults: the host's CPUs less
2, its memory less 6 GiB), and a 60 GiB disk by default. Everything else (Kata,
containerd, buildkit, Envoy, betterleaks) is in the appliance image; nothing is
installed on the host besides the `sandbox` binary.

**Building**: Go 1.27 for the host binary. The appliance image is built on
Linux as root with mkosi v27.1 and the tools in
[image/README.md](../../image/README.md); on a Mac, build it in a Linux Lima VM
with `image/build-in-lima.sh`.

**Agents on the host**: `claude` to make Claude Code's token (`claude
setup-token`), and `codex` for Codex's device login (`sandbox onboard --agent
codex`). See [Signing agents in](../how-to/onboarding-agents.md).
