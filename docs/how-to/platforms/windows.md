# Windows

[← Documentation](../../index.md)

**v3 is not available on Windows yet.** v2 ran on Windows in a dedicated WSL2
distro; v3 runs its agents in Kata microVMs inside an appliance VM, which on
Windows needs nested virtualization exposed to that VM through Hyper-V. Whether
and how that works (a Hyper-V driver or Lima's `hcs` driver) is the open spike
S3 in the [v3 design](../../design/v3-architecture.md), and Windows support is
planned for a release after v3.0.0.

What exists for Windows today:

- The host binary builds for Windows and would keep the credential broker's key
  in the Windows Credential Manager; it has not been run on Windows.
- No VM driver has been made or tested for Windows, so `sandbox install` does
  not create a working sandbox VM there.

Until then, use v2 on Windows (the `master` branch, and its
[Windows / WSL2 guide](https://github.com/samaritanark/agent-sandboxes/blob/master/docs/how-to/platforms/windows.md)),
or a Linux or macOS machine for v3.
