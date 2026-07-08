# Windows / WSL2 Setup

[← Documentation](../../index.md)

Windows is supported via a dedicated WSL2 distro named `sandbox-vm`,
which plays the same role Lima plays on macOS: it isolates the k3s,
Cilium, and gVisor stack from any other Linux distro you already use.

## PowerShell version

`setup.ps1` works with **Windows PowerShell 5.1** (the default shell
on every Windows install) as well as **PowerShell 7+** (`pwsh`).
PowerShell 7 is recommended -- it reads source files as UTF-8 by
default, so any non-ASCII slip in our scripts can't mis-decode under
the ANSI codepage and produce confusing parser errors. Install it
with:

```powershell
winget install Microsoft.PowerShell
```

## Prerequisites

```powershell
# 1. WSL2 itself (one-time, requires reboot on a fresh install).
wsl --install

# 2. A source Ubuntu-24.04 distro to clone from (one-time).
#    Walk through its first-launch UNIX username/password prompts.
#    setup.ps1 reads it once via 'wsl --export' and otherwise never
#    touches it -- you can remove or keep it independently.
wsl --install -d Ubuntu-24.04
```

> **Behind a corporate TLS-intercepting proxy (Zscaler, Netskope,
> etc.)?** WSL distros don't inherit the Windows trust store, so the
> in-distro image build inside `.\setup.ps1` will fail on HTTPS unless
> the proxy root is staged first. You have two options:
>
> 1. **Stage the cert from Windows ahead of time** — paste the
>    PowerShell snippet from [Corporate TLS-intercept
>    proxies](../tls-intercept-proxies.md#doing-it-by-hand) into your
>    current PowerShell session, then run `.\setup.ps1`.
> 2. **Let `.\setup.ps1` fail at the build step** — it aborts early
>    with a clear error pointing at the in-distro helper. By that
>    point the `sandbox-vm` distro exists, so you can extract from
>    inside it (with automatic Windows-store fallback) and re-run:
>
>    ```powershell
>    wsl -d sandbox-vm --cd "$PWD" -- ./bin/sandbox setup-proxy-cert
>    .\setup.ps1
>    ```
>
> See [Corporate TLS-intercept proxies](../tls-intercept-proxies.md) for details.

> **WSL2 requires an explicit DNS resolver (`-Dns`).** WSL hands the
> distro a tunnel sentinel (`10.255.255.254`) for DNS that only answers
> in the host's network namespace. CoreDNS runs inside a pod namespace,
> where that address is a black hole — so without `-Dns`, every in-pod
> lookup times out and agents fail to reach their APIs. `setup.ps1`
> stops with a clear error until you name a resolver pods can actually
> reach. Pass a public resolver, or your organization's internal DNS IP
> if you need Tier 3 pods to resolve internal names. See [Windows/WSL2
> DNS](#windowswsl2-dns) below.

Provision and run:

```powershell
# 3. Run the Windows setup script from the agent-sandbox checkout.
#    Forwards the same flags as ./setup.sh on Linux/macOS.
#    -Dns is required on WSL2 (see the note above).
.\setup.ps1 -Dns 1.1.1.1,8.8.8.8
.\setup.ps1 -Dns 1.1.1.1,8.8.8.8 -PodCidr 172.16.128.0/17
.\setup.ps1 -Dns 1.1.1.1,8.8.8.8 -ApiserverPort 7443

# 4. Put the CLI on PATH for this session (and add to your $PROFILE
#    to make it permanent).
$env:Path = "$PWD\bin;$env:Path"

# 5. Smoke-test.
sandbox status

# 6. Launch a Tier 1 session.
sandbox run --agent claude --tier 1
```

Once you're past setup, the [first session tutorial](../../tutorials/first-session.md)
covers Tier 2/3 from step 4 on.

## If setup.ps1 fails partway through

The work it has already done is recoverable -- the PowerShell wrapper is a
convenience, not load-bearing. Its job is (a) clone Ubuntu-24.04 into a new
`sandbox-vm` distro, (b) enable systemd, (c) run `setup.sh` inside it.

If `setup.ps1` failed **after** the clone step (i.e. `wsl --list`
already shows `sandbox-vm`), finish the bash half by hand from any
shell:

```powershell
wsl -d sandbox-vm --cd "$PWD" -- ./setup.sh
```

If it failed **before** the clone step, the dedicated distro doesn't
exist yet -- re-run `setup.ps1` once the PowerShell-side issue is
fixed, or as a last resort run `setup.sh` directly inside your seed
`Ubuntu-24.04` distro (no dedicated-distro isolation, but everything
else works the same).

## Repo placement for Tier 2/3

Clone repos *inside* the `sandbox-vm` distro, not on a Windows drive.
`/mnt/c/...` paths cross the NTFS<->WSL filesystem boundary on every
syscall — git status and builds run 10-20x slower than on native ext4
inside the distro. The CLI refuses Windows paths with a clear error
directing you to clone inside the distro:

```powershell
wsl -d sandbox-vm -- bash -c 'git clone https://example/your.git ~/repos/your'
sandbox run --agent claude --tier 2 --repo ~/repos/your
```

To shell into the sandbox distro directly (debugging, manual `kubectl`,
etc.), use `wsl -d sandbox-vm`.

**Caveat:** all WSL2 distros on a Windows host share one kernel and one
lightweight utility VM, so the `sandbox-vm` isolation is at the userland/
rootfs layer — not a separate hypervisor VM the way Lima provides on
macOS. The security boundary that matters for sandboxed agents is still
gVisor at the container layer; the dedicated distro exists to keep
sandbox state from colliding with your everyday Linux work.

## Windows/WSL2 DNS

WSL2 hands the distro a DNS-tunnel sentinel (`10.255.255.254`) in
`/etc/resolv.conf` that WSL intercepts in the *host* network namespace.
That works fine for commands you run in the distro directly, but CoreDNS
runs inside a pod network namespace where the sentinel is unreachable —
so every cluster DNS lookup times out, and agents come up only to fail
reaching their APIs (`could not resolve host`, `FailedToOpenSocket`).
Bare Linux and macOS/Lima don't hit this; they get a pod-reachable
resolver from the host automatically.

The fix is to tell CoreDNS which resolver to use, with `-Dns`
(`--dns` for `setup.sh`). It's **required** on WSL2 — `setup.ps1` errors
out until you set it — and accepts a comma- or space-separated list:

```powershell
# A public resolver is the simplest choice for Tier 1/2 (the agent APIs
# are all public). Confirm it's reachable from the distro first:
wsl -d sandbox-vm -- dig @1.1.1.1 +short api.anthropic.com

.\setup.ps1 -Dns 1.1.1.1,8.8.8.8
```

If you need **Tier 3** pods to resolve *internal* names, a public
resolver won't see them — point `-Dns` at an internal DNS server your
pods can actually reach instead (the corporate resolver behind WSL's
tunnel sentinel is not one of them):

```powershell
.\setup.ps1 -Dns 10.20.30.40
```

The same flag works from bash as an opt-in override on any Linux host —
handy if a bare-Linux box behind its own split-DNS needs CoreDNS pinned
to a specific upstream:

```bash
./setup.sh --dns 10.20.30.40
```

`-Dns` is wired into the k3s install, so changing it means re-running
setup (it's not a live restart). On macOS it's ignored with a warning —
Lima handles DNS on its own.
