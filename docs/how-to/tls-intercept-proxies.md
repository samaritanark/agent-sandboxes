# Corporate TLS-Intercept Proxies (Zscaler, Netskope, etc.)

[← Documentation](../index.md)

If your laptop egresses through a TLS-intercepting proxy — Zscaler is
the common case, also Netskope, Forcepoint, Cisco Umbrella, Palo Alto
Prisma, internal MITM appliances — the sandbox image build and the
running agents will fail TLS validation against the re-signed certs
unless the proxy's root CA is trusted inside the sandbox image.

Symptom during the image build (most often hit on **first-time
`./setup.sh`**):

```
curl: (60) SSL certificate problem: unable to get local issuer certificate
```

Symptom at runtime: `claude` / `codex` / `opencode` failing to
authenticate, or `npm install` / `pip install` / `git clone` inside a
sandbox failing to reach its registry.

`./setup.sh` runs a TLS probe before the image build and aborts early
with a pointer here if it sees interception, so you don't lose a build
to it.

## Fix

Drop the proxy's root CA into `config/extra-ca-certs/` as a PEM `.crt`
file, then run (or re-run) setup:

```bash
./setup.sh             # first-time install
sandbox rebuild        # already installed, refreshing the images
```

`Dockerfile.base` copies anything in `config/extra-ca-certs/` into the
image's trust store via `update-ca-certificates`. Because all the agent
images (`:claude`, `:codex`, `:opencode`, `:shell`, `:*-infra`) derive
from `:base`, the same trust applies inside every running pod — one
fix, build-time and runtime.

## Getting the cert

The repo ships a helper that auto-extracts the cert from the host. It
runs straight out of the checkout (no PATH setup needed) so you can use
it during a first-time install before the `sandbox` CLI is on PATH:

```bash
./bin/sandbox setup-proxy-cert        # first time, before setup.sh
sandbox setup-proxy-cert              # already installed
```

It writes `config/extra-ca-certs/proxy-ca.crt` and tells you what to
do next. Behavior by platform:

- **Linux**: scans `/usr/local/share/ca-certificates/` and the system
  bundle for certs whose Subject matches known proxy-vendor names.
- **macOS**: queries the System keychain via the `security` command.
- **WSL2**: tries the Linux distro store first; if empty, falls back to
  the Windows `LocalMachine\Root` store via `powershell.exe` (which is
  always on PATH inside WSL). This handles the common case where the
  corporate root was installed only on Windows, not in the distro.

Useful flags (see `./bin/sandbox setup-proxy-cert --help`):

- `--vendor <substring>` — Subject filter when your org's CA doesn't
  match the built-in vendor list (Zscaler, Netskope, Forcepoint, Cisco
  Umbrella, Palo Alto/Prisma, Symantec/Blue Coat, iboss, Menlo).
- `--from-wire <host[:port]>` — last-resort extraction by opening a
  TLS connection to a known-public host (e.g. `deb.nodesource.com`)
  and capturing whatever proxy chain the network actually presents.
  Useful when nothing matches in the trust store.
- `--list` — print what was found without writing the file.

## Doing it by hand

If `setup-proxy-cert` doesn't fit (e.g. you already know the cert
location), the equivalent one-liners are:

```bash
# Linux — IT often pre-installs corporate roots here:
cp /usr/local/share/ca-certificates/Zscaler*.crt config/extra-ca-certs/

# macOS — System keychain via the Security framework CLI:
security find-certificate -a -c Zscaler -p /Library/Keychains/System.keychain \
  > config/extra-ca-certs/zscaler.crt
```

```powershell
# Windows — run in PowerShell BEFORE setup.ps1, since WSL doesn't inherit
# the Windows trust store:
Get-ChildItem Cert:\LocalMachine\Root |
  Where-Object { $_.Subject -like '*Zscaler*' } |
  ForEach-Object {
    $b64 = [Convert]::ToBase64String($_.RawData, 'InsertLineBreaks')
    "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----"
  } | Out-File -Encoding ascii config\extra-ca-certs\zscaler.crt
```

The certs themselves are gitignored — your org's MITM root is unique to
your environment and shouldn't be committed.
