# Corporate TLS-Intercept Proxies (Zscaler, Netskope, etc.)

[← Documentation](../index.md)

If your machine egresses through a TLS-intercepting proxy (Zscaler is the common case, also
Netskope, Forcepoint, Cisco Umbrella, Palo Alto Prisma, internal MITM appliances), connections from
the sandbox VM and its sessions fail TLS validation against the re-signed certificates unless the
proxy's root CA is trusted there.

Symptoms: `sandbox rebuild` failing to download packages
(`curl: (60) SSL certificate problem: unable to get local issuer certificate`), agents failing to
reach their APIs, or `npm install` / `pip install` / `git clone` failing inside a session.

## Fix

Save the proxy's root CA into `~/.sandbox/extra-ca-certs/` (a PEM `.crt` or `.pem` file), before
you install the sandbox VM:

```bash
sandbox setup-proxy-cert      # finds it in your machine's trust store and saves it
sandbox install ...           # the VM trusts it from the start
```

v2 baked the CA into the agent images at build time. v3 delivers it at runtime instead, so the
images are the same everywhere and no rebuild is needed for a new CA:

- the sandbox VM itself trusts it (for `sandbox rebuild`'s downloads and the gateway's own
  upstream connections);
- every session gets one trust bundle (the system roots, your CAs, and the session gateway's
  certificate authority) read-only under `/etc/ssl/sandbox/`, with `SSL_CERT_FILE`,
  `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `PIP_CERT`, `GIT_SSL_CAINFO`, and
  `NODE_EXTRA_CA_CERTS` pointing at it.

**In this build the VM takes the CAs in `~/.sandbox/extra-ca-certs/` when it is installed.** A CA
you add later reaches the VM and its sessions only after the VM is installed again:
`sandbox uninstall` (answer `n` to keep each kind of state; never `--purge` while you use v2 on the
same machine), then `sandbox install` again. (`setup-proxy-cert`'s closing message says "from the
next session"; that is the design's intent, not yet what this build does.) The repository's
`config/extra-ca-certs/` and an overlay's `extra-ca-certs/` are not read yet either; put the CA in
`~/.sandbox/extra-ca-certs/`.

## Getting the cert

`sandbox setup-proxy-cert` runs on your machine and writes `~/.sandbox/extra-ca-certs/proxy-ca.crt`:

- **Linux**: scans `/usr/local/share/ca-certificates/` and the system bundle for certificates whose
  subject matches known proxy vendors.
- **macOS**: queries the System keychain.
- **Windows**: the `LocalMachine\Root` and `CurrentUser\Root` stores.

Options (`sandbox setup-proxy-cert --help`):

- `--vendor <name>`: the subject substring to match when your org's CA is not in the built-in
  list (Zscaler, Netskope, Forcepoint, Cisco Umbrella, Palo Alto/Prisma, Symantec/Blue Coat,
  iboss, Menlo).
- `--from-wire <host[:port]>`: last resort; opens a TLS connection to a public host (for example
  `deb.nodesource.com`) and saves the proxy chain the network presents.
- `--output <path>`: write elsewhere.
- `--list`: print what was found without writing.
- `--force`: overwrite an existing file without asking.

## Doing it by hand

```bash
# Linux: IT often pre-installs corporate roots here
cp /usr/local/share/ca-certificates/Zscaler*.crt ~/.sandbox/extra-ca-certs/

# macOS: the System keychain
security find-certificate -a -c Zscaler -p /Library/Keychains/System.keychain \
  > ~/.sandbox/extra-ca-certs/zscaler.crt
```

Your org's root is specific to your environment; keep it out of any repository.
