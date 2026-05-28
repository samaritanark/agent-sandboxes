# Extra Trusted Root CAs

Drop PEM-encoded root CA certificates (`*.crt`) into this directory. They
are baked into `sandbox:base` during image build via `update-ca-certificates`,
so every derived agent image — and every running sandbox pod — trusts them.

## When you need this

If your organization runs a TLS-intercepting egress proxy (Zscaler, Netskope,
Forcepoint, Cisco Umbrella, Palo Alto Prisma, Symantec/Blue Coat, an internal
MITM appliance, etc.), the sandbox image build and the running agents will
fail TLS validation against the re-signed certs unless their root CA is in
the image's trust store. Symptom during build:

```
curl: (60) SSL certificate problem: unable to get local issuer certificate
```

Symptom at runtime: the agent (claude/codex/opencode) fails to authenticate
or `npm install` / `pip install` / `git clone` inside the sandbox can't
reach their registries.

## How to get the cert

The easiest way is to run the helper:

```bash
sandbox setup-proxy-cert
```

That auto-detects your platform and writes the cert directly into this
directory. See `sandbox setup-proxy-cert --help` for options
(`--from-wire <host>`, `--vendor <name>`, `--list`).

If you want to do it by hand, see the "Corporate TLS-intercept proxies"
section in the top-level `README.md` for platform-specific one-liners.

## After dropping a cert in

Rebuild the images so the new trust takes effect:

```bash
sandbox rebuild        # or `sandbox setup` on a fresh install
```

## Notes

- Files must be PEM-encoded with a `.crt` extension. DER (`.cer`) is not
  picked up by `update-ca-certificates` — convert with
  `openssl x509 -inform DER -in foo.cer -out foo.crt`.
- The certs themselves are gitignored — your org's MITM root is unique to
  your environment and shouldn't be committed.
