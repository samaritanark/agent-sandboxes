# Documentation

Sandboxed execution environment for AI coding agents. Start with the
[README](../README.md) for what this is and a first session; the pages below go
deeper.

Before you operate this for anyone but yourself, read **[PRINCIPLES.md](../PRINCIPLES.md)** —
what the sandbox defends against, what it doesn't, and your accountability as
the operator.

## Tutorials — learning by doing

- [Your first session](tutorials/first-session.md) — install, then Tier 1 → 2 → 3.
- [Deploy an MCP dependency](tutorials/mcp-dependency.md) — box an MCP server into a session and confirm it's contained.

## How-to guides — a specific goal

- [Persistent extra domains & personal block list](how-to/persistent-domains.md)
- [Profiles and team overlays](how-to/profiles-and-overlays.md)
- [Store and inject secrets](how-to/secrets.md)
- [Vet repos for agent use](how-to/vetting.md)
- [MCP & service dependencies](how-to/mcp-and-dependencies.md)
- [Tier 3 infra credentials](how-to/tier3-infra-credentials.md)
- [Resume and keep-alive sessions](how-to/resuming-sessions.md)
- [Reach clusters behind a corporate VPN (Linux)](how-to/corporate-vpn.md)
- [Corporate TLS-intercept proxies (Zscaler, Netskope…)](how-to/tls-intercept-proxies.md)
- [Rebuild agent images](how-to/rebuilding-images.md)
- [Update the CLI to the latest release](how-to/updating-the-cli.md)
- [Upgrade infrastructure (k3s / Cilium / gVisor)](how-to/upgrading-infra.md)
- [Run the tests](how-to/running-tests.md)
- [Uninstall](how-to/uninstalling.md)
- [Windows / WSL2 setup](how-to/platforms/windows.md)

## Reference — look it up

- [CLI reference](reference/cli.md) — every subcommand, flags, diagnostics, session naming/IDs.
- [Agents & tiers](reference/agents-and-tiers.md) — supported agents, allowlists, the tier model.
- [Configuration](reference/configuration.md) — `config.yaml` keys and precedence.
- [Audit logs](reference/audit-logs.md) — what's recorded and where.
- [Platform requirements](reference/platform-requirements.md)

## Explanation — why it works this way

- [Security model](explanation/security-model.md) — isolation, egress, filesystem masking, the secret gate.
- [Architecture notes](explanation/architecture.md) — macOS sync, CIDRs, API port, quotas, gVisor+Cilium routing.
- [How this compares](explanation/comparisons.md) — Apple Containers, Docker, hosted sandboxes.
- [PRINCIPLES.md](../PRINCIPLES.md) — design intent and threat model (canonical).

## Something's wrong

- [Troubleshooting](explanation/troubleshooting.md) — common runtime and install failures.
