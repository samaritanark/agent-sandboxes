# Documentation

Sandboxed execution environment for AI coding agents. Start with the
[README](../README.md) for what this is and a quick start; the pages below go
deeper. These pages describe v3 (the `v3` branch): agents in Kata microVMs (or gVisor
sandboxes, your choice per session) inside an appliance VM, with a credential
broker and a per-session gateway.

Before you operate this for anyone but yourself, read **[PRINCIPLES.md](../PRINCIPLES.md)**:
what the sandbox defends against, what it doesn't, and your accountability as
the operator.

## Tutorials: learning by doing

- [Your first session](tutorials/first-session.md): install, sign an agent in, then Tier 1, 2, and 3.
- [Deploy an MCP dependency](tutorials/mcp-dependency.md): box an MCP server into a session and confirm it's contained.

## How-to guides: a specific goal

- [Install the sandbox VM](how-to/installing.md)
- [Upgrade from v2](how-to/upgrading-from-v2.md)
- [Sign agents in (Claude Code, Codex, OpenCode)](how-to/onboarding-agents.md)
- [Persistent extra domains & personal block list](how-to/persistent-domains.md)
- [Egress (L7) rules](how-to/egress-rules.md)
- [Profiles and team overlays](how-to/profiles-and-overlays.md)
- [Store and bind secrets](how-to/secrets.md)
- [Vet repos for agent use](how-to/vetting.md)
- [Accept secret-gate false positives](how-to/secret-exceptions.md)
- [MCP & service dependencies](how-to/mcp-and-dependencies.md)
- [Tier 3 infra credentials](how-to/tier3-infra-credentials.md)
- [Resume and keep-alive sessions](how-to/resuming-sessions.md)
- [Kata or gVisor](how-to/runtimes.md)
- [Clusters and hosts behind a corporate VPN](how-to/corporate-vpn.md)
- [Corporate TLS-intercept proxies (Zscaler, Netskope…)](how-to/tls-intercept-proxies.md)
- [Rebuild agent images](how-to/rebuilding-images.md)
- [Update the sandbox](how-to/updating-the-cli.md)
- [Run the tests](how-to/running-tests.md)
- [Uninstall](how-to/uninstalling.md)
- [Windows](how-to/platforms/windows.md) (not available in v3 yet)

## Reference: look it up

- [CLI reference](reference/cli.md): every subcommand and flag.
- [Agents & tiers](reference/agents-and-tiers.md): supported agents, allowlists, the tier model.
- [Configuration](reference/configuration.md): `config.yaml` keys and precedence.
- [Audit logs](reference/audit-logs.md): what's recorded and where.
- [Platform requirements](reference/platform-requirements.md)

## Explanation: why it works this way

- [Security model](explanation/security-model.md): microVM isolation, the gateway and broker, the sync gate.
- [Architecture](explanation/architecture.md): the host binary, the appliance VM, sandboxd, and the gateway.
- [How this compares](explanation/comparisons.md): Apple Containers, Docker, hosted sandboxes.
- [PRINCIPLES.md](../PRINCIPLES.md): design intent and threat model (canonical).
- Design records: [v3 architecture](design/v3-architecture.md) and the spike records in [design/spikes/](design/spikes/).

## Something's wrong

- [Troubleshooting](explanation/troubleshooting.md): common runtime and install failures.
