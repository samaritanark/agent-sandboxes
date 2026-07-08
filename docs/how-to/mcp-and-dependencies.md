# MCP & Service Dependencies

[← Documentation](../index.md)

Some work needs the agent to reach a tool or service that isn't a website on
the allowlist — an **MCP server** (a process that advertises tools the agent
can call, like browser automation or a ticket-system bridge), or a plain
**service** the session talks to directly (a dev database, a message broker).
A profile can declare those, and the sandbox brings each one up as its **own
locked-down pod** for the life of the session, then tears it down.

The rule the whole feature rests on: **a dependency gets no more network reach
than the session pod has.** Each dependency runs under gVisor like everything
else, carries its own CiliumNetworkPolicy that is a clone-or-subset of the
session's egress (default-deny, the same blocked-CIDR backstop, DNS scoped to
the same allowlist), accepts traffic **only** from its owning session, mounts
no workspace and no host path, and holds no long-lived credentials. Adding a
dependency adds capability, not an exit the session didn't already have.

Dependencies are not free-form YAML a user writes inline. They come from a
**catalogue** of vetted entries — an image (pinned to a `@sha256:` digest, never
a mutable tag), a port, an egress allowlist, resource limits, and any secrets it
needs. You select an entry by name; you don't describe a workload. Org entries
live in `config/catalogue/`; a team overlay may add more under
`<overlay>/catalogue/` (additive only — an overlay can never override or widen
an org entry).

```yaml
# config/catalogue/example-mcp.yaml   (an MCP server)
name: example-mcp
kind: mcp                              # mcp | service
image: ghcr.io/example-org/example-mcp@sha256:<64hex>
port: 8080
mcp_transport: http                    # http | sse — how the agent connects
mcp_path: /mcp
egress:                                # the dependency's OWN egress (443). Omit
  - example-api.internal.example.com #   entirely for a DNS-only dependency.
secrets:                               # provisioned from the host-side store
  - INNKEEPER_TOKEN                    #   (see Secret store), session-scoped
```

A profile then asks for it by name. `mcps:` entries are registered with the
agent (it can call their tools); `services:` entries are reachable by the
session but not registered as agent tools:

```yaml
# ~/.sandbox/profiles/example-dev.yaml
tier: 2
agent: claude          # MCP registration is wired for claude today; declaring
                       #   mcps for another agent fails the launch, by design
mcps:
  - example-mcp
services:
  - dev-postgres
```

At `sandbox run`, once the session pod is ready and its per-session network
identity is verified, each dependency is created (pod + Service + policy, all
labelled with the session and owned by it), the agent's MCP config is written to
point at the in-cluster Service URL, and the session's policy is extended with a
single rule to reach each one. If any dependency fails to come up the launch is
aborted and torn down — a profile asked for it for a reason. Everything is
reaped at `sandbox stop` (by owner reference, with a label-keyed sweep as
backstop), and each dependency's resolved version, egress allowlist, and
up/down times are written to the session's audit record.

> **A browser is the hard case.** A Playwright MCP is a general-purpose egress
> engine, so it's only safe under a specific shape (separate pod, QUIC/DoH off,
> `--no-sandbox` but never added capabilities, signature-verified image, no
> mounts). The catalogue supports it as a `class: browser` entry, and the design
> reasoning lives in `docs/design/phase5-mcp-dependencies.md`. Even fully
> contained it widens the in-allowlist exfil surface, which the CLI warns about
> at launch — enable it deliberately.

**New here?** The [MCP dependency tutorial](../tutorials/mcp-dependency.md) is a
hands-on walkthrough that deploys a real MCP server (the official reference
"everything" server) into a session, has the agent call one of its tools, and
shows you how to confirm the sandbox actually boxed it in.
