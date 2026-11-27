# MCP & Service Dependencies

[← Documentation](../index.md)

Some work needs the agent to reach a tool or service that isn't a website on
the allowlist — an **MCP server** (a process that advertises tools the agent
can call, like browser automation or a ticket-system bridge), or a plain
**service** the session talks to directly (a dev database, a message broker).
A profile can declare those, and the sandbox brings each one up as its **own
microVM** for the life of the session, then tears it down. A dependency that exits is not restarted (v2's pods were):
the agent sees it gone until the next session.

The rule the whole feature rests on: **a dependency gets no more network reach than the
session has.** In v3 each dependency is its own Kata microVM (a gVisor sandbox in a `--runtime gvisor` session) with its own link to the session's
gateway. Its egress is its catalogue entry's allowlist, checked against the same block lists; it
mounts no workspace and no host path; the agent reaches it only through the gateway, at
`<name>.deps.sandbox.internal:<port>`, and it cannot reach the agent, the other dependencies, or
other sessions. Each connection to it is in the session's flow log (`sandbox flows`). Adding a
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
args: [node, dist/sse.js]              # optional: after the image's entrypoint
secrets:                               # from the host-side store (see Secret store),
  - INNKEEPER_TOKEN                    #   brokered toward the entry's egress hosts
```

`command:` replaces the image's entrypoint and `args:` its default command, as in Kubernetes. A
secret a dependency declares is a placeholder in its environment that the gateway replaces toward
the hosts its binding names (and that its egress reaches); a dependency cannot be given a readable
secret.

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

At `sandbox run` (`==> Profile dependencies: ...`), each dependency's microVM is started with the
session, before the agent's. For MCP servers the agent's MCP configuration is written for the
session, naming each server at its address through the gateway
(`http://<name>.deps.sandbox.internal:<port><mcp_path>`), mounted read-only at
`/home/agent/.sandbox-mcp/config.json`, and Claude Code is started with
`--mcp-config /home/agent/.sandbox-mcp/config.json --strict-mcp-config`, so it registers those
servers and nothing else. If a dependency fails to start, the launch fails and everything is torn
down. Everything goes at `sandbox stop` (or when the session ends), and each dependency's image and
up and down times are in the session's audit record. (`sandbox resume` does not add the MCP flags,
as in v2.)

> **A browser is the hard case.** A Playwright MCP is a general-purpose egress
> engine, so it's only safe under a specific shape (its own microVM, QUIC/DoH off,
> `--no-sandbox` but never added capabilities, signature-verified image, no
> mounts). The catalogue supports it as a `class: browser` entry. Even fully
> contained it widens the in-allowlist exfil surface, which the CLI warns about
> at launch — enable it deliberately.

**New here?** The [MCP dependency tutorial](../tutorials/mcp-dependency.md) is a
hands-on walkthrough that deploys a real MCP server (the official reference
"everything" server) into a session, has the agent call one of its tools, and
shows you how to confirm the sandbox actually boxed it in.
