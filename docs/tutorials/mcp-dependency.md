<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Samaritan's Purse -->

# Tutorial: run a real MCP server inside a sandbox

This walkthrough deploys a **real** MCP server alongside a sandbox session, has the agent call one
of its tools, and shows you how to confirm the sandbox boxed the server in. It doubles as a gentle
intro to MCP if the term is new to you. Plan on about 15 minutes.

Everything here uses the official Model Context Protocol **"everything" reference server**, the
demo server the MCP project ships to show what the protocol can do. It exposes sample tools
(`echo`, `add`, `printEnv`, `longRunningOperation`, ...), needs no credentials, and makes no
outbound network calls, which makes it an ideal first dependency.

---

## What is MCP, in one paragraph?

**MCP (Model Context Protocol)** is a standard way for an AI agent to call external tools and read
external data. An *MCP server* advertises **tools** (functions the agent can call, e.g.
`add(a, b)`), **resources** (data it can read), and **prompts**; any MCP-aware agent can use them.
A server speaks over **stdio** (a pipe to a subprocess) or **HTTP/SSE** (a network service at a
URL). The sandbox runs each dependency in its *own microVM*, reached over the network, so we use a
server that speaks **HTTP/SSE**.

What this feature adds: instead of running an MCP server loose on your machine, the sandbox runs it
as a locked-down neighbor of the agent: its own Kata microVM, its own egress allowlist (none, here),
reachable only by that one session through the session's gateway, gone at teardown. See
[MCP & service dependencies](../how-to/mcp-and-dependencies.md) for the design in brief.

---

## Prerequisites

- A working sandbox (`sandbox status` says the VM is running). See [Installing](../how-to/installing.md).
- The `claude` image built (`sandbox rebuild --agent base && sandbox rebuild --agent claude`) and
  Claude Code onboarded (see [Onboarding agents](../how-to/onboarding-agents.md)). MCP registration
  is wired for `claude` only; declaring `mcps:` for another agent fails the launch.
- The sandbox VM can pull a public image from Docker Hub the first time.

---

## What ships with the repo (already in place)

1. **The catalogue entry**, `config/catalogue/everything-mcp.yaml`, a vetted, digest-pinned spec
   for the reference server. It's committed; you don't create it.

   ```yaml
   name: everything-mcp
   kind: mcp
   image: docker.io/mcp/everything@sha256:330885a0c4b2eed6f0cd3aae0f0b37152ccdf2852e2f6af6d616a5d5c1e9817d
   port: 3001
   mcp_transport: sse
   mcp_path: /sse
   args: [node, dist/sse.js]   # the image defaults to stdio; this starts SSE
   ```

2. **A profile.** Create this one yourself (profiles live in your home directory, not the repo).
   Save it as `~/.sandbox/profiles/mcp-demo.yaml`:

   ```yaml
   tier: 1                # ephemeral, no repo: the simplest possible session
   agent: claude
   mcps:
     - everything-mcp
   ```

---

## Step 1 — (optional) meet the server on your own machine

Before involving the sandbox, see what an MCP server *is*. If you have Docker or Podman:

```bash
docker run --rm -p 3001:3001 mcp/everything node dist/sse.js
# in another terminal:
curl -N --max-time 2 http://127.0.0.1:3001/sse
```

You'll see an `event: endpoint` line: the server announcing where the agent should post requests.
(`/sse` is a long-lived stream, so `--max-time 2` lets `curl` print the opening events and exit.)
`Ctrl-C` the container when you've seen it.

---

## Step 2 — inspect what the sandbox will create (dry run)

A dry run resolves the profile and prints the session spec it would hand the sandbox VM, without
starting anything:

```bash
sandbox run --profile mcp-demo --dry-run
```

Find these in the spec:

- under `dependencies`, an `everything-mcp` entry: its pinned image, `args`, port `3001`, a
  non-root `run_as_user`, resource limits, and an `egress` with an empty allowlist (this server
  needs no internet, so it gets none). There is no field for mounts: a dependency cannot be given
  a workspace or a host path;
- under `mounts`, an `mcp-config` mount of the session's MCP configuration at
  `/home/agent/.sandbox-mcp`, read-only.

---

## Step 3 — launch and use a tool

```bash
sandbox run --profile mcp-demo
```

The launch says `==> Profile dependencies: everything-mcp`. When Claude attaches, the reference
server is registered (its configuration names it at
`http://everything-mcp.deps.sandbox.internal:3001/sse`, which the session's gateway forwards to
the dependency's microVM). Ask it, in plain language:

> List your available MCP tools. Then call the `add` tool with 2 and 3, and the `echo` tool with
> the message "hello from MCP".

(You can also type `/mcp` in Claude Code to see the connected server.)

If you get `5` and `hello from MCP` back, the whole path works: profile → catalogue → microVM →
gateway → MCP registration → agent tool call.

---

## Step 4 — confirm the box is closed

While the session runs, in another terminal on your machine:

```bash
sandbox list                     # the session, running
SID=<session id from the launch banner>
sandbox flows "$SID"
```

`flows` lists the session's connections as the gateway saw them. The calls to the server appear as
`dependency  everything-mcp:3001`. Nothing else in the list comes from the dependency: its
allowlist is empty, so any connection it tried to open would be refused (and listed as `denied`).
The dependency cannot reach the agent, other dependencies, or other sessions at all.

---

## Step 5 — tear down and read the audit trail

Exit the agent (`Ctrl-D` or `exit`). Teardown is automatic. Then read what was recorded:

```bash
grep dependency_up ~/.sandbox/logs/$SID/events.jsonl   # name and pinned image
sandbox logs "$SID"                                     # the session's record
```

That's the round trip: an MCP server is a tool provider; this feature runs one as a disposable,
network-isolated, audited neighbor of the agent.

---

## Troubleshooting

- **`mcps` for another agent fails the launch**: only `claude` has MCP registration wired. Use
  `agent: claude` in the profile.
- **The session fails to start, naming the dependency's image**: the sandbox VM could not pull the
  pinned digest. Check that the VM reaches Docker Hub (`sandbox doctor`). The digest is immutable,
  so a successful pull is always the exact image in the catalogue entry. Pre-loading images into an
  offline VM is not supported yet.
- **The agent has no tools, or `/mcp` shows nothing**: the server may still be starting. Give it a
  moment and ask again.
- **A session lingers after a crash**: `sandbox stop <SID>` removes it and its dependencies.

---

## What you learned

- **MCP** lets an agent call external tools over a standard protocol.
- This sandbox runs an MCP server in its **own microVM**, with an egress allowlist no broader than
  its catalogue entry, no mounts, no standing credentials, and full teardown, so it adds
  capability without adding reach.
- Dependencies are **selected from a vetted, digest-pinned catalogue**, not authored inline: the
  governance boundary that keeps "just add this one server" from becoming an egress hole.

To go further, look at the `services:` list (non-MCP dependencies like a dev database) and the
`class: browser` catalogue entry for Playwright.
