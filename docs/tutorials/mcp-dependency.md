<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Samaritan's Purse -->

# Tutorial: run a real MCP server inside a sandbox

This walkthrough deploys a **real** MCP server alongside a sandbox session, has
the agent call one of its tools, and shows you how to confirm the sandbox
actually boxed the server in. It doubles as a gentle intro to MCP if the term is
new to you. Plan on about 15 minutes.

Everything here uses the official Model Context Protocol **"everything" reference
server** — the demo server the MCP project ships specifically to show what the
protocol can do. It exposes sample tools (`echo`, `add`, `printEnv`,
`longRunningOperation`, …), needs no credentials, and makes no outbound network
calls, which makes it the ideal first dependency.

---

## What is MCP, in one paragraph?

**MCP (Model Context Protocol)** is a standard way for an AI agent to call
external tools and read external data — think "USB-C for AI tools." An *MCP
server* advertises a list of **tools** (functions the agent can call, e.g.
`add(a, b)`), **resources** (data it can read), and **prompts**; any MCP-aware
agent can use them over a defined protocol. A server can speak over **stdio** (a
pipe to a subprocess) or over **HTTP/SSE** (a network service at a URL). Because
this sandbox runs each dependency as its *own pod* reached over a network
Service, we use a server that speaks **HTTP/SSE**.

What this feature adds: instead of running an MCP server loose on your laptop,
the sandbox runs it as a locked-down neighbor of the agent — same gVisor
isolation, same default-deny egress, reachable only by that one session, gone at
teardown. See the "MCP & service dependencies" section of the [README](../../README.md)
for the design in brief, and `docs/design/phase5-mcp-dependencies.md` for the
full reasoning.

---

## Prerequisites

- A working sandbox install (`sandbox status` is green). See the README Quick Start.
- The **`claude`** agent authenticated (`sandbox onboard`, or just complete the
  OAuth prompt on first launch). MCP registration is wired for `claude` today;
  declaring `mcps:` for another agent intentionally fails the launch.
- Your node can pull a public image from Docker Hub the first time (or see
  [Air-gapped nodes](#air-gapped-or-offline-nodes) to pre-load it).

---

## What ships with the repo (already in place)

Two pieces of scaffolding back this tutorial:

1. **The catalogue entry** — `config/catalogue/everything-mcp.yaml`, a vetted,
   digest-pinned spec for the reference server. It's committed; you don't create it.

   ```yaml
   name: everything-mcp
   kind: mcp
   image: docker.io/mcp/everything@sha256:330885a0c4b2eed6f0cd3aae0f0b37152ccdf2852e2f6af6d616a5d5c1e9817d
   port: 3001
   mcp_transport: sse
   mcp_path: /sse
   args: [node, dist/sse.js]   # the image defaults to stdio; this starts SSE
   ```

2. **A profile** — create this one yourself (profiles live in your home dir, not
   the repo). Save it as `~/.sandbox/profiles/mcp-demo.yaml`:

   ```yaml
   profile: mcp-demo
   tier: 1                # ephemeral, no repo — the simplest possible session
   agent: claude
   mcps:
     - everything-mcp
   ```

---

## Step 1 — (optional) meet the server on your own machine

Before involving the cluster, see what an MCP server actually *is*. If you have
Docker:

```bash
docker run --rm -p 3001:3001 mcp/everything node dist/sse.js
# in another terminal:
curl -N --max-time 2 http://127.0.0.1:3001/sse
```

You'll see an `event: endpoint` line — that's the server announcing where the
agent should post requests. That process is now advertising tools like `echo`
and `add`. An agent pointed at its URL can call them. That's the whole idea.
(`/sse` is a long-lived stream, so `--max-time 2` just lets `curl` print the
opening events and exit — don't pipe it to `head`, which would block waiting
for lines that never come.) `Ctrl-C` the `docker run` when you've seen it.

---

## Step 2 — inspect what the sandbox will create (dry run)

A dry run resolves the profile and prints every object **without applying
anything** (it needs the cluster reachable, but creates nothing):

```bash
sandbox run --profile mcp-demo --dry-run
```

Read the output — this is where the lockdown becomes concrete. Confirm:

- a **dependency pod** with `runtimeClassName: gvisor`,
  `automountServiceAccountToken: false`, all capabilities dropped, a non-root
  `runAsUser`, and **no `volumes:` / no `hostPath`** — nothing from your machine
  is mounted into it;
- a **dependency CiliumNetworkPolicy** whose ingress is `fromEndpoints` your
  session pod *only*, and whose egress is DNS-only (this server needs no
  internet, so it gets none);
- the **session policy** gaining exactly one `toEndpoints` rule to that pod plus
  its `…svc.cluster.local` DNS name — and nothing wider;
- the **MCP ConfigMap**, holding
  `{"mcpServers":{"everything-mcp":{"type":"sse","url":"http://…:3001/sse"}}}`.

---

## Step 3 — launch and use a tool

```bash
sandbox run --profile mcp-demo
```

Watch the launch narrate itself: session pod ready → per-session network
identity verified → dependency brought up → reach wired. When Claude attaches,
the reference server is registered. Ask it, in plain language:

> List your available MCP tools. Then call the `add` tool with 2 and 3, and the
> `echo` tool with the message "hello from MCP".

(You can also type `/mcp` in Claude Code to see the connected server directly.)

If you get `5` and `hello from MCP` back, the whole path works:
profile → catalogue → pod → Service → MCP registration → agent tool call.

---

## Step 4 — confirm the box is actually closed

While the session runs, open another terminal. Use the sandbox kubeconfig:

```bash
export KUBECONFIG="$HOME/.sandbox/kubeconfig"
SID=<session id from the launch banner>

# The session pod plus its dependency pod, Service, and policy:
kubectl get pod,svc,cnp -n sandbox -l "sandbox-session=$SID"

# Prove the dependency is hardened and unmounted:
kubectl get pod -n sandbox -l "sandbox-session=$SID,sandbox-role=dependency" \
  -o jsonpath='{range .items[0]}runtime={.spec.runtimeClassName} uid={.spec.securityContext.runAsUser} volumes={.spec.volumes}{"\n"}{end}'
# → runtime=gvisor uid=1000 volumes=  (no volumes at all)
```

The dependency accepts traffic only from your session pod (its policy ingress)
and has no egress to the internet (DNS-only). It's a neighbor the agent can
call, not a hole in the wall.

---

## Step 5 — tear down and read the audit trail

Exit the agent (`Ctrl-D` or `exit`). Teardown is automatic. Then confirm nothing
leaked and read what was recorded:

```bash
export KUBECONFIG="$HOME/.sandbox/kubeconfig"
kubectl get all,cnp,cm,secret -n sandbox -l "sandbox-session=$SID"   # expect: nothing

jq '.dependencies' "$HOME/.sandbox/logs/$SID/session.json"
# → name, kind, resolved version, egress allowlist, up_time / down_time
```

That's the round trip: an MCP server is a tool provider; this feature runs one
as a disposable, network-isolated, audited neighbor of the agent — and lets you
prove it couldn't become an exfiltration path.

---

## Troubleshooting

- **`mcps for agent 'X' … fails the launch`** — only `claude` has MCP
  registration wired today. Use `agent: claude` in the profile.
- **Dependency pod stuck `Pending` / `ErrImagePull`** — the node couldn't pull
  the pinned digest. Confirm outbound access to Docker Hub, or pre-load it (next
  section). The digest is immutable, so a successful pull is always the exact
  image in the catalogue entry.
- **Agent says it has no tools / `/mcp` shows nothing** — the dependency may not
  have finished starting before you asked. Give it a moment; if it persists,
  check the dep pod's logs: `kubectl logs -n sandbox -l "sandbox-session=$SID,sandbox-role=dependency"`
  (it should print `Server is running on port 3001`).
- **The dependency lingers after a crash** — `sandbox stop <SID>` reaps it; a
  label-keyed sweep removes anything an owner reference missed.

### Air-gapped or offline nodes

Dependency pods use `imagePullPolicy: IfNotPresent`, so a node with registry
access just pulls the pinned digest on first use. On an air-gapped node, pre-load
the exact digest into the cluster's container runtime before launching:

```bash
docker pull mcp/everything@sha256:330885a0c4b2eed6f0cd3aae0f0b37152ccdf2852e2f6af6d616a5d5c1e9817d
docker save mcp/everything | sudo k3s ctr images pull \
  docker.io/mcp/everything@sha256:330885a0c4b2eed6f0cd3aae0f0b37152ccdf2852e2f6af6d616a5d5c1e9817d
# (or, simplest on a connected node, just `k3s ctr images pull <image>@<digest>`)
```

---

## What you learned

- **MCP** lets an agent call external tools over a standard protocol.
- This sandbox runs an MCP server as its **own gVisor pod** with a network policy
  no broader than the session's, no mounts, no standing credentials, and full
  teardown — so it adds capability without adding reach.
- Dependencies are **selected from a vetted, digest-pinned catalogue**, not
  authored inline — the governance boundary that keeps "just add this one server"
  from quietly becoming an egress hole.

To go further, look at the `services:` list (non-MCP dependencies like a dev
database) and the `class: browser` catalogue entry for Playwright — the worked
hard case, documented in `docs/design/phase5-mcp-dependencies.md`.
