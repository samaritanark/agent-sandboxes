# Architecture

[← Documentation](../index.md)

v3 runs every agent in a microVM inside a dedicated Linux VM on your machine,
the **appliance VM**. Nothing of your machine is mounted into that VM: your
repositories are synced into it, your settings are copied in, and logs are
pulled back, each by the `sandbox` binary on your machine over SSH. v3 runs on
macOS and Linux; Windows follows in a later release. The full design is
[docs/design/v3-architecture.md](../design/v3-architecture.md).

```
 YOUR MACHINE (macOS or Linux)
 ┌───────────────────────────────────────────────────────────────────────┐
 │ sandbox (host binary)                                                 │
 │  ├─ VM driver: vfkit (macOS) or qemu (Linux); lima on request         │
 │  ├─ sandbox netd: the VM's only network; keeps it from your machine   │
 │  ├─ SSH to the VM: pinned host key, a key of its own                  │
 │  ├─ workspace sync and the sync gate (withheld changes: sync review)  │
 │  ├─ settings copied in before each command (config, profiles, ...)    │
 │  ├─ audit records pulled back (append-only)                           │
 │  └─ secret store, credential sealing, agent onboarding               │
 └───────────────┬───────────────────────────────────────────────────────┘
                 │ SSH and the sync only. No mounts.
 APPLIANCE VM (Ubuntu 24.04, built by image/build.sh)
 ┌───────────────▼───────────────────────────────────────────────────────┐
 │ policy layer (`sandbox` in the VM): tiers, gates, vetting, masks,      │
 │   overlays, catalogue, profiles  ──►  session spec (JSON)              │
 │ sandboxd: containerd + Kata, networks, gateways, the broker store,     │
 │   lifecycle, teardown, audit                                           │
 │ /var/lib/sandbox/{workspaces, agent-history, broker, logs, operator}   │
 │                                                                        │
 │  session A                               session B                     │
 │  ┌─ gateway: resolver, check, Envoy, broker ─┐   ┌─ gateway ─┐          │
 │  │   ▲ link A (the only route)                │   │  ▲ link B │          │
 │  │ ┌─┴──────────────────────┐                 │   │ ┌┴───────┐│          │
 │  │ │ Kata microVM: agent    │                 │   │ │ agent  ││          │
 │  │ │ (non-root, placeholders│                 │   │ └────────┘│          │
 │  │ │  instead of credentials)                 │   └───────────┘          │
 │  │ └────────────────────────┘                 │                          │
 │  │ ┌──────────────────┐ link A.dep            │                          │
 │  │ │ Kata: dependency │──────────────────────►│                          │
 │  │ └──────────────────┘                       │                          │
 │  └────────────────────────────────────────────┘                          │
 │  gateway uplink → the VM's network → netd → the internet                 │
 └────────────────────────────────────────────────────────────────────────┘
```

## The pieces

**The host binary** (`sandbox`) manages the VM, holds your secret store and the
credential broker's key, onboards agents, and runs the workspace sync. It
decides no policy: tiers, allowlists, gates, and vetting are decided in the VM.
Commands it does not handle itself it runs in the VM over SSH, with your
terminal attached. Before each one it copies your settings into the VM
(`config.yaml`, `profiles/`, `vetting/`, `extra-ca-certs/`,
`egress-rules.yaml`, `agent-config/`), and after it pulls the sessions' new
audit records.

**sandbox netd** is a process on your machine that is the VM's only network
interface (on vfkit and qemu). It forwards the VM's traffic to the internet and
refuses anything addressed to your machine: its loopback, its LAN address, the
host subnet's broadcast. If netd stops, the VM has no network until it is
restarted; `sandbox vm start` restarts it, and `sandbox doctor` checks it. The
Lima driver (`--driver lima`) cannot block your LAN address and is there for
compatibility only.

**The policy layer** is v2's CLI ported to Go and runs inside the VM. It makes
the same decisions with the same messages, and turns a launch into a **session
spec**: the image (pinned by digest), the mounts, the allowlist and block
lists, the L7 rules, the credential bindings, the dependencies, and the limits.

**sandboxd** is the session supervisor. It checks the spec again, then builds
the session: a network namespace and gateway for it, a Kata microVM (Cloud
Hypervisor) for the agent and one per dependency, the interception
certificates, and the credential handover. It journals every resource before it
creates it, so a crash or a reboot never leaves one behind: at start it tears
down whatever it did not see finish. It ends a session when you stop it, when
its terminal has been gone for two minutes, or for a `--keep-alive` session
after 24 hours detached or 7 days in all.

**The gateway** is per session and the session's only route out. It runs in
the session's own network namespace as an unprivileged user and holds:

- a resolver that answers only allowed names;
- a connection check that admits only allowed destinations and refuses the
  block lists;
- Envoy, which passes allowed TLS connections through or, for a host with a
  credential binding or an L7 rule, terminates TLS with a certificate issued
  for that session, applies the L7 rules, and forwards;
- the broker, which replaces placeholders with credentials on the way out and
  takes the credentials back out of responses.

The agent's microVM reaches its dependencies through the gateway too, at
`<name>.deps.sandbox.internal`; dependencies cannot reach the agent or each
other.

## Workspace sync

The agent works on a copy of each repository in the VM
(`/var/lib/sandbox/workspaces/<id>`), mounted at `/workspace` in its microVM.

- Before a launch (and a resume) the host syncs your repository into the copy.
- While the agent runs, the host syncs about every 3 seconds, and once more at
  the end, so the agent's changes appear in your checkout as it works.
- Changes from the VM pass the **sync gate** on your machine first. Files that
  could run code on your machine or change how git behaves there
  (`.git/config`, hooks, `.gitattributes` filters, `.gitmodules`, and the like)
  are held back in `~/.sandbox/quarantine`; `sandbox sync review` shows the diff
  and applies or discards each.
- A change made on both sides at once is a conflict and is held the same way.

The copy belongs to an unprivileged sync user in the VM; the gates' own git in
the VM runs as another unprivileged user, so a repository's configuration
cannot act as root there.

## Agent logins, configuration, and history

An agent's login lives in the broker store in the VM, sealed with a key kept on
your machine and given to the VM only in memory. A session's agent gets a
placeholder; see [Security model](security-model.md#credential-brokering).

Each launch copies the agent's configuration (from
`~/.sandbox/agent-config/<agent>/`, which `sandbox onboard` fills) into the
session as a writable copy, discarded at the end. The agent's conversation
history is kept per agent, tier, and repository set in
`/var/lib/sandbox/agent-history`, and for tier 1 only for the session.

## Images

The appliance image carries Kata, containerd, Envoy, betterleaks, and the Go
binaries, built from pinned, checksummed inputs (`image/artifacts.lock`,
`image/packages.*.lock`). Agent images are built in the VM with
`sandbox rebuild` and run by digest. Releasing signed images, and
`sandbox upgrade` to move between them, are not built yet.

## What v2 had that v3 does not

k3s, Cilium, Hubble, gVisor, CoreDNS, Helm, and the per-host setup scripts are
gone. So are host mounts: on macOS v2 mounted parts of your home into its VM; on
Linux v2 ran the cluster on your machine itself. In v3 nothing on your machine
is reachable from the VM except the SSH channel and the sync, which the host
drives.
