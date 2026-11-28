# agent-sandboxes v3 — Architecture Design

[← Documentation](../index.md)

| | |
|---|---|
| **Status** | Draft, revision 5. Revision 4 (third external review, Appendix C; Go policy port, D-34) plus operator-driven agent harness updates (D-35, Appendix D). Gating spikes S1, S2, S4, S5, S6, S7, and S8 have run on macOS (Apple M6) and its arm64 Lima VM; S6 and S1 have also run on a Linux x86_64 host, and the other Linux-host runs are pending. For current status and next steps see `docs/design/spikes/S8.md`, "Start here"; S3 (Windows) not run |
| **Target** | v3.0.0 (major version; breaking install and platform changes) |
| **Owner** | Jase Hall |
| **Date** | 2026-11-18 |
| **Supersedes** | Revision 1 of this document (k3s + Cilium + Kata inside an appliance VM) |

## 0. How to use this document

This document describes the **end state** of agent-sandboxes v3 and the
acceptance criteria for v3.0.0. It is written to be implemented in stages by
Claude Code or a human.

- **Normative language.** MUST / MUST NOT / SHOULD / MAY carry their RFC 2119
  meanings. Anything not marked normative is explanation.
- **Security parity is the release gate.** v3.0.0 MUST NOT ship until every
  row of the [protection parity matrix](#7-protection-parity-matrix-acceptance-criteria)
  passes on **macOS and Linux**. No exceptions are pre-approved.
- **Windows is best effort for v3.0.0** (D-29). The design keeps Windows in
  scope and nothing may foreclose it, but v3.0.0 does not wait for it. When
  Windows ships, it MUST pass the same matrix; there is no reduced-security
  Windows build.
- **Protection may only go up.** A v3 mechanism that is weaker than the v2
  mechanism it replaces is a defect, even if it is simpler.
- **Seamless collaboration is a requirement, not a nicety.** An operator and
  an agent MUST be able to work on the same files, branches, and staged
  changes with only sync latency (seconds) between them (G9). A control that
  removes a v2 collaboration workflow is a defect unless it is replaced by an
  equally direct one. Friction drives operators out of the sandbox, and an
  operator outside the sandbox has no protection at all.
- **No capability may be lost silently.** Every v2 user-facing capability, and
  every capability in the credential-brokering design (§5.9), is either carried
  forward, replaced by a named equivalent, or removed by an entry in the
  decision log (§14) that names what replaces it.
- **Gating spikes come first.** Work that depends on a spike (§8) MUST NOT
  start until the spike's exit criteria are met and its findings are recorded
  in `docs/design/spikes/<id>.md`. If a spike fails, follow its stated
  fallback and update this document before continuing.
- **Do not implement [future phases](#12-future-phases).** They are recorded
  so v3 does not foreclose them.
- **Migration (§11) is a sequence of options, not a schedule.** Each step must
  leave `master` releasable or behind a feature flag.
- **Where this document is wrong, fix the document first.** Divergence between
  code and design is a bug in one of them; decide which, in writing.
- **Claims about v2 are cited.** Appendix A lists the v2 facts this design
  depends on, each with `file:line`. If the code changes, re-check the claim.

---

## 1. Summary

v2 runs three topologies: native k3s on Linux, a Lima VM with the CLI on the
Mac host, and a WSL2 distro with a PowerShell shim on Windows. Each carries its
own workspace, DNS, uid, and port-forwarding code. In every one of them gVisor
is the only barrier between an adversarial agent and the operator's
workstation: the Lima VM mounts the whole home directory writable, the WSL2
distro relies on interop and drive automount, and Linux has no VM at all
(Appendix A.1).

v3 replaces this with **one design on every host**, and removes Kubernetes,
Cilium, and gVisor entirely:

1. **A hardened appliance VM** booted from a single signed, pinned image. The
   VM is a real security boundary: no host filesystem mounts, no host-exec
   interop, and no route to the host except the control channel, the
   workspace sync, and operator-declared Tier 3 endpoints.
2. **`sandboxd`, a small supervisor inside the VM**, that runs each session
   and each dependency as a **Kata Containers microVM (Cloud Hypervisor)**
   through containerd directly. There is no Kubernetes. `sandboxd` owns
   lifecycle, resource accounting, teardown on every exit path, credential
   revocation, and transcript capture.
3. **Egress by topology, not policy.** Each microVM gets exactly one network
   link, and that link leads only to **that session's own gateway**. A
   filtering DNS resolver answers only allowlisted names. The gateway enforces
   the allowlist, block lists, post-resolution CIDR blocks, and L7 rules. There
   is no other route out.
4. **Credential brokering, per session**, as specified in the
   credential-brokering design (§5.9). No credential that works outside the
   sandbox is readable inside it. Pods hold placeholders; the session's broker
   substitutes real values only toward bound destinations.
5. **A thin, cross-platform Go host binary** that manages the VM, moves
   commands, files, a TTY and signals, and performs a short, enumerated list
   of operations that need the operator's own host credentials (vetting
   signatures, private overlay fetches, trust-store extraction). It makes no
   policy decisions.

The policy layer that implements tiers, masking, the secret gate, vetting,
profiles, overlays, the catalogue, and audit is **ported to Go** (D-34) and
runs in the VM as an unprivileged process, on exactly one platform, emitting a
**session spec** instead of Kubernetes YAML. The whole product is one Go
module; the v2 bash stays in the tree as a frozen test oracle until release.

What this buys:

- **Protection:** two hardware-virtualized boundaries on every host;
  credentials outside the sandbox; structural no-publish and no-push;
  teardown and revocation on every exit path; the repo gates no longer run
  git against an untrusted repo on the host.
- **Maintenance:** roughly 2,800 lines of Kubernetes, Cilium and gVisor code
  and roughly 1,800 lines of Lima/WSL/PowerShell platform code are deleted
  (Appendix A.6). The remaining bash is ported, leaving one language (Go) to
  maintain. Security tests run once, against one platform.
- **Workstation footprint:** the host carries one binary and one VM. Nothing
  runs as root on the host outside the hypervisor.

---

## 2. Goals and non-goals

### 2.1 Goals

- **G1 — Protection parity, then more.** Every v2 control that protects
  against an adversarial agent is preserved (§7.1), and the new protections in
  §7.2 are added. This is the adoption bar for the team.
- **G2 — One design.** The same image, runtime, egress path, workspace model,
  and policy layer on macOS, Linux, and Windows. Per-OS code is confined to
  the host binary's driver, console, and trust-store layers.
- **G3 — Two hardware boundaries between agent and host** on every platform:
  Kata guest → (Cloud Hypervisor + KVM) → appliance VM → (host hypervisor) →
  host.
- **G4 — Credentials outside the boundary** (§5.9), as a requirement.
- **G5 — Structural, not cooperative, egress semantics** where the protocol
  allows it (install-not-publish, no `git push` by default).
- **G6 — Hermetic, verifiable distribution.** Signed image, signed host
  binary, provenance; air-gap mirrorable; works behind TLS-intercepting
  proxies and split DNS.
- **G7 — Fewer regressions.** The security test suite runs once, against the
  one in-VM platform, and exercises the product's real session output, not
  hand-written fixtures (§9).
- **G8 — Smaller workstation install footprint.** No host-level Kubernetes,
  CNI, container runtime, or root services. Memory use has an explicit,
  measured budget (P-24). Nested virtualization may cost more memory than v2
  on Linux; security is not traded for memory.
- **G9 — Seamless operator–agent collaboration.** File edits, commits on
  feature branches, branch switches, staging, merges, and conflict resolution
  made on either side appear on the other within seconds, with no manual
  step. Protection is enforced by the host-side sync gate (§5.6.2), not by
  asking the operator to do more.
- **G10 — One language.** The host binary, `sandboxd`, the in-VM policy CLI,
  and the gateway controller are one Go module (§5.4.1, D-34). Trust
  boundaries between processes are kept; only the language split goes.

### 2.2 Non-goals for v3.0.0

- Changing policy behaviour during the Go port. The port MUST be
  behaviour-identical to v2 (differential-tested, S8) except where this
  document says a protection goes up (for example strict config decoding,
  §5.4.1). New policy features wait until after the port.
- Runtime syscall/process detection (F1).
- Windows Home, Intel Macs, Apple M1/M2, and launching from a host that is
  itself a VM are **unsupported** (§5.2.4). The team has confirmed none of
  these are in use; the M3 floor is verified by spike S6.
- Multi-node, cluster, or shared deployments. One operator, one VM. (A cluster
  deployment of the same policy layer is F4.)
- Snapshot-based suspend/resume of sessions (F6).
- Windows as a release gate. Windows support is best effort and may follow
  v3.0.0 in a later release (D-29); Windows users stay on v2 until then.

---

## 3. Background

### 3.1 v2 topologies (verified against the code; see Appendix A.1)

| | Linux | macOS | Windows |
|---|---|---|---|
| CLI runs | host | **Mac host** (bash 3.2, BSD userland) | inside WSL distro, as root, via `bin/sandbox.ps1` |
| k3s runs | host | Lima VM | WSL2 distro (shared WSL kernel) |
| Workspace | hostPath bind mount; pod uid = operator uid | 9p home mount → per-session VM-local copy + in-VM Mutagen; uid 1000 | bind mount from distro ext4; `/mnt/*` refused |
| DNS | host resolver; optional `--dns` | Lima | `--dns` required |
| Second boundary after gVisor | none | VM, but `~` and `/tmp/lima` are mounted **writable** | distro, but setup writes only `[boot]`/`[user]` to `wsl.conf`, and the CLI itself runs from `/mnt/<drive>` |
| Host root services | k3s, Cilium, gVisor, buildkit, helm, masquerade unit, firewalld rules | Lima (user), everything else in VM | everything in distro |

Consequences: three install paths, platform branches throughout `lib/`, a
recurring class of macOS-only fixes, and a Kubernetes/Cilium stack whose
quirks drive a large share of the code (Appendix A.2).

### 3.2 What Kubernetes and Cilium actually do for v2

The control plane uses a small Kubernetes surface: Pods (apply, get, delete,
exec), Secrets with ownerReferences, one ConfigMap per session for MCP config,
ClusterIP Services for dependencies, and CiliumNetworkPolicy objects. Cilium
performs 17 distinct enforcement jobs (Appendix A.3). Several of v2's
documented gaps come directly from relying on Kubernetes primitives:

- ownerReference garbage collection does not fire on eviction, so an evicted
  keep-alive session's Secrets stay live;
- there is no server-side reaper for keep-alive sessions (issue #94);
- teardown depends on CLI signal traps, which do not cover the pre-attach
  window or SIGKILL;
- the transcript is copied only by `sandbox stop`, from a directory the agent
  can rewrite.

A supervisor that owns every microVM directly closes all four structurally.

### 3.3 External context

- MicroVM isolation and out-of-sandbox credential proxies became the norm for
  agent sandboxes in 2026. v2's policy layer is more complete than any of them
  (masking, secret gate, signed vetting, tiers, additive-only overlays,
  host-exec vector protection), but its boundary and credential handling are
  behind (`docs/explanation/comparisons.md` already says gVisor is the weaker
  boundary).
- **Agent Substrate** (ate.dev, CNCF Sandbox) is the closest production
  design. v3 adopts its strongest ideas and deliberately keeps what
  agent-sandboxes does better:

  | Adopted from Substrate | Kept from agent-sandboxes (Substrate has no equivalent) |
  |---|---|
  | A microVM sandbox class (Kata + Cloud Hypervisor) beside its gVisor default; plain containers are not a boundary. v3 makes the microVM the only runtime | Path masking and host-exec vector protection |
  | Kubernetes off the per-agent path | Fail-closed pre-launch secret gate |
  | All egress through a choke point; DNS relay answers NXDOMAIN for unlisted names; fail closed if the enforcement point fails | Signed repo vetting with operator trust roots |
  | Zero ambient credentials: header replacement at the gateway, credentials referenced by URI, pluggable provider, 403/503 fail-closed | Tiers; overlays that may only tighten |
  | Every sandbox has a structural identity | Digest-pinned catalogue dependencies built from empty |
  | Structured audit of gateway routing and policy violations | Local working-tree sync with the operator's checkout; transcript audit |

---

## 4. Threat model

The v2 threat model in [PRINCIPLES.md](../../PRINCIPLES.md) is unchanged: v3
defends against a rogue, mistaken, prompt-injected, or jailbroken agent, and
does not defend against a malicious operator, a compromised host, compromised
model providers, or supply-chain compromise of this tool.

v3 adds explicit assumptions about **escape depth**:

| Attacker reaches | v2 consequence | v3 requirement |
|---|---|---|
| Code execution in the agent microVM | Contained by pod controls | Same; plus no readable credentials (§5.9) |
| Exploit of the session's own gateway, resolver, or broker (the guest speaks TLS, HTTP, and DNS to them directly) | n/a | Confined to that session: unprivileged user, per-session network namespace, seccomp, only that session's bindings loaded (§5.8.2, §5.9.2). MUST NOT yield VM root or any other session's credentials |
| Guest kernel compromise (Kata) | n/a | Contained by Cloud Hypervisor + KVM; MUST NOT reach other sessions |
| microVM escape → appliance VM root | Host home writable (macOS), host itself (Linux), distro root with Windows drives (Windows) | MUST NOT reach any host file, process, credential, or network service beyond the control channel, the sync, and operator-declared Tier 3 endpoints (§5.2.6). Every VM→host data flow MUST be validated by the host (§5.1.5). MAY reach other sessions' workspace copies and the brokers' credential stores (accepted; §5.9.8) |
| Appliance VM escape → host | n/a | Out of scope (hypervisor vulnerability) |

**Trust domains.** Sessions that share a working tree are one trust domain:
content one agent writes, the other reads (§5.13). Agent history is shared per
agent, repo, and tier (§5.7), so sessions of the same agent on the same repo at
the same tier are one trust domain for history; history never crosses tiers.

**Agent-writable artifacts are never evidence.** Audit records are produced by
`sandboxd` and the gateway from their own observations (§5.12). The agent's
transcript is copied for convenience and is labelled **agent-reported**.

**Audit integrity against VM root is not claimed.** Streaming with sequence
numbers (§5.1.5) makes suppression after the fact detectable as a gap; it
cannot stop an attacker who already holds VM root from falsifying events
before they are emitted.

---

## 5. Architecture

### 5.0 Overview

```
 HOST (macOS / Linux / Windows)
 ┌──────────────────────────────────────────────────────────────────────┐
 │ sandbox (Go host binary)                                             │
 │  ├─ VM driver: lima-vz | lima-qemu | hyperv (or lima-hcs)            │
 │  ├─ control channel: SSH (pinned host key, per-install client key)   │
 │  ├─ workspace sync (host-driven; host enforces direction rules)      │
 │  ├─ operator-state push (allowlisted set, one-way)                   │
 │  ├─ audit stream + typed pulls: logs, transcripts (host-validated)   │
 │  ├─ host-side sync gate (applies VM-origin changes; quarantine)      │
 │  └─ host operations: vet signing, overlay fetch, trust-store CA      │
 │     extraction, browser open, exec-plugin token pump                 │
 └───────────────┬──────────────────────────────────────────────────────┘
                 │ SSH + sync only. No host mounts, no interop.
 APPLIANCE VM (signed image; immutable system disk, persistent state disk)
 ┌───────────────▼──────────────────────────────────────────────────────┐
 │ policy layer (Go, ported from v2): tiers, gates, vetting, masks,     │
 │   overlays, catalogue, audit  ──►  session spec (JSON)               │
 │ sandboxd (Go): containerd + Kata shim, links, nftables, quota,       │
 │   lifecycle, reaping, revocation, transcript capture                 │
 │ /var/lib/sandbox/{workspaces,agent-history,broker,logs,operator}     │
 │                                                                      │
 │  session A                                 session B                 │
 │  ┌─ gateway+resolver+broker (A) ─┐         ┌─ gateway+… (B) ─┐       │
 │  │  ▲ link A (only route)        │         │  ▲ link B        │       │
 │  │ ┌┴───────────────────────┐    │         │ ┌┴──────────┐    │       │
 │  │ │ Kata: agent (non-root, │    │         │ │ Kata:     │    │       │
 │  │ │ placeholders only)     │    │         │ │ agent     │    │       │
 │  │ └────────────────────────┘    │         │ └───────────┘    │       │
 │  │ ┌──────────────┐ link A.dep1  │         └─────────────────┘       │
 │  │ │ Kata: MCP dep│──────────────┤                                    │
 │  │ └──────────────┘              │                                    │
 │  └───────────────────────────────┘                                    │
 │  gateway egress → VM NAT → host network (plus declared host endpoints)│
 └──────────────────────────────────────────────────────────────────────┘
```

Each session box above is a **per-session network namespace**: the session's
gateway, resolver, and broker run there as an unprivileged user under seccomp,
with one link to the session's microVMs and one NAT'd uplink to the VM root
namespace (§5.8.2).

**Separation of duties.** The policy layer decides; `sandboxd` executes; the
per-session gateway enforces. Each has one job, and the interface between the
policy layer and `sandboxd` is the session spec (§5.4.2).

### 5.1 Host binary (`sandbox`, Go)

#### 5.1.1 Responsibilities (exhaustive)

The host binary MUST be limited to:

1. VM lifecycle via the driver interface (§5.2): install, start, stop,
   upgrade, uninstall, probe.
2. Opening the control channel and running `sandbox <args>` inside the VM with
   stdio/TTY attached, forwarding signals and window-size changes.
3. Translating host paths (`--repo`, `--from-file`, `--infra-kubeconfig`,
   etc.) into repo IDs or pushed files, and driving workspace sync (§5.6).
4. Pushing operator state host → VM (§5.1.4) and performing typed pulls VM →
   host (§5.1.5).
5. The **host operations** in §5.1.3.
6. Verifying signatures of images and of its own updates.
7. The version handshake (§5.1.6).
8. Running `sandbox netd`, the host-side network process that holds the
   host-reach control (§5.2.6, D-31).

The host binary MUST NOT implement policy: tier resolution, allowlists, block
lists, masking decisions, the secret gate, vetting *verification*, catalogue
resolution, and session-spec generation all live in the VM. A change that
needs policy knowledge on the host is a design change and requires updating
this document. In the single Go module (§5.4.1), the host binary MAY import
only the packages designated host-safe (shared rule tables, the sync gate, the
drivers); a CI check on the import graph fails the build if it imports the
policy, vetting, secret-gate, or repo-parsing packages. One exception (owner's
decision, 2026-11-25): the sync gate reads the host checkout's own
`masked_paths:` list (§5.6.2 rule 1), because the VM's report of it cannot be
trusted, using the same small dependency-free list reader as the policy layer
(`internal/yamllist`). The repository's policy files (`.sandbox/`,
`.betterleaksignore`, `.gitleaksignore`) never flow VM → host without review,
so the list the host reads is one the operator controls.

#### 5.1.2 Platforms and build

- Targets: `darwin/arm64`, `linux/amd64`, `linux/arm64`, `windows/amd64`.
- Per-OS code lives only in build-tagged files (`*_darwin.go`, `*_linux.go`,
  `*_windows.go`) behind interfaces: driver, TTY/console (ConPTY on Windows),
  signals (no SIGHUP on Windows), path handling, browser open, trust-store
  access, file-permission checks on `~/.sandbox`.
- The binary SHOULD shell out to `limactl` rather than import Lima's Go
  packages, which are not a stable API. It MUST resolve `limactl` to an
  absolute path at install, refuse a path another account could replace (the
  file, its link target, or any directory above either owned by neither root
  nor the operator, world-writable, or group-writable by a group other than
  root's or, on macOS, `admin`; Homebrew's own directories pass; owner's
  decision, 2026-11-25), and
  re-verify the path and its ownership on every start; `sandbox upgrade`
  re-records the path after a Lima upgrade.
- Unit tests MUST run on GitHub-hosted runners for all three OSes using a mock
  driver (no virtualization required).

#### 5.1.3 Host operations (exhaustive)

These need the operator's own host credentials or host state, which MUST NOT
enter the VM. Each is started by an operator command or by the attached
session the operator started, never by an unsolicited request from the VM,
except where noted.

| Operation | Why it is host-side | v2 source |
|---|---|---|
| **Vetting attestation signing** (`sandbox vet`, inline attest at launch), **without running git against the host repo** (D-20). (1) The VM builds the canonical tag payload (`object <commit-sha>`, `type commit`, `tag agent-vetted/<sha>`, tagger, message) and the exception acknowledgement list from its synced copy. (2) The host reads HEAD's commit SHA itself by parsing `.git/HEAD`, the ref file, and `packed-refs` as plain files (no git execution) and refuses if it differs from the payload's SHA. (3) The host shows the operator the SHA, the exceptions, and the message, plus any commits at or below `HEAD` that the sync gate's ledger records as created in a sandbox session (§5.6.2 rule 6), and asks for approval; those commits require explicit acknowledgement. (4) The host signs the payload bytes with `ssh-keygen -Y sign -n git` (or `gpg --detach-sign`), exactly what `git tag -s` signs. (5) The VM assembles the signed tag object (`git mktag`) and verifies it against the trust roots; the host binary then re-verifies the object, writes it as a loose object, and writes `refs/tags/agent-vetted/<sha>` itself, because tags never sync VM → host (§5.6.2 rule 6). Existing `agent-vetted/*` tags remain valid: the object format is unchanged | The signing key is the operator's SSH/GPG key | `lib/vetting.sh:1149-1236` |
| **Signing-identity setup assist** (`vet` offering to configure git signing) | Edits the operator's global git config | `lib/vetting.sh:1333-1423` |
| **Overlay clone and sync** (`sandbox link`, the run-path sync). The host fetches with the operator's git credentials, validates nothing (that is policy), and pushes the tree; the VM validates shape and pins | Private overlay repos need the operator's git credentials | `lib/link.sh:132-141, 461-515` |
| **Leakscan config fetch** (`leakscan_config_url`) MAY run in the VM (it needs no host credentials); if the URL is only reachable from the host network, the host fetches and pushes. The VM verifies the sha256 pin either way | Network reachability only | `lib/filesystem.sh:485-563` |
| **Proxy CA extraction** (`sandbox setup-proxy-cert`): macOS System keychain, Linux trust store, Windows `LocalMachine\Root` / `CurrentUser\Root` | Reads host trust stores | `lib/certs.sh` |
| **Browser open / device-code display** for onboarding. This is the one VM-initiated request. The host accepts it only while an operator-started `sandbox onboard <agent>` is in the foreground on the host, and only once per onboarding; at any other time it is refused and logged. The host MUST open only `https` URLs that match a per-agent **URL template** compiled into the binary (host, path, and the `client_id` and `redirect_uri` the agent uses; S2 enumerates them), never a host alone, and MUST show the URL to the operator. For a device code, the host MUST show which agent and OAuth client the code belongs to, taken from its compiled-in table and not from VM text | OAuth flows need the host browser | — |
| **Exec-plugin token pump** for brokered exec-plugin kubeconfigs (§5.9.5): while a session is attached, the host runs the allowlisted plugin with the operator's host auth state and pushes the short-lived credential to the session broker. The invocation (command, args, env, `provideClusterInfo`) is **captured by the host binary from its own copy of the operator-supplied kubeconfig at `run`** and keyed by an index; a pump request from the VM carries only that index and a session ID, and the host runs exactly the captured invocation (§5.9.5). Only plugins classified **cluster-scoped** are pumped by default (§5.9.5) | Auth-provider state (`~/.aws`, gcloud, kubelogin caches, `~/.tsh`) MUST NOT enter the VM (PRINCIPLES.md rule 3) | new |
| **Clipboard copy**, only on explicit operator request | Host clipboard | — |

#### 5.1.4 Operator state (host → VM, one-way)

Operator state stays on the host under `~/.sandbox/` (Windows:
`%USERPROFILE%\.sandbox\`) so it survives VM rebuilds. Before each proxied
command the host binary pushes a defined set to `/var/lib/sandbox/operator/`
(root-only, never mounted into any microVM):

- `config.yaml`, `profiles/`, `vetting/` trust roots,
- only the secrets named by the session's resolved bindings (§5.9.2), as 0600
  files, never the whole `secrets/` directory,
- agent tokens **only during `sandbox onboard`** (import), never on later
  commands, so a token the broker has since rotated is never overwritten by a
  stale host copy (§5.9.6),
- linked overlay checkouts (as fetched in §5.1.3),
- extra CA certificates from `~/.sandbox/extra-ca-certs/` **and** the v2
  location `config/extra-ca-certs/` in the install (both read; §5.10),
- the infra kubeconfigs and tokens passed on the command line, for that
  session only.

The pushed set MUST be enumerated in code (an allowlist), not "the whole
directory". Secrets are pushed only for `run` and `resume`, only those the
session's bindings reference, and are written directly into the broker store
(§5.9.2) or a tmpfs; the staging copy MUST be deleted once the broker has
started. Nothing else from `secrets/` is pushed or persisted on the state disk.

#### 5.1.5 VM → host data flows (host-pulled, typed, validated)

Under the threat model, VM root may be attacker-controlled. Therefore every
VM → host flow MUST be **initiated by the host**, **typed**, **validated by the
host**, and **written only to a fixed destination**. The VM never writes host
state directly.

| Flow | Destination | Host-side validation (MUST) |
|---|---|---|
| Session events and gateway log | `~/.sandbox/logs/<session>/` | **Streamed** to the host over the control channel while the host binary is attached, and pulled on reattach or stop. Every record carries the session ID and a monotonic sequence number; the host records any gap as an `audit_gap` event. Regular files only, no symlinks, no `..`, size caps; **append-only**: the host never rewrites a record it already holds |
| Transcripts (agent-reported) | `~/.sandbox/logs/<session>/transcript/` | Same file rules as logs; labelled agent-reported in `session.json` |
| Workspace changes | the host repo | Applied only by the host-side sync gate (§5.6.2) |
| Vetting signing request | none (host prompts the operator, then signs) | The host derives the commit SHA itself and signs only a payload naming that SHA (§5.1.3) |

**There is no VM → host token flow.** Rotated agent tokens stay in the broker
store on the VM state disk, which survives `sandbox upgrade`. Deleting or
recreating the VM requires re-running `sandbox onboard` (D-21). This removes a
token-substitution path: a hostile VM cannot plant a token for an attacker's
account in the host store.

#### 5.1.6 Command surface

All v2 subcommands are proxied into the VM unchanged: `run`, `resume`,
`list`, `logs`, `flows`, `stop`, `cleanup`, `status`, `check`, `allow`,
`onboard`, `secret`, `mask`, `exceptions`, `vet`, `profile`, `link`,
`rebuild`, `version`. v3 adds the in-VM `agent` command (`update`, `status`,
`rollback`; §5.7.1), also proxied. The host binary adds its host-side half where §5.1.3
says so (`vet`, `link`, `onboard`, `setup-proxy-cert`).

Host-only commands:

| Command | Purpose |
|---|---|
| `sandbox install` / `uninstall` | Create/destroy the VM; `uninstall` also offers v2 cleanup (§11) and asks, per category, whether to remove `~/.sandbox` state (secrets and agent tokens, logs, settings and profiles); without a terminal it keeps everything unless `--purge` is given |
| `sandbox upgrade [--app] [--image]` | Update binary and/or image (§10) |
| `sandbox vm start\|stop\|status\|shell` | VM lifecycle; `shell` is a root debug shell, recorded by the host binary in `~/.sandbox/logs/vm-shell.log` (append-only), because an in-VM record can be erased by VM root |
| `sandbox sync review [--apply <id>] [--discard <id>]` | Lists workspace changes the sync gate withheld (§5.6.2) with diffs; applies or discards them on explicit operator action |
| `sandbox doctor` | Capability probe (§5.2.3) and connectivity diagnostics |
| `sandbox setup-proxy-cert` | Host operation (§5.1.3) |
| `sandbox ca rotate` | Rotate the per-install gateway CA (§5.10) |

`setup` remains an alias of `install`. Removed commands and flags are listed
in §6.

#### 5.1.7 Version handshake

The image exposes `/etc/sandbox/release` with `IMAGE_VERSION` and
`CONTROL_API` (integer). The host binary embeds the range of `CONTROL_API`
values it supports and MUST refuse to proxy commands outside that range,
printing the exact `sandbox upgrade` invocation that resolves it. The v2
overlay `min_sandbox_version` gate continues to apply to the in-VM version.

### 5.2 VM drivers

#### 5.2.1 Driver interface

```go
type Driver interface {
    Probe(ctx) (Capabilities, error)          // nested virt, CPU/RAM, hypervisor availability
    Create(ctx, img ImageRef, res Resources, seed SeedConfig) error
    Start(ctx) error
    Stop(ctx) error
    Delete(ctx) error
    Status(ctx) (State, error)
    Endpoint(ctx) (SSHEndpoint, error)        // control + sync transport
    HostReach(ctx) (HostReachControl, error)  // §5.2.6
}
```

Exec, copy, and sync all go over the SSH endpoint so they are identical
across drivers. Drivers MUST NOT configure host filesystem mounts, clipboard
sharing, or host-exec integration.

#### 5.2.2 Drivers

| Host | Driver | Notes |
|---|---|---|
| macOS 15+, Apple M3 or later | `vfkit` (default) | vfkit (Apple's Virtualization framework) run by `sandbox netd`, whose userspace network is the VM's only NIC (§5.2.6, D-31; S7 2026-11-25); `--nested`, no shares, no NAT device. Raw disk image, cloud-init NoCloud seed |
| macOS 15+, Apple M3 or later | `lima-vz` (`--driver lima`) | `vmType: vz`, `nestedVirtualization: true`, `mounts: []`. Lima always attaches its own user-mode NIC, so the VM can reach the host's LAN address and `sandbox doctor` fails (§5.2.6) |
| Linux (bare metal) | `qemu` (default) | qemu 7.2+ with KVM run by `sandbox netd`, whose datagram socket pair is the VM's only NIC (`-netdev dgram`); UEFI firmware from the distribution (OVMF/AAVMF, no Secure Boot enforcement); the cloud-init seed on a FAT disk the host binary writes; QMP for a graceful stop. Nested KVM enabled (`/sys/module/kvm_{intel,amd}/parameters/nested`); the user needs `/dev/kvm` (the `kvm` group) |
| Linux (bare metal) | `lima-qemu` (`--driver lima`) | KVM; nested KVM enabled. Lima always attaches its own user-mode NIC, so it has no host-side per-destination control (§5.2.6) |
| Windows 11 Pro/Enterprise | `hyperv` **or** `lima-hcs` | Decided by spike S3. Requires nested virtualization exposed to the guest and Hyper-V Administrators membership. The in-VM virtualization backend (nested KVM, or MSHV if Kata + Cloud Hypervisor support it in this configuration) is decided by S3. **This is the least certain assumption in the design** (Appendix C, F-01). **Best effort for v3.0.0** (D-29) |

The virtualization backend inside the appliance MAY differ between hosts; the
security contract MUST NOT: every agent and dependency runs in a
hardware-isolated Kata guest (D-22).

WSL2 is **not** a v3 driver: it boots on Microsoft's shared WSL kernel, and
its interop and automount controls are configured from inside the distro.

#### 5.2.3 Capability probe

`sandbox install` and every `sandbox run` MUST verify, functionally rather
than by model name:

1. The appliance VM starts with nested virtualization enabled.
2. A supported hardware virtualization backend is present inside the VM
   (`/dev/kvm`, or `/dev/mshv` where S3 qualifies it). This check is
   diagnostic only; check 3 is the contract.
3. A canary Kata microVM starts, reports a guest kernel, reaches its gateway,
   reads a canary file through virtio-fs, and tears down cleanly.
4. The host-reach control (§5.2.6) is in force: a canary connection from VM
   root to a host loopback listener the binary opens for the purpose fails.

On failure the binary MUST refuse to proceed with a specific message (which
check failed, likely cause, supported-hardware link). There is **no fallback
runtime** (D-04).

#### 5.2.4 Supported hosts

- macOS 15+ on Apple M3 or later (verify Apple's nested-virtualization chip
  and OS floor in S6).
- Linux on bare metal with KVM and nested KVM.
- Windows 11 Pro/Enterprise with Hyper-V available: **best effort**, not
  required for v3.0.0 (D-29). Windows 11 Home has no Hyper-V and stays
  unsupported.
- Not supported: Windows Home, Intel Macs, Apple M1/M2, any host that is
  itself a VM. The team has confirmed no current user depends on these.

#### 5.2.5 VM hardening requirements

- No host filesystem mounts of any kind.
- No host-exec interop; no shared clipboard; **no port forwarding of any kind
  from the guest to the host**. Lima otherwise appends a fallback rule that
  forwards every guest loopback listener to the same port on host loopback
  (review F4; confirmed on Lima 2.3.0 in S7, where a guest loopback listener
  appeared on host loopback with defaults and did not with `plain: true`),
  which would let VM
  root squat on host ports. The Lima drivers MUST set `plain: true` (if S7
  confirms the appliance needs nothing plain mode removes) or, failing that, a
  first `portForwards` rule `{guestIP: "0.0.0.0", proto: any, ignore: true}`.
  The Hyper-V driver MUST NOT run an equivalent agent. N-02 tests it.
- SSH, with **no trust-on-first-use**: the host binary generates both the
  per-install client key and the guest's SSH host key, delivers the host
  private key in the NoCloud seed, pins the public key before first
  connection, and deletes the seed after first boot. The pinned key is bound to
  the install ID. Password auth disabled; root login by key only. On Lima the seed is
  a root-only data file Lima writes on every boot, and its copy stays in Lima's
  0700 instance directory on the host, so it is not deleted after first boot;
  VM root holds the host key anyway (owner's decision, 2026-11-25). Lima's own
  guest user keeps SSH for Lima's readiness check but has no sudo, so only the
  pinned key reaches root.
- Inbound: SSH from the host only. The VM MUST NOT be reachable from the LAN.
- Outbound: NAT through the host for the gateways' upstream connections.
- Two disks: a **system disk** (the signed image), mounted read-only with
  dm-verity so an offline modification fails verification at boot, and a
  persistent **state disk** at `/var/lib/sandbox` for everything that changes.
  This gives distribution and boot integrity. It is **not** runtime integrity
  against VM root, which can change anything in memory; that is covered by §4,
  not by the image. Upgrades swap the system disk and keep the previous one for
  rollback (§10).

#### 5.2.6 Host reach (decision D-15)

User-mode and NAT networking in the supported drivers can expose the host
itself to the VM (for example, Lima publishes the host as
`host.lima.internal`). Under the threat model this would let VM root reach
host loopback services. Therefore:

- **Default:** the VM MUST NOT reach any host address or host loopback
  service. This MUST be enforced by a **host-side or hypervisor-side**
  control, because an nftables rule inside the VM can be removed by VM root.
  Spike S7 determines the control per driver.
- **Declared exception:** the operator MAY declare host or VPN-only endpoints
  for a Tier 3 session (`--infra-endpoint`, an `--infra-kubeconfig` whose
  server is host-local, or a `host_endpoints:` config entry). Each declared
  endpoint passes the blocked-destination checks and is reachable from the VM
  only on the declared port and only for the session's lifetime. The host-side
  control scopes an endpoint to **the VM**, because every session gateway
  leaves through the VM's single uplink. Scoping it to **one session's
  gateway** is enforced by nftables in the VM and is defense in depth against a
  gateway compromise, not against VM root. This replaces v2's same-node `toEntities: host` grant and
  covers local k3d/podman clusters and VPN-routed clusters.
- VPN-routed destinations reached through the host's routing table (not via a
  host address) need no exception; the gateway's NAT'd connection follows the
  host routes. S7 MUST confirm this per driver.
- The control MUST cover IPv4 and IPv6, every host alias the driver publishes,
  and the host's gateway addresses, and MUST hold after VM root removes every
  VM-local firewall rule.
- **Upstream DNS is the one standing host service.** The VM's upstream
  resolver is reached through the driver (Lima's host resolver, or an explicit
  resolver on Windows). It is allowed for DNS only. DNS-based exfiltration by
  VM root through it is not a new exposure, because VM root already has NAT'd
  internet access.
- **Measured on `lima-vz` (S7, Lima 2.3.0, `docs/design/spikes/S7.md`):**
  Lima's `networkOpts.hostLoopback` (vz only, default true) lets the guest
  reach host loopback-only and all-interface services through
  `host.lima.internal` (192.168.5.2) and the host's LAN address. Set to
  `false`, all three measured targets were blocked while outbound NAT kept
  working. Lima's own comment says LAN-address reach remains; that did not
  reproduce, and the cause is unknown. Because the setting lives in the
  hypervisor's NAT, VM root cannot change it. Therefore **whenever a `lima-vz`
  VM uses Lima's built-in user-mode NAT, the driver MUST set
  `hostLoopback: false`**. It is defense in depth, not the control: it blocks
  all host reach (so it cannot scope declared Tier 3 endpoints), it does not
  exist for `lima-qemu` or Hyper-V, and IPv6 and VM-root tampering with routes
  are untested.
- **Lima's default network is already host-side userspace (S7).** On `lima-vz`
  the VM's NIC is served by gvisor-tap-vsock inside Lima's detached host agent,
  which outlives the CLI. So an owner that survives a detached keep-alive
  session exists today, and its one policy control is `hostLoopback`, which is
  all or nothing. Per-endpoint scoping of declared Tier 3 host endpoints is
  what stock Lima lacks, and making `sandbox netd` the VM's only NIC was not
  found to be configurable (an external Lima driver or a vfkit-based driver of
  our own are the untested routes). D-31 stands as the target for the
  per-endpoint requirement; `hostLoopback: false` plus the host agent is the
  baseline without it (`docs/design/spikes/S7.md`).
- **Measured with `sandbox netd` on vfkit (S7, 2026-11-25):** with netd as the
  VM's only NIC, VM root (VM-local rules removed) could not reach the host's
  LAN address, loopback, the gateway, or a host network's broadcast address;
  DNS, outbound HTTPS, and a declared endpoint worked; throughput matched
  Lima's built-in network. netd's forwarders refuse every address on any host
  interface (read at each connection), their directed broadcasts, loopback,
  link-local, multicast, and the VM's own network; the stack is IPv4 only, so
  the VM has no IPv6 path. A supervisor owns the VM's link (a datagram socket
  pair, one end given to vfkit) and restarts the stack worker, so the VM fails
  closed and recovers; if the supervisor itself dies the VM has no network
  until stopped. This is the `vfkit` driver (§5.2.2), the default on macOS.
  Open: Linux (qemu), Windows, split DNS, VPN routes, and hairpin NAT (a LAN
  router forwarding a public address back to the host is not caught by an
  address check).
- **Mechanism and owner (S7 evaluates first):** a host-side userspace network
  stack as the VM's only NIC (the gvisor-tap-vsock approach Lima's user-mode
  networking already uses), run by **`sandbox netd`** (D-31): a mode of the
  signed host binary that `sandbox vm start` launches detached and that lives
  exactly as long as the VM, as Lima's host agent does. It needs no launchd or
  systemd unit and is covered by the signed-binary verification (§5.1.1
  item 6). One host-controlled data path on all three drivers gives host-reach
  filtering, VPN routing, and split DNS (§5.8.9) uniformly, and corporate
  endpoint security sees the traffic as host-process traffic. Its cost is
  userspace TCP throughput, which S7 measures. If S7 shows stock Lima and
  gvproxy meet every requirement below, that is an acceptable alternative
  owner; per-driver native controls are the other.
- **Requirements on the owner (MUST):**
  - it holds the control while the `sandbox` CLI is not running (detached
    `--keep-alive` sessions);
  - it fails closed (no host reach) when its configuration is missing,
    unreadable, or while it restarts;
  - endpoints are opened only from host-parsed operator input at `run`, and
    closed on `stop`, on reap, or, for non-keep-alive sessions, on attach-lease
    expiry; never on a request from the VM;
  - endpoints of a `--keep-alive` session stay open until its reap limit, so a
    detached Tier 3 session keeps its declared cluster;
  - `sandbox status` and `sandbox doctor` report whether it is running, and
    any `sandbox` command restarts it if it died.

### 5.3 Appliance image

#### 5.3.1 Contents

- Ubuntu 24.04 LTS base, minimal.
- containerd (pinned), Kata Containers with Cloud Hypervisor (pinned guest
  kernel and guest image), nftables, nerdctl + buildkit (for `sandbox
  rebuild`), betterleaks, the gateway/resolver/broker binary, `sandboxd`, the
  in-VM `sandbox` policy layer, and preloaded agent images pinned by digest (the tested baseline;
  harness-only updates are delivered by §5.7.1).
- **Not included:** k3s, Cilium, CoreDNS, Helm, gVisor, Hubble, and the v2
  bash CLI (ported to Go, §5.4.1).
- Pins remain in `setup/versions.sh` (or its successor) and are managed by
  Renovate as today. Every downloaded artifact in the image build MUST be
  checksum- or signature-verified (fixes the unpinned-download class in
  Appendix B).

#### 5.3.2 Build and provenance

- Built in CI by a reproducible pipeline (tool choice open: mkosi, Packer, or
  scripted debootstrap). Requirements by level: pinned, verified inputs
  (MUST); reproducible appliance filesystem content (MUST); byte-identical
  serialized disk images across formats (SHOULD, validated separately);
  signed provenance and artifact signatures (MUST).
- Outputs per architecture (`amd64`, `arm64`): qcow2 (Lima qemu), raw
  (Lima vz), VHDX (Hyper-V).
- Each artifact MUST be signed (cosign, keyless or org key) with SLSA
  provenance and an SBOM. The host binary MUST verify before boot. It MUST pin
  the signing identity (cosign certificate identity and issuer, or the org key
  fingerprint) rather than accept any valid signature, and MUST refuse an
  `IMAGE_VERSION` lower than the highest it has installed unless the operator
  passes an explicit, audited `--allow-downgrade` (§10).
- Images are large; GitHub release assets cap at 2 GiB per file. Publish as
  OCI artifacts (e.g. `ghcr.io/samaritanark/agent-sandboxes-image`) so they
  can be mirrored for air-gapped installs.

#### 5.3.3 Per-install configuration (first boot)

Injected via a cloud-init NoCloud seed, never baked into the image: SSH public
key, corporate CA bundle, upstream DNS and proxy settings, split-DNS zones
(§5.8.9), resource sizing (from host RAM/CPU; logic from `lib/resources.sh`),
hostname. The gateway CA is generated in-VM on first boot (§5.10).

### 5.4 In-VM policy layer and `sandboxd`

#### 5.4.1 Policy layer (Go)

- The v2 bash CLI (`bin/sandbox`, `lib/*.sh`) is **ported to Go** (D-34) and
  ships in the image as the in-VM `sandbox` policy CLI, running only on the
  appliance VM. The ported code covers tiers, agents, config, profiles, links
  (validation), catalogue validation, masks, the secret gate, vetting
  verification, checks, and audit: roughly half of `bin/sandbox` and most of
  `lib/` (Appendix A.6). Behaviour is identical to v2 except where this
  document says a protection goes up.
- **One module, several binaries, trust boundaries kept.** The host binary,
  the in-VM policy CLI, and `sandboxd` are separate binaries in one Go module.
  The policy CLI runs **unprivileged**: it parses untrusted repo content
  (`.sandbox/config.yaml`, overlays, profiles) and MUST NOT run as root or
  inside `sandboxd`. It hands the session spec to `sandboxd` over a local
  socket, and `sandboxd` validates it (§5.4.2). Small shared packages hold the
  rule tables used by both the host-side sync gate and the policy CLI (mask
  set, exec-vector list, protected-branch defaults, blocked-destination
  rules), so there is one source of truth; the import-graph check in §5.1.1
  keeps the host binary from importing anything else from the policy side.
- **Strict decoding.** Profiles, overlays, config, and catalogue files decode
  into typed structs that reject unknown fields. v2's bash parsing is looser,
  so this is a protection gain.
- **Argv proxy unchanged.** The host binary still forwards arguments and
  parses no flags (§5.1.1, §5.1.6).
- **git and betterleaks.** The policy CLI shells out to the system `git`
  inside the VM with v2's hardening ported (OQ-14), and to the betterleaks
  binary for the secret gate. The host runs no git against `--repo` (N-09).
- **Oracle and differential testing (S8).** The v2 bash stays in the tree,
  frozen, as the oracle until release. Each ported module is tested against it
  on the same fixtures, and its bash is deleted only when outputs match on the
  v2 corpus plus the new adversarial cases. Before v3.0.0 is cut, the bash is
  deleted from the v3 line; v2 keeps it on its own branch (OQ-05).
- Removed, not ported: all `is_macos` / `is_wsl` branches, `lib/lima.sh`,
  `bin/sandbox.ps1`, `setup.ps1`, `setup/macos.sh`, the host install paths,
  `lib/cluster.sh`, `lib/network.sh`, `lib/dns.sh` (CoreDNS rendering),
  `lib/policy.sh` (CNP rendering; its domain-set logic at `:42-97` moves into
  the allowlist builder), the Kubernetes parts of `lib/manifest.sh`,
  `lib/dependency.sh`, `lib/secrets.sh`, `lib/credentials.sh`, and the
  gVisor/hostPath workarounds in `lib/filesystem.sh:1501-1674` (root-owned
  detritus). The mount-type mismatch check of `check_masking_paths` is kept
  as policy (owner's decision, 2026-11-25): a `masked_paths:` entry that
  exists as the other type (`foo` a directory, `foo/` a file) still refuses
  the launch with v2's message, because an in-guest overlay of the wrong type
  would otherwise mask nothing.
- `resolve_agent_home`, `resolve_workspace_mount`, and `resolve_pod_uid`
  become constants (uid 1000; VM-local paths).
- Running the gates in the VM is itself a protection increase: v2 runs git
  against an untrusted repo **on the host** and needs extensive hardening to
  stop repo config from executing code there (`lib/vetting.sh:367-485`). In v3
  that code runs in the VM; the hardening is ported to Go and kept as defense
  in depth.

#### 5.4.2 Session spec

The policy layer's output is a JSON **session spec** (a versioned Go type with
strict decoding, passed over a local socket from the unprivileged policy CLI)
handed to `sandboxd`. It
replaces the pod YAML, CNP, Secrets, ConfigMap, and Services of v2. It MUST
contain everything `sandboxd` and the gateway need and nothing else:

- session ID, name, agent, tier, image digest, command, resource limits;
- mounts: workspace copies, read-only exec-vector overlays, masks (empty file
  / empty dir), agent history and re-staged agent config (§5.7), CA bundle,
  MCP config, generated kubeconfig (placeholders only);
- environment, with placeholders in place of every credential;
- the egress allowlist (FQDNs and wildcards after apex expansion), merged
  block lists and CIDRs, L7 rules, declared host endpoints, declared extra
  ports;
- broker bindings (credential reference, destination hosts, injection
  method), never values;
- dependencies, each with its own image digest, port, egress allowlist,
  bindings, and resources, built **additive-from-empty** as in v2
  (`lib/dependency.sh:11-20`);
- keep-alive flag; audit metadata.

`sandboxd` MUST reject a spec that violates a structural invariant (a host
path outside the workspace store, a dependency with a workspace mount, a
capability, privileged mode, a credential value in env), mirroring v2's
`check_no_privileged_flags` and `check_dependency_no_host_mounts`.

#### 5.4.3 `sandboxd` responsibilities

`sandboxd` is a systemd service, written in Go, root in the VM, and never
reachable from any microVM. It:

1. Creates, starts, attaches to, and destroys Kata microVMs through containerd
   and the Kata shim (`io.containerd.kata.v2`), per the session spec.
2. Creates each session's network links and nftables rules (§5.8.2), and
   starts that session's gateway/resolver/broker instance.
3. Enforces the resource budget (§5.5.3) before creating anything.
4. **Teardown on every exit path.** Each attached session holds an **attach
   lease** renewed by the host binary's heartbeat. A non-keep-alive session is
   torn down when its lease expires for any reason: closed terminal, host
   binary SIGKILL, host sleep, network change, or a signal during launch before
   attach. The lease grace period (default 120 s, matching v2's
   `SANDBOX_TEARDOWN_REMINDER_GRACE`; overlay-configurable) lets a brief SSH
   drop or a short sleep reattach without losing the session. This closes all
   three v2 teardown bypasses (PRINCIPLES.md "Audit logs").
5. **Revocation.** On any end of a session (teardown, crash, OOM, eviction
   under memory pressure, operator stop, keep-alive reap), it stops the
   session's broker, destroys its bindings and placeholders, and records the
   end. Revocation does not depend on garbage collection.
6. **Keep-alive reaping.** Keep-alive sessions get an operator-configurable
   maximum idle time and a maximum lifetime; on expiry they are torn down and
   revoked (closes issue #94).
7. **Transcript capture.** At every session end it copies the transcript
   from the session's history store into the audit log (§5.12), so eviction no
   longer loses it.
8. Records `end_reason` from its own observations, never from data the
   microVM wrote.
9. Reboot behaviour: on VM boot it restarts keep-alive sessions whose
   lifetime has not expired (parity with v2 `restartPolicy: Always`) and
   reaps and revokes everything else. Restart needs the broker store key
   (§5.9.2), which the host binary pushes at VM start; if the VM reboots on
   its own with no host binary connected, those sessions wait for the next
   `sandbox` command to reconnect.
10. **Persistent, reconciled state machine** (D-23). Each session moves through
    `REQUESTED → ADMITTED → STARTING → RUNNING → STOPPING → TERMINATED`, with
    `FAILED` reachable from any state. State and every owned resource
    (containerd tasks, microVMs, netns, links, nftables sets, gateway and
    broker processes, bindings, mounts) are journaled before they are created.
    On start, `sandboxd` reconciles actual resources against the journal,
    finishes or rolls back partial starts, and tears down orphans **before it
    accepts new sessions**. Cleanup is idempotent and bounded in time; a
    resource that cannot be removed is recorded as `teardown-incomplete` in the
    audit log, as v2 does today.

### 5.5 Runtime: Kata Containers without Kubernetes

#### 5.5.1 Runtime

- Kata Containers with **Cloud Hypervisor** for every session and every
  dependency. Firecracker is excluded: it lacks virtio-fs, which workspace
  sharing needs. QEMU is excluded for attack-surface reasons.
- Driven by containerd directly, not by a kubelet. containerd provides image
  storage and snapshots; Kata provides the VM. S1 confirmed this works with
  containerd 2.4.2 and Kata 4.4.0 on arm64 (`docs/design/spikes/S1.md`), with
  three packaging constraints the image build MUST handle: the Cloud
  Hypervisor configuration and the Go shim ship in the separate
  `kata-go-static` bundle, not in `kata-static`; Kata accepts only its shipped
  configuration files, so `sandboxd` selects Cloud Hypervisor through
  containerd's runtime config path, not a custom `KATA_CONF_FILE`; and the
  shipped config enables no CPU or memory annotations, so per-session sizing
  is an open design item.
- gVisor is no longer the default (D-02; kept as an operator-chosen runtime since
  2026-11-27, with the sandbox's flags in the image's `/usr/lib/sandbox/runsc.toml`).
  Codex's own bubblewrap sandbox failed under gVisor
  (`lib/onboard.sh:211-264`); S1 records whether it works under Kata, and if
  so the `danger-full-access` override MAY be dropped. Agent-native sandboxes
  are optional defense in depth; Kata is the boundary, and parity never
  depends on them. Any compatibility override is documented and tested not to
  grant access outside the guest. S1 result (`docs/design/spikes/S1.md`):
  bubblewrap works under Kata with the §5.5.2 posture (UID 1000, no
  capabilities, `no_new_privs`) only with two in-guest compatibility
  overrides: the runtime's masked and read-only `/proc` and `/sys` paths
  removed, and a seccomp profile that permits user-namespace creation (the
  default profile blocks it). Both weaken in-guest defense in depth only; neither
  reaches outside the microVM. Whether Codex takes them, or keeps the
  `danger-full-access` override, is open (OQ-16).

#### 5.5.2 Workload hardening (parity with v2 pod hardening)

Inside each guest: the agent runs non-root (uid 1000), with
`no_new_privileges`, all capabilities dropped, the default seccomp profile,
no service-account token, no container runtime socket, no access to
`sandboxd`, and no route except its link. Dependencies additionally run as a
non-zero catalogue `run_as_user` with no workspace or history mount
(`lib/catalogue.sh:189-198, 243-257`).

**Guest seccomp is off by default in Kata.** S1 found that the shipped Kata
configuration sets `disable_guest_seccomp = true`: the container's seccomp
profile reaches the VM but is not applied (`Seccomp: 0` inside the guest). The
image's Kata configuration MUST set it to `false`, and P-02 MUST read
`Seccomp: 2` from inside a real guest. Compatibility of the default profile
with each supported agent is an S2 question; it blocks user-namespace creation,
which is why Codex's bubblewrap fails under it (§5.5.1).

#### 5.5.3 Resource model

- Each microVM's memory is fixed at creation (guest memory plus Kata
  overhead). `sandboxd` MUST refuse to start a session or dependency if the
  sum of committed microVM memory would exceed the VM's memory minus a
  reserve. This preserves the v2 invariant "memory is not overcommitted; CPU
  may be" (`lib/resources.sh:12-16`) without a ResourceQuota, and fixes the v2
  caveat that the clamp to one pod violates it on undersized nodes.
- Per-session defaults start from v2's limits (1 CPU request / 4 limit, 2 Gi
  / 6 Gi, 20 Gi ephemeral) and are re-measured in S1 with Kata overhead.
- The per-session dependency ceiling (`SANDBOX_MAX_DEPS_PER_SESSION`, default
  6) is kept.
- VM sizing keeps the v2 Lima logic (`lib/resources.sh:144-189`) for all
  drivers, with the same `--vm-cpus` / `--vm-memory` / `--vm-disk` overrides.

### 5.6 Workspace model and sync

#### 5.6.1 Model

- Each `--repo` maps to a **repo ID** (stable hash of the canonical host
  path). The VM holds one working copy per repo at
  `/var/lib/sandbox/workspaces/<repo-id>/` on the state disk, including `.git`
  (the gates need refs, tags and objects).
- All sessions using that repo mount the **same** copy (§5.13).
- The host binary drives a two-way sync between the host repo and the VM copy
  over the control transport. The sync starts with the first session on that
  repo, is reference-counted, and is flushed and stopped after the last
  session ends.
- Tier 1 remains an empty scratch directory; no sync.
- v2's repo-path refusals carry over unchanged (credential directories,
  `$HOME`, the agent-sandboxes install, `~/.sandbox`, the overlay;
  `lib/filesystem.sh:50-145`).

#### 5.6.2 Sync rules (security-relevant)

All rules below MUST be enforced by the **host side** of the sync, because VM
root may control the VM side, including a tampered sync endpoint that
misreports changes.

**Host-side sync gate (D-24).** The sync engine MUST NOT have direct write
authority over the host checkout for VM-origin changes. VM → host changes are
staged, then validated and applied by a host-side gate in the host binary.
Host → VM transfer MAY use any engine. The gate MUST:

- validate canonical relative paths and reject traversal;
- classify paths **case-insensitively and Unicode-normalization-insensitively**
  on hosts whose filesystem is either (APFS and NTFS defaults). Otherwise
  `.GIT/hooks/pre-commit`, legal and distinct on the VM's ext4, lands in the
  host's `.git/hooks/pre-commit`;
- refuse symlinks that resolve outside the repo, hard links, Windows
  junctions and reparse points, and file-type changes (file → symlink or
  directory) on any classified path;
- resolve paths race-safely (open relative to a directory handle, no
  follow-symlink), write atomically, and enforce per-file and per-batch size
  limits;
- detect conflicts and never pick a winner silently (the one deliberate
  exception, staging-only conflicts in the index, is rule 7);
- survive interruption: a half-applied batch is resumed or rolled back.

**Withheld changes are quarantined, not dropped.** A VM-origin change to a
protected path (rules 1–3 and 6–8) is kept in a quarantine area, recorded in the
session audit log, and listed by `sandbox sync review` with a diff, for the
operator to apply or discard explicitly.

1. **Masked paths never cross in either direction.** The built-in mask set
   and each repo's `masked_paths:` are excluded host → VM, **and** any change
   to a masked path made in the VM is never written to the host. (Without the
   second half, an agent could create `.env` in the VM and overwrite the
   operator's real `.env`.) In-guest empty overlays remain as defense in depth.
   S1 found that Kata's file mask truncates any file already present at that
   path in the VM copy when the microVM starts (directory masks and read-only
   overlays do not). This is harmless only because masked files are never in
   the VM copy; the gate MUST NOT report the empty placeholder as a change,
   and P-12 MUST assert that the VM copy never holds real content at a masked
   path.
2. **Host-exec vectors never flow VM → host.** These paths are synced host →
   VM only; creation, modification, or deletion of them in the VM is never
   propagated:
   - `.git/config`, `.git/hooks/`, `.git/info/`, `.git/objects/info/`
     (alternates and http-alternates), `.gitmodules`;
   - `.git/modules/*/config`, `.git/modules/*/hooks/` (submodule git dirs);
   - `.git/worktrees/*/config.worktree`, and `.git/config.worktree` (main
     worktree, when `extensions.worktreeConfig` is set);
   - hook-manager config that runs on the operator's next host commit:
     `.pre-commit-config.yaml`, `lefthook.yml`, `.lefthook*`;
   - `.lfsconfig` (it can redirect git-lfs traffic, with the operator's
     credentials, to another endpoint);
   - the directory named by the host repo's effective `core.hooksPath`
     (for example `.husky/`, `.githooks/`), resolved on the host;
   - `.vscode/`, `.idea/`, `.devcontainer/`;
   - agent-tool config that executes on the host: `.claude/settings*.json`,
     `.claude/hooks/`, and equivalents for the other supported agents;
   - additions from the OQ-07 review (`.envrc`, `mise`/`.tool-versions`, and
     anything else S4 finds that auto-executes without a trust prompt).

   This closes v2's "protected only if present at launch" gap
   (PRINCIPLES.md "Filesystem isolation") and the `core.hooksPath` gap. In-guest
   read-only mounts remain as defense in depth.
3. **Symlinks** that resolve outside the repo are never propagated VM → host.
4. **Conflicts** use two-way-safe semantics: never silently pick a winner;
   surface conflicts in `sandbox status` and the session log.
5. The sync tool runs as the operator on the host and as a dedicated
   non-root user in the VM. It MUST NOT be reachable from any microVM.

6. **Refs, `HEAD`, and objects (VM → host).** The gate parses refs as files
   (no git execution on the host, N-09) and applies them per ref. `packed-refs`
   is parsed into individual updates and never copied as a file.
   - **Objects.** A loose object's content MUST hash to its path before it is
     written. A pack is accepted only together with its `.idx`, verified the
     same way, or through the bundle path (§5.6.4 item 5).
   - **Local branches.** A VM-origin update to `refs/heads/*` is applied
     directly only when it is a **fast-forward** of the host's current value
     (the gate walks commit objects to check) and the branch is not protected.
     Creating a new unprotected branch is applied. Protected branches are
     `master`, `main`, the default branch named by the host repo's
     `refs/remotes/origin/HEAD` when present, and a `protected_branches:` list
     (operator config; overlays may add, never remove). An update to a
     protected branch, a non-fast-forward update (rebase, amend, reset), and a
     branch deletion are quarantined and applied only by `sandbox sync review
     --apply`. This keeps commits made on the operator's behalf direct, and it
     enforces PRINCIPLES.md's "never commit to `main` / `master`" in the gate
     instead of in a host hook the agent can skip with `--no-verify`.
   - **`HEAD`.** Synced two-way, but a VM-origin `HEAD` is accepted only as
     exactly `ref: refs/heads/<valid-name>` naming a branch that exists on the
     host once the ref updates are applied (protected branches included, since
     switching commits nothing), or as a detached SHA that exists in the host
     object store. Anything else (tags, remotes, `..`, extra lines) is
     refused. A `HEAD` changed on both sides since the last sync is a
     conflict. Every VM-origin `HEAD` change is recorded and shown in
     `sandbox status`.
   - **Never VM → host:** `refs/tags/*`, `refs/remotes/*`, `.git/logs/`
     (reflogs), `FETCH_HEAD`, `ORIG_HEAD`, `.git/objects/info/`, `.git/shallow`.
     The one exception is the vetting tag, which the host binary writes itself
     (§5.1.3).
   - **Ledger.** The gate records every VM-origin ref and `HEAD` update (ref,
     old and new SHA, session) in the audit log. `sandbox vet` lists the
     commits at `HEAD` that came from the ledger and requires acknowledgement
     (§5.1.3).
   - Host → VM: all refs and `HEAD` flow unconditionally.
7. **Index (two-way, merged by entry).** `.git/index` is never copied as a
   file. The host binary parses it in Go (strict size and entry-count limits,
   checksum trailer verified; it MUST read index versions 2, 3, and 4, because
   the guest image enables `feature.manyFiles`, OQ-17) and merges it per path
   and stage, three ways:
   the last-synced snapshot, the host index, and the VM index. A path changed
   on only one side takes that side's entry, so `git add`, `git reset`,
   `git rm`, branch switches, and merge-conflict stages carry both ways in
   near real time. VM-origin entries are validated like file changes:
   - entries on masked or exec-vector paths, gitlinks, and file-type changes
     are withheld (the host keeps its own entry);
   - the `assume-valid` and `skip-worktree` flags are cleared, because they
     hide changes from `git status`;
   - an entry whose blob is not in the host object store (hash-verified) is
     dropped;
   - extensions (split index, untracked cache, fsmonitor token, and the rest)
     are never accepted; the host writes a plain index with zeroed stat data,
     which git refreshes on first use.

   The gate takes `.git/index.lock` as git does, writes atomically, applies
   batches briefly, and defers if the operator's git holds the lock. The
   merged result is pushed to the VM, so the agent sees the operator's staging
   and the VM index matches `HEAD` after a host branch switch or merge. If both
   sides staged the same path differently, **the host wins and the conflict is
   recorded in the session log**; only staging is lost, and the agent's file
   content is untouched. This is the one deliberate exception to "never pick a
   winner silently". In-progress operation state (`MERGE_HEAD`,
   `rebase-merge/`) stays local, and conflict resolution still collaborates:
   conflict stages and marker files sync, the agent's `git add` returns a
   resolved entry, and the operator completes the merge on the host. If S4
   cannot meet N-20 for the merge, the fallback is a **HEAD-derived
   reconcile**: when `HEAD` or a branch tip moves, the gate sets the host index
   entry of each changed path to the new commit's blob unless the operator
   staged that path differently. Its cost is that agent staging without a
   commit does not reach the host index.
8. **`.gitattributes` (all depths).** A VM-origin change that adds or changes a
   `filter=`, `diff=`, or `merge=` attribute is quarantined, because it routes
   the operator's later `git diff`, checkout, or merge through a driver defined
   in their own git configuration, with agent-chosen input. The exact git-lfs
   triple (`filter=lfs diff=lfs merge=lfs`) and attributes that name no driver
   (`text`, `eol`, `binary`, `-diff`, `linguist-*`) pass. `.git/info/attributes`
   is already an exec vector (rule 2).

Tooling (Mutagen or an alternative, pinned and checksum-verified), transport,
per-path directionality, and the behaviour of concurrent git use on host and
VM are validated in spike S4.

#### 5.6.3 Pre-launch gates

The secret gate (betterleaks) and vetting verification run **in the VM**
against the synced copy, before any microVM is created, with semantics
unchanged from v2: fail-closed gate, encrypted-at-rest exemptions, vetted
exceptions, `vetting_exceptions_from_commit`,
`vetting_exceptions_require_head`, `vetting_forbid_unvetted_override`, the
inference-endpoint trust prompt, and audited `--i-accept-*` overrides
(`lib/filesystem.sh:1292-1499`, `lib/vetting.sh:735-966`). Trust roots come
from the pushed operator state (§5.1.4).

Known change: repo content (minus masked paths) now reaches the VM state disk
before the gate runs, rather than being gated in place on the host. Under §4
this exposes it only to an attacker who already has VM root, which already
reaches other sessions' copies. Accepted.

#### 5.6.4 Git consistency contract

General file sync does not preserve git's transactional semantics. v2 on macOS
already syncs the whole repo, `.git` included, with Mutagen `two-way-safe`
(`lib/lima.sh:285-307`), so this risk exists today; v3 makes the contract
explicit:

1. Lock files (`*.lock`) and in-progress operation state (`MERGE_HEAD`,
   `rebase-merge/`, `rebase-apply/`, `CHERRY_PICK_HEAD`, `sequencer/`) are
   never synced; each side keeps its own. The `index` is not copied as a file;
   it is merged entry by entry (§5.6.2 rule 7).
2. Objects and packs are synced; they are content-addressed and append-only.
3. Refs and `HEAD` sync host → VM unconditionally and VM → host under
   §5.6.2 rule 6. A ref or `HEAD` changed on both sides since the last sync is
   a conflict, surfaced and never resolved automatically.
4. Concurrent mutation of the **same branch** on host and VM is unsupported.
   `sandbox status` and the session log detect and report it; `--worktree`
   (§5.13) is the supported way to work concurrently.
5. Submodules and git LFS are covered by S4's test list. The fallback, if
   S4 cannot meet "no silent corruption or lost changes", is transactional
   transfer: VM commits leave as a git bundle that the host fetches into the
   operator's repo, which is ordinary fetch semantics, run with the host
   repo's own (protected) config.

What each side sees (target behaviour, validated by S4 and N-12/N-19/N-20),
with sync latency of seconds:

| Operation | What the other side sees |
|---|---|
| File edit, create, delete (non-protected path) | The change, both directions |
| `git add` / `git reset` / `git rm` | Index entries merge both ways (§5.6.2 rule 7) |
| Commit on a non-protected branch (either side) | The branch tip moves; the other side's index and files follow |
| Branch switch or `git checkout <sha>` (either side) | `HEAD` follows (§5.6.2 rule 6); files and index follow |
| Merge or rebase finished on the host | Refs, files, and index follow in the VM |
| Merge conflict started on the host | Marker files and conflict stages appear in the VM; the agent resolves and `git add`s; the operator completes the merge on the host |
| Commit on a protected branch, history rewrite, branch delete, tag, or remote ref (from the VM) | Withheld; listed by `sandbox sync review` |
| `MERGE_HEAD`, `rebase-merge/`, lock files | Stay local to each side |

This is an intentional parity decision, recorded as D-25 and D-30: v2 Linux
shares one `.git` directly; v3 shares it through this contract, with the
host-side gate enforcing protection so that collaboration stays direct.

### 5.7 Agent home and history (decision D-14)

v2 mounts one per-agent directory read-write into every session of that agent,
across repos and tiers, and keeps OAuth tokens in it
(`lib/manifest.sh:557-562`, `lib/onboard.sh:23-35`). An agent in one session
can therefore read its token and plant settings or hooks that take effect in a
later session on a different repo or tier. v3 replaces it:

1. **Tokens never live in agent home.** They live in the broker (§5.9).
2. **History is per agent, per repo, and per tier**, at
   `/var/lib/sandbox/agent-history/<agent>/tier<N>/<repo-key>/`, where
   `repo-key` is the repo ID, or for a multi-repo session the hash of the
   sorted set of repo IDs. History holds conversation state and transcripts,
   so the agent's own resume (`claude --resume`, `/resume`) keeps working per
   repo and tier. A conversation cannot be resumed at a different tier; this
   is deliberate, so lower-tier history never feeds an agent that holds
   higher-tier access.
3. **Tier 1** history is per session and destroyed at teardown.
4. **Executable agent config and global instructions are re-staged at every
   launch** from the operator's onboarded copy on the host, as a **writable
   copy discarded at teardown** (some agents write their config at runtime:
   Claude keeps `.claude.json` in its config directory, `lib/manifest.sh:283-287`,
   so a read-only mount would break it). The re-staged set is enumerated per
   agent in S2 and includes `settings.json`, hooks, plugins, MCP config,
   agent-level instruction files (for example the agent home's `CLAUDE.md` or
   `AGENTS.md`), and per-agent hardening (Codex `sandbox_mode`, Grok
   `disable_codebase_upload` and telemetry off, `lib/onboard.sh:211-392`).
   Writes inside the guest do not persist.
   Per-project agent memory is history-like and follows the history scope in
   item 2; it is the one prompt-injection persistence channel that is kept,
   for the same reason conversation resume is kept.
5. Sessions of the same agent on the same repo at the same tier share history
   and are one trust domain for it. Sessions at different tiers never share
   history (D-14). The working tree itself is still shared across tiers
   (§5.13, OQ-06): it is the work product and the operator reviews it, unlike
   history.
6. The session-scoped MCP config stays a separate read-only mount, as in v2
   (`lib/agents.sh:252-259`).

#### 5.7.1 Agent harness updates (D-35)

Harness releases are frequent, and rebuilding an image for each one is the v2
maintenance burden this section removes. The appliance image ships a **tested
baseline** of every agent harness, pinned by digest. A harness-only update
does not need a new image:

- `sandbox agent update <agent> [--version V | --channel C]` is
  **operator-initiated and out-of-session**; no agent and no session can
  trigger it. `sandbox agent status` lists the baseline, installed, and
  available versions, and `sandbox agent rollback <agent>` returns to the
  previous one.
- The vendor's own documented install path for a specific version (S2 records
  it per agent, Appendix D) runs in a **short-lived updater microVM**, the
  onboarding-microVM pattern (§5.9.6), with egress limited to that vendor's
  download hosts. It has no workspace, no history, and no credentials.
- `sandboxd` validates the output (regular files and directories only, no
  symlinks leaving the tree, no setuid or setgid bits, size caps), verifies
  integrity as the recipe allows (below), records version, source, and digest
  in the audit log, and promotes it to a versioned, root-owned directory
  `/var/lib/sandbox/agents/<agent>/<version>/` on the state disk.
- Sessions mount the selected version **read-only** over the image's copy.
  Nothing an agent writes persists in it, so an update cannot become a
  persistence channel (N-08 still holds).
- The in-session self-updater is turned off where the agent offers a switch
  (S2 records it), and the session's closed egress stops it otherwise.

**Integrity levels**, set per agent in its recipe (S2): **signed** (a
verifiable signature or signed manifest from the vendor), **attested**
(registry-level provenance or signatures), **checksum** (a digest the vendor
publishes at the same origin as the download: it catches corruption, not a
compromised origin), and **TLS-only** (a download over TLS from the vendor's
host with no published checksum). The updater performs the verification
itself and does not rely on the vendor's install script: S2 found that one
script skips its check silently when the digest file is unavailable, and two
verify nothing. Signed, attested, and checksum updates proceed after showing
the operator the old and new versions and the digest. A TLS-only update additionally requires `--accept-unverified-download`,
which is audited. S2 (`docs/design/spikes/S2.md`) placed the supported
harnesses by what their vendors publish: claude **signed** (a GPG-signed
manifest, verified against a pinned key), codex and copilot **checksum**,
grok and opencode **TLS-only**. An org overlay may require signed-or-attested only, may
disable self-update entirely so that only the image baseline runs
(`agent_update: disabled`), and may set a minimum release age
(`harness_min_age_days`) before a version is offered. Overlays can only
tighten.

**Compatibility.** The image carries a tested version range per agent (S2 and
N-04 run against the baseline). A version outside the range prints a warning
and needs `--allow-untested`. The broker adapters (§5.9.4) and the re-staged
config set (§5.7 item 4) were written against tested versions, so an untested
version is expected to fail closed (authentication errors), not to leak.
`sandbox doctor` reports the active version per agent and whether it is in
range.

### 5.8 Networking and egress

#### 5.8.1 Principle

Egress is enforced by **topology**: each microVM has one link, and that link
reaches only its session's gateway and resolver. Policy decides what the
gateway forwards; topology guarantees nothing bypasses it.

#### 5.8.2 Per-session links

- **Per-session gateway namespace.** `sandboxd` creates one network namespace
  per session (D-26). The session's gateway, resolver, and broker run inside
  it as a dedicated unprivileged user, under a seccomp profile, with only that
  session's bindings loaded. The namespace has one link per microVM of the
  session (agent and each dependency) and one NAT'd uplink to the VM root
  namespace. The guest speaks TLS, HTTP, and DNS directly to these processes,
  so they are the guest's first attack surface; this placement means a parser
  exploit there yields one session's namespace and bindings, not VM root.
- **Cross-session reach is impossible by construction.** Session links
  terminate in different namespaces with no route between them. (With all
  links in one shared namespace, Linux's weak-host model would accept a packet
  for any local address on any interface, and isolation would depend on
  nftables being exactly right.)
- nftables inside each session namespace, installed by `sandboxd` before the
  microVM starts:
  - no forwarding from a microVM link (the guest has no route, only the
    gateway);
  - input from a microVM link only to the gateway listeners (443, declared
    extra ports, dependency ports) and resolver (53/UDP+TCP);
  - everything else dropped **and logged**; drops are recorded in the session
    audit log as bypass attempts.
- **Root-namespace input filtering.** The uplink also connects the gateway
  namespace to the VM root namespace, so `sandboxd` MUST install an `input`
  rule in the root namespace on each uplink interface that drops everything
  except what the gateway legitimately needs (and nothing from the gateway to
  `sandboxd`, `sshd`, or any other root listener). S5 verified that such a rule
  stops the gateway namespace reaching the VM's `sshd`.
- Session identity is the namespace. The gateway serving it belongs to exactly
  one session, so no source-IP mapping exists to go stale.
- Plumbing SHOULD use the standard CNI `ptp`/`bridge` and `firewall` plugins
  driven through go-cni from `sandboxd`. Bespoke netlink or nftables code is
  written only where CNI cannot meet this section (S1). S1 measured this
  topology on Kata 4.4.0 (`docs/design/spikes/S1.md`):
  - The `ptp` plugin, executed **inside the gateway namespace** with the agent
    namespace as `CNI_NETNS`, puts the host end of the link in the gateway
    namespace and the guest end in the agent namespace, leaving no veth end in
    the VM root namespace. A Kata microVM started on that namespace
    (`ctr run --with-ns network:/var/run/netns/<agent-ns>`) got the interface
    and address and reached the gateway.
  - **Namespaces are single-use.** Killing a microVM leaves Kata's traffic
    control redirect on the guest-side interface, and a new microVM on the
    same namespace fails (`Failed to add qdisc ... file exists`). `sandboxd`
    MUST delete and recreate both namespaces per session.
  - **Weak-host rules are required.** The gateway namespace answers ARP for,
    and accepts packets addressed to, its uplink address on the guest link.
    The input chain MUST drop traffic from the guest link whose destination is
    not the gateway's link address or whose source is not the guest's address;
    both rules fired in testing. Forwarding stays disabled in the gateway
    namespace (`net.ipv4.ip_forward=0`), so nftables is a second layer.
  - A new namespace has no working resolver: it inherits `127.0.0.53`. The
    gateway's upstream resolver address MUST be set explicitly (§5.8.9).

#### 5.8.3 Filtering resolver

For names allowed for the session and not blocked, the resolver returns the
gateway's link address (A only; AAAA empty unless IPv6 is enabled).
Everything else returns NXDOMAIN, and nothing is forwarded upstream for it.
Dependency names (`<dep>.deps.sandbox.internal`) resolve to the gateway. A
dependency with an empty egress list resolves nothing except its own
upstream-free names (parity with v2's explicit `dns: []`). The resolver
answers absolute names directly, so v2's `ndots:1` workaround is unnecessary.

#### 5.8.4 Gateway connection handling

1. Read SNI; re-check it against the session allowlist and the merged block
   lists (org ∪ overlay ∪ user). Missing SNI → deny.
2. Resolve the upstream with the VM resolver; deny if any resolved address is
   in `blocked_cidrs` (deny wins; DNS-rebinding and IMDS defense), including
   IPv6 addresses (v2 checks IPv6 literals only at runtime in Cilium). The
   gateway MUST connect to exactly the address that passed this check and MUST
   NOT re-resolve between check and connect. S5 (`docs/design/spikes/S5.md`)
   found no post-resolution CIDR deny in Envoy and enforced this in nftables:
   a rule on the gateway namespace's `output` chain rejects connections to a
   blocked address, which checks the address actually dialled. The gateway's
   DNS queries to the upstream resolver are exempted from that rule.
3. **Passthrough by default** (TCP splice after the SNI check).
4. **Intercept (TLS termination)** only for destinations that carry L7 rules
   or credential injection (§5.8.5, §5.9). Re-encrypt upstream, validating
   against system roots plus the corporate CA bundle. S5 found that Envoy
   checks the certificate chain but accepts a certificate for the **wrong
   name** from a trusted CA unless a subject-alternative-name matcher is
   configured, so the controller MUST emit an explicit SAN match for every
   intercepted upstream (`docs/design/spikes/S5.md`).
5. Supports HTTP/1.1, HTTP/2, upgrades (WebSocket and SPDY for `kubectl exec`
   and `port-forward`), long-lived streams (watches, SSE model responses). S5 found upgrades are refused
   by default (HTTP 403) and must be enabled in the connection manager; once
   enabled, the HTTP filter chain, including `ext_proc`, still processes the
   upgraded stream, so injection and scrubbing apply. Only a raw handshake was
   tested; `permessage-deflate` would hide a token from a plain-text scan and
   MUST NOT be negotiated. S8 measured the rest: the upgraded stream reaches
   `ext_proc` as raw frames in chunks that do not follow frame boundaries, so
   the broker scrubs WebSocket frame by frame and refuses every other upgrade
   toward a brokered destination (SPDY included); upgrades leave over HTTP/1.1.
6. Supports chaining through a corporate upstream proxy or
   TLS-intercepting proxy when configured.
7. TCP 443 by default; other ports only when declared (parity with v2's
   443-only `toFQDNs`). Plain HTTP and non-TCP egress are denied.
8. Fail closed: if the gateway, resolver, or broker is down, unconfigured, or
   cannot evaluate a mandatory rule, the request or session has no egress.
9. Protocol edge cases (each has an adversarial test, §9):
   - **No usable SNI**, or an **Encrypted ClientHello** whose outer SNI is not
     the allowlisted name: deny. ECH to an allowlisted host is passthrough
     only if the outer SNI itself is allowlisted; otherwise it is denied.
   - **Authority mismatch** on intercepted connections: every HTTP/1.1 `Host`
     and HTTP/2 `:authority` MUST match the SNI's allowlisted name; mismatches
     are denied and logged.
   - **Connection reuse / HTTP/2 coalescing**: on intercepted connections,
     policy and credential binding are evaluated per request, never per
     connection.
   - **Redirects**: the gateway never follows redirects; the client's next
     request is evaluated on its own.
   - **CONNECT from the guest** (forward-proxy use) is denied, as Substrate
     does.
   - **Non-443 ports** (for example a Kubernetes API on 6443) only when
     declared, with the same SNI and CIDR checks.
   - **Domain fronting** on shared CDNs remains a residual in passthrough mode
     (it is in v2 too); destinations with L7 rules or credentials are
     intercepted, which closes it for them.

**Data plane.** The gateway SHOULD use a mature proxy data plane (Envoy is the
default candidate) with a small Go controller that compiles session policy,
bindings, and audit hooks into its configuration. TLS and HTTP parsing MUST NOT
be written from scratch unless S5 documents that existing implementations
cannot meet this section (D-27). Whether the data plane runs as one process per
session or as one process per session namespace is decided in S5 on footprint;
either way no process holds another session's credentials.

#### 5.8.5 L7 rules

- Schema: per-domain rule lists of `{methods, path_patterns, action}`,
  evaluated deny-first. Domains with rules are automatically intercepted.
  `path_patterns` are globs: `*` within one path segment, `**` across
  segments, and an optional `?query` part; the gateway controller compiles
  them to Envoy RE2 and tests them against the same Go matcher (owner,
  2026-11-25). A query condition holds when any occurrence of its parameter
  matches, compared percent-decoded, and only deny rules may have one: an
  allow satisfied by one occurrence would pass a request whose server reads
  another.
- **Org baseline** (shipped in `config/egress-baseline.yaml`;
  overlay-extensible; not removable by profiles or operators). The baseline is
  stated as **protocol rules and applies to every intercepted destination,
  whatever its domain** (D-33). A destination with a broker binding is always
  intercepted, so it always receives it:
  - Git smart HTTP is push-denied on every host: deny `POST` to any path ending
    in `/git-receive-pack` and `GET` with `service=git-receive-pack`
    (relaxation: OQ-02).
  - Package registries are read-only on every host that serves the registry
    API: npm-compatible (deny `PUT` / `DELETE`; this covers
    `registry.npmjs.org` and self-hosted Verdaccio, Artifactory, and Nexus),
    PyPI-compatible (deny `POST` to upload paths such as `/legacy/`), and the
    equivalent for each ecosystem the catalogue supports. This closes an
    exfiltration path v2 cannot see: `npm publish` with an attacker's own npm
    token, or with a brokered credential, to any registry.
  - `TRACE` and `TRACK` are denied (§5.9.3).
  - Residual, stated so the guarantee is not overread: a destination the
    operator allowlists with no binding and no L7 rule is passthrough and is
    not inspected. It carries no brokered credential, so a push or publish
    there has no brokered credential to use. An operator who wants the baseline
    on such a host adds an L7 rule for it, which makes it intercepted.
  - GitHub API writes (non-`GET`) denied except endpoints a supported agent
    requires (for example Copilot's own API), enumerated per agent in S2/S5.
    Left out of the shipped baseline until that list exists (owner,
    2026-11-25).
- The additive-only invariant extends to L7: overlays MAY add deny rules and
  narrow allows; they MUST NOT remove an org deny.

#### 5.8.6 Dependencies

Agent → dependency traffic goes through the gateway: the agent dials
`<dep>.deps.sandbox.internal:<port>`, the gateway forwards to that
dependency's link, and logs the request. Dependencies cannot reach the agent,
each other, or other sessions (parity with v2's ingress rule scoped to the
owning session, `lib/policy.sh:427-437`). Dependency egress goes through the
same gateway under the dependency's own catalogue allowlist. This also gives
v2's missing record of agent → MCP traffic.

#### 5.8.7 Allowlist sources (unchanged meaning)

All v2 allowlist sources keep their meaning and checks: per-agent domains,
per-tier domains, `--allow-domain`, `~/.sandbox/config.yaml`,
`SANDBOX_EXTRA_ALLOWED_DOMAINS`, profile `extra_allowed_domains`, per-repo
domains only from the vetted HEAD under the overlay opt-in
(`lib/vetting.sh:1025-1077`), infra endpoints and kubeconfig servers. Every
entry passes `check_egress_target_not_blocked` at add time, including the
over-broad wildcard refusal and apex handling (`lib/checks.sh`).

Wildcards now match multiple labels where the operator intends it. v2 needed
one entry per Copilot plan namespace because Cilium wildcards match a single
label (`lib/agents.sh:74-82`). The gateway's wildcard semantics MUST be
specified explicitly and tested, and MUST NOT silently widen any existing
entry: the default stays single-label, and multi-label is an explicit `**.`
form.

#### 5.8.8 Hot allowlist extension

`sandbox allow <id> --add-domain` keeps its v2 semantics (add-only, audited,
no restart, in-flight connections preserved) by updating the session
gateway's configuration.

#### 5.8.9 Split DNS and corporate networks

The VM's upstream resolver follows the host. Split-DNS zones (v2
`internal_dns_zones:` and systemd-resolved detection, `lib/dns.sh`) are
detected **on the host** by the host binary and pushed into the VM resolver
configuration. This replaces v2's Linux-only CoreDNS rendering and its
`--dns` flag, and extends split DNS to macOS and Windows.

#### 5.8.10 Enforcement layers

What each layer guarantees, so no requirement silently depends on the wrong
one:

| Layer | Enforces | Does not enforce |
|---|---|---|
| Kata guest + per-session namespace + links | The guest has no route except its gateway; no cross-session reach | Which names or paths are allowed |
| nftables in the session namespace | Only gateway and resolver ports reachable; drops logged | Anything above L4 |
| Filtering resolver | Only allowlisted names resolve; no upstream query for others | Connections to literal IPs (denied by topology and the gateway) |
| Gateway, TLS routing | SNI and authority on the allowlist; blocked CIDRs after resolution; ports | Request semantics on passthrough traffic |
| Gateway, L7 policy (intercepted only) | Method and path rules; install-not-publish; no-push | Anything on passthrough connections |
| Broker bindings | Real credential only toward its bound destination; misuse detection | What an authorized request does |
| Upstream RBAC/IAM | What the bound identity may do at all | — (operator-owned; §5.9.5) |

### 5.9 Credential brokering

#### 5.9.1 Requirement and source

> No credential that is usable outside the sandbox is readable inside an
> agent or dependency guest, except an explicitly authorized, audited
> `--allow-readable` exception.

Real credentials remain readable by the appliance-side broker. The
consequences by escape depth are in §4 and §5.9.8.

The credential-brokering design (`docs/design/credential-brokering.md`, on
branch `credential-brokering-design`, Draft, 2026-08-27) is the normative
specification for this section and MUST be merged to `master` before broker
work starts. Where this section and that document differ, that document wins
for semantics, and this section wins for placement in the v3 topology. Every
R1 item in that document is a v3.0.0 requirement.

#### 5.9.2 Placement

**One broker per session**, co-located with that session's gateway in the
session namespace, as the brokering design mandates. It runs as that
session's unprivileged user under seccomp. `sandboxd` (root) decrypts only the
session's bound credentials from `/var/lib/sandbox/broker/` (encrypted at
rest; the key lives in the operator's host keychain and is pushed by the host
binary over the control channel at VM start, held only in `sandboxd` memory or
a tmpfs and never written to the state disk; D-32) and hands them to the broker
at start. A stolen or backed-up state disk is therefore not enough to read the
store. On Windows the key is kept in Credential Manager. Where no host keychain exists (headless Linux), the key is a 0600 file
under `~/.sandbox` pushed the same way, and `sandbox doctor` reports the
weaker protection. The host seals entries itself; the VM stores them and never
holds the key on disk. VM root can still read the key from memory (§5.9.8). The broker never has
read access to the store. It is destroyed with the session (§5.4.3).

S5 prototyped this handover (`docs/design/spikes/S5.md`). Entries are
AES-256-GCM with the credential id as associated data: a flipped byte, a wrong
key, and an entry moved under another id were all rejected, and no plaintext
was on disk. The unprivileged user could not read the key, the store, or the CA
key. The broker received its secrets over its stdin pipe only (none in its
command line, environment, or any file) and held exactly its session's
bindings in memory: a credential bound to no session never entered it, and a
second session's broker held only its own. **A long-lived root process
retains plaintext after handing it over** (Go strings cannot be wiped), so the
decrypt-and-start step MUST run in a short-lived helper that exits after the
handover and writes the pipe synchronously before wiping its buffer. `sandboxd`
then supervises the reparented broker by cgroup or transient unit, not as a
child. The plaintext also lives in the gateway process's memory while it
injects, as §5.8.2 accepts.

Destroying a session's bindings is **local** revocation. Issuer-side
revocation of a long-lived credential stays the operator's responsibility, as
in v2; `sandbox stop` keeps v2's reminder.

#### 5.9.3 Placeholders and misuse

- Format: opaque, high-entropy, session-scoped (e.g.
  `sbxph_<session>_<name>_<random>`), JWT-shaped where a client parses tokens
  (S2 determines per agent).
- Injection is keyed on **destination and placeholder**. The broker overwrites
  (never appends) the header, strips hop-by-hop headers, never follows
  redirects, guards against request smuggling, and validates upstream TLS
  against the bound host.
- **Responses are scrubbed.** On every intercepted connection where the broker
  injected a value, the broker scans response headers and bodies for that value
  and its common encodings (base64, URL-encoding, the basic-auth pair),
  replaces matches with the placeholder, and records a `credential_reflection`
  audit event. This covers reflecting endpoints (`TRACE`, echo and debug pages,
  error pages that print the request) and `Location` headers that carry a
  query-injected credential. Headers are always scanned. Bodies are scanned
  with a streaming matcher that spans chunk boundaries, so SSE and other
  long-lived streams are covered; S5 measures the cost and may bound body
  scanning by size for non-streaming responses. S5 showed why this needs
  per-connection state: a scrubber that buffers the body delayed the first byte
  of a 5 s event stream until the end, one that skipped event streams leaked
  the token, and one that scrubbed chunk by chunk leaked a token split across
  two chunks, so the matcher MUST hold back the last `len(value) - 1` bytes of
  each chunk (the `ext_proc` streamed mode, not Lua). S5 built this as a Go
  `ext_proc` service: holding back only a suffix that is a proper prefix of the
  value added no delay to a live event stream, `failure_mode_allow` must be
  `false` (a stopped broker returned HTTP 500 and forwarded nothing), and in
  plain `STREAMED` mode the body must be returned as a per-chunk `body`
  mutation (the `StreamedBodyResponse` form belongs to `FULL_DUPLEX_STREAMED`
  and was silently ignored, which let the real token through while the broker
  logged success). N-04 therefore reads what the guest receives, not the
  broker's log. `TRACE` and `TRACK` are denied
  on every intercepted destination (§5.8.5).
- On intercepted connections, a placeholder seen toward an unbound destination
  MUST be blocked and recorded as a `credential_misuse` audit event.
  Passthrough connections are spliced after the SNI check and cannot be
  inspected; placeholders are worthless outside the sandbox, so this is not a
  gap. A real credential value seen leaving the session is recorded as a
  tamper signal.
- Per-credential rate limits and quotas apply.
- **Unbound secrets are withheld by default.** Readable injection into the
  guest requires a per-secret `--allow-readable` (or profile equivalent), is
  audited per session, and is listed truthfully as `brokered` / `injected` /
  `withheld`. The value never passes through `sandboxd` or containerd: a
  short-lived helper writes it from the broker store to a file on a tmpfs,
  mounted read-only into the agent's microVM at `/run/sandbox/secrets/<VAR>`;
  the environment carries `<VAR>_FILE`, and an attached command is wrapped in a
  shell that exports `<VAR>` from the file (an image without a shell gets the
  file only).

Brokering prevents credential **theft**, not credential **use**: the agent can
still act with a bound credential toward its bound destination, within the L7
rules. Tiers, bindings and L7 rules bound what that use can do.

#### 5.9.4 Credential kinds (R1)

| Kind | v2 (today) | v3 |
|---|---|---|
| User secrets (`sandbox secret`, profile `secrets:`) | Plain env vars in the pod (`lib/secrets.sh:188-214`) | Placeholder env var; each binding names hosts and injection (header, bearer, basic, query: query is flagged "degraded"). The binding is the secret's own (`sandbox secret set/bind NAME --bind HOST --inject KIND`, or `--allow-readable`), kept beside it on the host and sealed with its value, so the VM can use the value only as bound |
| `--infra-token` (incl. `NAME=PATH`) | `$INFRA_TOKEN*` in the pod | Placeholder bound to the `--infra-endpoint` host(s) |
| Agent OAuth (claude, codex, copilot, grok) | Token files in the shared agent home, readable by the agent | Broker holds access and refresh tokens; a per-agent adapter rewrites token-endpoint responses so the client only sees placeholders; the broker performs refresh (S2), so detached keep-alive sessions keep working. The account identity recorded at onboarding is re-checked after every refresh where the provider exposes it. Rotated tokens stay in the VM store; nothing flows back to the host (§5.1.5) |
| Agent API key (opencode) | Env var via a Secret (`lib/manifest.sh:311-325`) | Placeholder injected toward the configured provider host |
| Catalogue dependency secrets | Env vars in the dependency pod | Placeholders in the dependency, brokered by the session broker toward the dependency's bound hosts |
| Kubeconfig bearer token / static token | Mounted kubeconfig | §5.9.5 |
| Kubeconfig client certificate + key (mTLS), including the repo's Teleport recipe (`examples/teleport/bake-kubeconfig.sh:145-150`) | Mounted kubeconfig | **R1 in v3** (promoted from R2): the gateway holds the certificate and key and opens the upstream mTLS connection, passing `tls-server-name` through for Teleport TLS routing; the guest kubeconfig carries placeholders only (D-28) |
| Kubeconfig `auth-provider: oidc` | Rejected as unsupported | Decomposed on the host; secrets go to the broker, never the guest |

#### 5.9.5 Tier 3 Kubernetes access

- `--infra-kubeconfig` is ingested by the broker (after the v2 minify/merge
  logic, `lib/cluster.sh:186-333`), which keeps the real token or client
  credentials and CA.
- The guest receives a generated kubeconfig whose `server` points at a
  per-cluster gateway name (e.g. `https://kube-<n>.gw.sandbox.internal`),
  trusts the gateway CA, and carries no usable credentials.
- The gateway terminates TLS, applies the **minimal API-server deny-list** from
  the brokering design (Secret get/list/watch, TokenRequest, CSR
  create/approve, hostPath/privileged/hostNetwork workloads) plus any operator
  verb/resource rules, and originates the upstream connection with the real
  credentials.
- **Exec-plugin kubeconfigs are supported (R1)**, not rejected. v2 prompts or
  accepts `--allow-exec-plugin` and the auth then fails in-pod; v3 runs the
  plugin from a binary allowlist **on the host** (the plugin needs host
  auth-provider state, which MUST NOT enter the VM) via the exec-plugin token
  pump (§5.1.3). Credentials are short-lived, cached in broker memory with a
  TTL, `interactiveMode` is rejected, and disk caching is suppressed. Behaviour
  for a keep-alive session after the operator detaches is OQ-09.
  **The invocation is fixed on the host, not supplied by the VM:** at `run` the
  host binary captures each exec stanza (command, args, env,
  `provideClusterInfo`) from its own copy of the operator-supplied kubeconfig
  and keys it by an index. A pump request from the VM carries only that index
  and a session ID. The host runs exactly the captured invocation, refuses any
  index or session it did not issue, and rate-limits mints per session. The
  per-invocation classification (role ARN, cluster, profile) is recorded in
  the audit log, because a classification per binary alone does not bound what
  an argument change would authorize (D-19).
- **Every allowlisted plugin is classified by what its credential
  authorizes**, recorded in `docs/reference/credential-exceptions.md` and
  verified in S2:
  - **cluster-scoped** (pumped by default): for example `aws eks get-token`
    (a presigned STS identity token, minutes long, used only to authenticate
    to EKS) and `tsh` (short-lived Teleport client certificates);
  - **general-purpose cloud credential** (refused by default; overlay
    exception, audited per session): for example `gke-gcloud-auth-plugin`,
    whose gcloud access token works against GCP APIs well beyond the cluster.
  This bounds what VM root gains from the broker (§5.9.8).
- **The gateway is defense in depth, not authorization.** The API-server
  deny-list cannot make an over-privileged identity safe. Tier 3 identities
  MUST be least-privilege (PRINCIPLES.md: never `cluster-admin`, never an
  unscoped cloud account, never production). At launch the broker runs a
  `SelfSubjectRulesReview` with the real credential and warns on
  cluster-admin-equivalent rights; an overlay MAY make that a refusal. For
  OpenStack and other APIs, prefer project-scoped application credentials;
  generic method/path rules are not a substitute for upstream roles.

#### 5.9.6 Onboarding

`sandbox onboard <agent>` either imports the operator's existing host token
(as v2 does, `lib/onboard.sh`) or runs the agent's login flow inside a
sandboxed onboarding microVM with the broker in **capture mode** for that
agent's token endpoints. The host binary opens the browser or shows the
device code (§5.1.3). Real tokens land only in the broker store. Onboarding
records the account identity (where the provider exposes one) so the broker
can reject a refresh that returns a different account. v2's host-env
blocklist and refusal of long-lived keys carry over
(`lib/credentials.sh:26-48`, `lib/onboard.sh:62-90`). After the VM is deleted
or recreated, onboarding runs again; `sandbox upgrade` keeps the state disk
and does not require it.

#### 5.9.7 Audit and binding integrity

- Per-credential audit events are shipped to an **append-only sink outside the
  broker** (the session log written by `sandboxd`, pulled append-only to the
  host). The broker logs no values, bodies, or query strings.
- Bindings MAY be signed: the brokering design's signature-anchored binding
  library, anchored to the vetting trust root, is an R1 item.

#### 5.9.8 Accepted risk

- An attacker who exploits a session's gateway or broker gains **that
  session's** bindings only (§5.8.2, §5.9.2).
- An attacker with appliance-VM root can read the broker store and live broker
  memory: every onboarded agent token, every profile secret pushed for a
  running session, and the credentials of every running session. General-
  purpose cloud credentials are excluded by default (§5.9.5), which bounds the
  worst case. Kata plus the per-session namespaces is what protects the store;
  session-scoped revocation in `sandboxd` limits exposure in time.
- VM root cannot plant credentials in the host: there is no VM → host token
  flow (§5.1.5).

#### 5.9.9 Exceptions and later releases

- If S2 finds an agent cannot be brokered, it MUST be listed in
  `docs/reference/credential-exceptions.md`, require an explicit org-overlay
  allowance, and produce an audit event per session (OQ-01).
- R2+ items from the brokering design are recorded so v3 does not foreclose
  them: request signing (AWS SigV4, GCP JWT, OAuth client-credentials, HMAC),
  SSH keys and git-over-ssh via agent forwarding, and (R3+)
  database/wire-protocol proxies. (mTLS re-origination is R1 in v3; §5.9.4.)

### 5.10 Certificate authorities

- **Gateway CA:** generated in-VM on first boot (ECDSA P-256, at most one-year
  validity, rotated on rebuild or `sandbox ca rotate`). The private key is
  root-only on the state disk and never mounted into a guest, and the gateway
  never holds it (see below). **No CA private key is ever shipped in the image
  or repository.**
- **Distribution:** a combined bundle (system roots + gateway CA + corporate
  CAs) mounted read-only at the system bundle path, plus `SSL_CERT_FILE`,
  `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `GIT_SSL_CAINFO`.
- **Change from v2:** v2 bakes corporate CAs into the images at build time from
  `config/extra-ca-certs/` (`docker/Dockerfile.base`). v3 delivers them at
  runtime, so agent images are identical across installs. Both v2 sources
  (`config/extra-ca-certs/` and the overlay's `extra-ca-certs/`) are read, plus
  `~/.sandbox/extra-ca-certs/`. The pre-build TLS-intercept probe moves to
  `sandbox doctor`. `sandbox setup-proxy-cert` stays as a host operation with
  v2's flags; its default output becomes `~/.sandbox/extra-ca-certs/proxy-ca.crt`
  and its closing message says the CA applies from the next session, with no
  rebuild (owner's decision, 2026-11-25).
- **Per-session issuing certificates.** `sandboxd` (root) issues each
  session's gateway a per-session intermediate certificate, name-constrained
  to that session's intercepted names and valid for the session's maximum
  lifetime (or per-session leaf certificates, if S5 finds the intermediate
  unnecessary), and hands the gateway only that. The CA private key is never
  readable by the gateway user, so a gateway compromise yields a certificate
  good for one session's names, not for every site for a year. A hot-added
  intercepted name (§5.8.8) gets a re-issued certificate. Clients that ignore
  name constraints make the constraint defense in depth only; the key
  confinement is what holds. S5 measured this
  (`docs/design/spikes/S5.md`): with a critical name constraint, `pathlen:0`,
  and 2 h validity, OpenSSL rejected a leaf for `evil.com` signed by the session
  intermediate (`permitted subtree violation`), and one session's intermediate
  could not sign another session's host; subdomains of a permitted name are
  allowed. The gateway user could read its leaf key but not the intermediate or
  root key. Leaves are minted per host at session start, so a hot-added
  intercepted name needs the root helper to issue another. Nothing revokes a
  certificate before its end time, so a stolen leaf key is usable for the
  session lifetime. All seven stacks tried enforced the critical
  constraint (OpenSSL, curl, Python, Node, wget, git over GnuTLS, and Go's own
  `crypto/x509`), each checked against an unconstrained control; rustls,
  BoringSSL, Java, and the agents' bundled runtimes were not tested.

### 5.11 Dependencies (catalogue)

Unchanged from v2 except for the runtime and network path:

- Catalogue-only (org first, overlay may add, never override), digest-pinned
  images, kind `mcp` or `service`, forbidden privilege fields, `egress: '*'`
  forbidden, browser entries require signature verification
  (`lib/catalogue.sh:145-279`).
- Built additive-from-empty: no workspace, no history, no host paths.
- Created after the session microVM is running; launch aborts if any
  dependency fails; torn down with the session by `sandboxd`.
- MCP registration remains Claude-only until other agents are wired
  (`lib/agents.sh:266-271`); declaring `mcps:` for another agent fails closed.
- The browser residual risk warning stays, but the gateway now records URL
  paths and methods for intercepted dependency traffic.

### 5.12 Audit

Per session, under `~/.sandbox/logs/<session>/` (written in-VM by `sandboxd`
and the gateway, pulled append-only to the host at stop and periodically
during the session):

- `session.json`: v2 schema plus `runtime`, `image_version`, broker bindings
  (names and hosts, never values), `end_reason` from `sandboxd`, and the
  resolved agent-history key.
- Override events (`record_override`), vetting and secret-scan summaries,
  allowlist extensions, dependency up/down records: unchanged.
- **Gateway request log** per request: time, session, SNI/host, decision, rule
  ID, bytes; plus method and path for intercepted traffic. Replaces Hubble
  `flows.json`; `sandbox flows` reads it. **Redaction rules (MUST):** query
  strings stripped; no request or response headers logged except an
  allowlisted set (`Host`/`:authority`, `Content-Type`, `Content-Length`,
  `User-Agent`); never a credential or placeholder value; path segments that
  match credential-shaped patterns redacted; per-session log size capped. The
  audit trail must not become a second secret store.
- Link drops (bypass attempts), `credential_misuse` events, sync conflicts,
  withheld (quarantined) sync changes, `audit_gap` events (§5.1.5).
- Transcript copy, captured by `sandboxd` on every exit path, labelled
  **agent-reported** in `session.json` (the agent can rewrite it before
  capture). A gateway-produced record of the model exchange is F8.
- Workspace baseline and diff (`files.log`), computed in the VM.
- Retention: v2 writes `retention_days` into `session.json` but nothing
  enforces it (`lib/tier.sh:61-67`). v3 either enforces it in `sandbox cleanup`
  or removes the claim from the docs (OQ-08).

### 5.13 Concurrent sessions on one repo

- **Default:** sessions on the same repo share the one VM-local working tree.
  This matches v2 on Linux. On macOS v2 gives each session its own copy, so
  this is a behaviour change there and MUST be called out in the release notes.
- Shared-tree mounts MUST use virtio-fs settings that keep guests coherent.
  S1 measured the trade-off (`docs/design/spikes/S1.md`, Kata 4.4.0, nested on
  Apple M6): the shipped `cache=auto` is fast but a second microVM can read a
  stale file size for up to 1 s after an in-place overwrite (observed: 3 of 8
  bytes read), while `cache=never` is coherent but about 19× slower on
  metadata (20,000 files: `find` 12.3 s against 0.66 s). On a 100,000-file
  repository `git status` inside a microVM took about 10 to 13 s under `auto`
  and about 23 s under `never`, against 0.07 s natively in the appliance VM:
  **large repositories are slow under either mode**, because every `git status`
  re-stats every file across virtio-fs. This is an open usability risk for the
  shared-tree design, not a cache-mode choice; S1.md records
  the measured mitigations (git settings take about a third off; a virtiofsd
  thread pool and vCPU count showed no benefit) and the larger options (OQ-17).
  For typical repositories (a few thousand files) `git status` takes about
  0.2 to 0.4 s in the microVM. `metadata` and
  `always` cache attributes without expiry and are not acceptable for a shared
  tree. **Decision (OQ-15): `auto`.** The sync tool MUST write by atomic
  rename, which creates a new inode and avoids the stale-size case; the
  up-to-1-s window for in-place overwrites between two sessions is stated in
  the release notes.
- **Opt-in `--worktree`:** each session gets its own `git worktree` and branch
  under the repo's VM copy, sharing the object store. Worktree metadata stays
  VM-side (`.git/worktrees/` is never synced to the host, §5.6.2). The branch
  reaches the host through the shared object store and the ref rules in
  §5.6.2 rule 6 (fast-forward-only, never a protected branch).
- **Trust-domain warning:** launching a session that shares a tree with a
  running session of a different tier or allowlist prints a warning and
  records an audit event. An overlay MAY set `shared_tree_policy: deny`.
  Built (2026-11-27): `go/internal/cli/sharedtree.go`, read from the running
  sessions' records.

### 5.14 Session lifecycle

| Command | v3 behaviour |
|---|---|
| `run` | Host pushes state and starts sync → VM policy layer runs gates and builds the session spec → `sandboxd` creates links, gateway, broker, microVMs → host attaches the TTY |
| `stop` | `sandboxd` destroys the microVMs first (the containment action), then the broker and bindings, then captures audit, then the host pulls logs. This keeps v2's pod-first teardown order |
| `resume` | Re-attach to a running session; if the session is gone, recreate it after re-running every gate. v2's macOS blocker on recreation disappears. Its tier 3, profile, and opencode blockers stay until the broker lands; then recreation re-resolves the profile and rebinds tier 3 and opencode credentials from the broker store (owner's decision, 2026-11-25) |
| `--keep-alive` | Survives detach and VM reboot, subject to the reaper (§5.4.3) |
| `list`, `logs`, `status` | Read `sandboxd` state and logs |
| `check` | Unchanged preview of masks and scan results |

---

## 6. Configuration and schema changes

| Area | Change |
|---|---|
| Profiles `secrets:` | Each entry gains `hosts:` (required) and `inject:` (`header:<name>`, `bearer`, `basic`, `query`); `allow_readable: true` is the audited exception |
| Egress | New optional `l7_rules:` per domain (org, overlay, profile); org baseline in `config/egress-baseline.yaml`; explicit multi-label wildcard form `**.` |
| Host reach | New `host_endpoints:` (Tier 3 only) |
| Tier 3 | `--infra-token` requires `--infra-endpoint`; kubeconfigs handled by the broker; exec plugins supported via the host pump; an `--infra-endpoint` given as a URL is reduced to its host for the allowlist and the block check (v2 put the whole URL into the policy) |
| Overlay | `shared_tree_policy`, credential exceptions, L7 deny additions, exec-plugin allowlist, keep-alive maximums, `protected_branches` additions (§5.6.2), harness update policy (`agent_update`, `harness_min_age_days`; §5.7.1) |
| Agent home | `--homedir` is replaced by the per-agent-per-repo history model (§5.7) |
| Unchanged | Tiers, agents, catalogue, masks, exceptions, vetting keys, blocked destinations, persistent domains, profiles, links |

**Removed flags and commands.** Each MUST fail with a message naming the v3
replacement, never be silently ignored:

| Removed | Replacement |
|---|---|
| `install --dns` / setup.ps1 `-Dns` | Host-detected upstream DNS and split zones (§5.8.9) |
| `install --apiserver-port`, `--pod-cidr`, `--service-cidr` | None needed (no Kubernetes) |
| `install --vm-cpus/--vm-memory/--vm-disk`, setup.ps1 `-VmMemory/-VmCpus` | Kept as `install --vm-*` for all drivers |
| `uninstall --keep-lima`, `--keep-kubetools` | `uninstall --keep-vm` |
| `upgrade --infra/--k3s/--cilium/--gvisor`, `--to-k3s/--to-cilium/--to-gvisor` | `upgrade --image` |
| `upgrade --betterleaks`, `--to-betterleaks` | Part of the image |
| `configure-network` | Not needed; the VM follows host networking |
| `runtime_class: gvisor`, Windows `SANDBOX_DISTRO` | None |
| `--homedir` | §5.7 |

---

## 7. Protection parity matrix (acceptance criteria)

Every row MUST pass on macOS and Linux before v3.0.0, and on Windows before
any release that supports Windows (D-29). Tests MUST
exercise the product's **real** session output (a session created by
`sandbox run` or by `sandboxd` from a spec produced by the policy layer), not
hand-written fixtures. The "v2 coverage" column records what the current suite
actually verifies, from a full read of `tests/`; several v2 tests cited by
revision 1 test something other than their row. Where a row says "keep", the
test is ported to Go with the module it covers and passes against both
implementations until the bash is deleted (S8, D-34).

### 7.1 Preserved protections

| ID | Protection | v2 mechanism | v3 mechanism | Acceptance test | v2 coverage today |
|---|---|---|---|---|---|
| P-01 | Kernel isolation of the agent | gVisor | Kata `clh` (default) or gVisor (`--runtime gvisor`, D-02) | `test-runtime-kata` (new): agent runs in a guest kernel; VM `/dev`, `/proc`, processes not visible; under gVisor, the same from inside the sentry | `test-gvisor` checks the RuntimeClass and dmesg on its own pod only |
| P-02 | Workload hardening | securityContext, no SA token, no RBAC | §5.5.2 in the guest | `test-workload-hardening` (new): asserts uid, caps, no_new_privs, and seccomp (`Seccomp: 2` read from inside the guest; Kata's shipped default leaves it at 0) on a real session | No test asserts the agent pod's securityContext |
| P-03 | Default-deny egress | Cilium default deny + per-session CNP | Link + nftables + gateway | `test-default-deny` (rewrite): direct IP, non-443 port, UDP, and other-session dials all fail and are logged | Only "unlabeled pod cannot curl example.com" |
| P-04 | Per-agent/tier/profile FQDN allowlist | `toFQDNs` on 443 | Resolver + SNI check | `test-allowlist` (rewrite of tier1/2/3 tests) against the real session allowlist | Hand-written CNPs, not generated policy |
| P-05 | DNS-exfiltration control | Cilium L7 DNS rules | Filtering resolver | `test-dns-exfil` (new): unlisted name → NXDOMAIN; TXT and long-label queries not forwarded upstream | None (`test-dns` tests split-DNS rendering) |
| P-06 | Blocked domains, checked on add | `lib/checks.sh` | Same + gateway | `test-blocked-domains` (keep) + gateway runtime check (new) | Yes (unit) |
| P-07 | Blocked CIDRs, deny wins, rebinding defense | Cilium `egressDeny` | Gateway post-resolve check, IPv4 and IPv6; dial the checked address | `test-blocked-cidrs` (keep unit) + runtime test: allowlisted name resolving to `169.254.0.0/16` or a blocked IPv6 range is denied; a resolver returning a safe address first and a blocked one second is denied | Unit only; runtime untested |
| P-08 | Tier 3 cluster reachability, scoped | `toCIDR` + conditional host entity | Broker kube route + declared host endpoints | `test-tier3` (rewrite): reach the declared cluster only; API-server deny-list enforced; local k3d via `host_endpoints`; a Teleport-style client-certificate kubeconfig with `tls-server-name` works with no key in the guest | Hand-written CNP, placeholder endpoint |
| P-09 | No cross-session / sibling reach | Egress-only isolation (session ingress admits any cluster source, `lib/policy.sh:288-294`) | Per-session namespaces, no route | `test-cross-session` (new): session A dials session B's gateway, resolver, and dependency addresses; all fail | None |
| P-10 | Catalogue-only dependencies, digest-pinned, own allowlists, built from empty | `lib/catalogue.sh`, `lib/dependency.sh` | Same; behind the gateway | `test-catalogue` (keep) + `test-dependency-isolation` (new): dependency cannot reach agent, siblings, or unlisted hosts | Catalogue unit yes; rest YAML greps |
| P-11 | Workspace is the only writable host path; Tier 1 scratch | hostPath / emptyDir | VM copy + sync / scratch; no host mounts | `test-workspace-scope` (new) + `test-vm-no-host-mounts` (new) | None |
| P-12 | Sensitive-path masking (+ per-repo) | Empty overlays on paths present at launch | Bidirectional sync exclusion + in-guest overlays | `test-masking` (new): masked files absent from VM copy, empty in guest, and a guest-created `.env` never reaches the host | Only `.env` on a hand-built pod; real masking only in manual `test-probe` |
| P-13 | Host-exec vectors read-only | RO mounts when present | Host-enforced host→VM-only sync (§5.6.2) + in-guest RO | `test-sync-exec-vectors` (new): every listed path, incl. `core.hooksPath` target and submodule hooks, created or modified in the guest never reaches the host | YAML assertions only |
| P-14 | Secret gate | betterleaks on host repo | betterleaks on VM copy, pre-microVM | `test-secret-gate` (keep) | Yes (unit, extensive) |
| P-15 | Repo vetting | `lib/vetting.sh` on host | In-VM verification; host signing | `test-vetting` (keep) + host-signing test (new) | Yes (unit, extensive) |
| P-16 | Session-scoped credentials, revoked on every end | Secrets + ownerRefs + traps | Per-session broker + `sandboxd` revocation | `test-revocation` (new): after stop, crash, OOM, eviction, SIGKILL of the host binary, and keep-alive reap, placeholders no longer work and the broker is gone | Mocked ordering only |
| P-17 | No auth-provider state, SSH agent, or credential helpers; `.gitconfig` RO | Not mounted; RO mount | Not pushed; RO mount | `test-no-host-credential-paths` (new) | Only manual `test-probe` |
| P-18 | Overlays additive-only on safety | `lib/link.sh`, profile merge | Same, extended to L7 rules, exceptions, host endpoints | `test-link`, `test-profile`, `test-config` (keep) | Yes |
| P-19 | Audit: session record, overrides, network record, transcript | `lib/audit.sh`, Hubble | Same + gateway log + `sandboxd` transcript capture | `test-audit` (keep) + gateway-log and transcript-on-eviction tests (new) | No network-record test |
| P-20 | Memory not overcommitted; concurrency ceiling | ResourceQuota | `sandboxd` budget incl. Kata overhead | `test-resource-budget` (new) | None (`test-vm-sizing` tests Lima sizing) |
| P-21 | Teardown on disconnect | CLI traps | `sandboxd` attach-drop teardown | `test-supervisor-teardown` (new): includes signal during launch | Mocked |
| P-22 | Integrity of root-run binaries | `_safe_root_binary` | Signed immutable system disk + verification | Image-signature verification test (new) | `_safe_root_binary` has no test |
| P-23 | Concurrent sessions sharing one working tree | Shared hostPath (Linux only) | Shared VM copy, coherent mounts | `test-concurrent-shared-tree` (new) | None |

### 7.2 New protections (also required for v3.0.0)

| ID | Protection | Acceptance test |
|---|---|---|
| N-01 | Appliance VM is a second boundary: VM root sees no host files and cannot exec host processes | `test-vm-boundary` (new) |
| N-02 | VM cannot reach host services except declared endpoints (§5.2.6) | `test-host-reach` (new): host loopback and host LAN address unreachable from VM root; a listener opened by VM root on `127.0.0.1` and on `0.0.0.0` is not connectable from the host; a declared endpoint is reachable from the VM only for its session's lifetime (per-session scoping is checked VM-side and is not claimed against VM root); the same holds with the host CLI detached and after `sandbox netd` restarts; with `netd` configuration missing, the VM has no host reach |
| N-03 | Hardware isolation between sessions | P-01 + per-session guest kernel check |
| N-04 | No usable credential in any guest | `test-broker-no-secrets` (new): every credential-shaped value in env, files, and history fails against its real upstream from outside; includes an mTLS client-certificate kubeconfig; an upstream that reflects the injected credential (header echo, `TRACE`, a `Location` carrying a query credential) returns only the placeholder to the guest |
| N-05 | Placeholder misuse detected and blocked on intercepted connections | `test-broker-misuse` (new) |
| N-06 | Install-not-publish and no-push are structural | `test-l7-baseline` (new): `npm publish` and `git push` fail at the gateway; `npm install` and `git fetch` succeed; the same holds for a broker binding toward a non-baseline git host (self-hosted Gitea or GitLab) and a non-baseline npm-compatible registry |
| N-07 | VM → host flows are host-validated | `test-host-pull-validation` (new): symlinks, `..`, oversize files, and rewrites of earlier log files from a hostile VM are rejected |
| N-08 | Agent config and global instructions cannot persist across sessions | `test-agent-config-restage` (new): hooks, settings, and agent-level instruction files written in one session are absent in the next |
| N-09 | No git execution against the host repo | Structural (§5.1.3, §5.4.1): the host binary contains no git invocation against `--repo`; vet signing reads refs as files and signs a payload |
| N-10 | Keep-alive sessions are reaped and revoked | `test-keepalive-reap` (new) |
| N-11 | Host-side sync gate holds against a hostile VM | `test-sync-gate-adversarial` (new): a tampered VM-side endpoint attempts masked paths, exec-vector paths, case- and normalization-aliased paths (`.GIT/hooks`), symlinks out of the repo, hard links, type changes, and concurrent replacement; every attempt is withheld and listed by `sandbox sync review` |
| N-12 | No silent git corruption or lost changes | `test-git-consistency` (new): concurrent commits, staging, rebase/reset, branch switches, worktrees, submodules, LFS, interrupted sync; conflicts surfaced (§5.6.4) |
| N-13 | Gateway compromise is confined to one session | `test-gateway-confinement` (new): code execution as the gateway user cannot read the broker store, the gateway CA private key, other sessions' namespaces, or VM root files |
| N-14 | Gateway protocol confusion is denied | `test-gateway-protocol` (new): no SNI, ECH with a non-allowlisted outer SNI, SNI/authority mismatch, HTTP/2 coalescing to an unbound authority, CONNECT from the guest, request smuggling, malformed ClientHello, oversized DNS |
| N-15 | `sandboxd` recovers from crashes without leaks | `test-sandboxd-recovery` (new): kill `sandboxd` at each lifecycle state; on restart no orphaned microVM, namespace, broker, or binding survives and no new session is admitted before reconciliation |
| N-16 | Audit suppression is detectable | `test-audit-gap` (new): dropping records in the VM produces an `audit_gap` event on the host |
| N-17 | No token substitution through the host | Structural: no VM → host token flow (§5.1.5); plus `test-token-identity` (new): a broker refresh returning a different account is rejected |
| N-18 | Agent history never crosses tiers | `test-history-tier-isolation` (new): history written by a Tier 2 session on a repo is absent from a Tier 3 session of the same agent on the same repo, and vice versa |
| N-19 | VM-origin refs, tags, and objects cannot reach the operator's publish path | `test-sync-refs` (new): a guest that moves `main`, adds a tag, rewrites `refs/remotes/origin/main`, writes alternates or `shallow`, or plants a corrupt loose object produces no change to those host refs or files; a fast-forward on a feature branch applies; a non-fast-forward update, a protected-branch update, and a branch deletion appear in `sandbox sync review`; a valid `HEAD` switch applies and an invalid one is refused |
| N-20 | Index sync is seamless and safe | `test-sync-index` (new): host `git status` is clean after a VM commit, a VM branch switch, a host merge, and an agent-resolved conflict; adversarial index entries (a staged malicious blob with a benign file, `skip-worktree`, `assume-valid`, protected paths, gitlinks, a split-index pointer, crafted extensions, an oversized or truncated index) are withheld or dropped |
| N-21 | The exec-plugin pump runs only the captured invocation | `test-pump-integrity` (new): a pump request with altered args or env, an unknown index, or an unknown session is refused; mints are rate-limited |
| N-22 | VM-initiated browser open is bounded | `test-onboard-browser` (new): a request with no foreground `sandbox onboard`, a second request in one onboarding, a matching host with a wrong path or `client_id`, and a device code for an unlisted client are all refused |
| N-23 | `.gitattributes` cannot select operator git drivers | `test-sync-gitattributes` (new): a guest-written `filter=`, `diff=`, or `merge=` attribute is quarantined; the git-lfs triple and driverless attributes pass |
| N-24 | No silent image downgrade | `test-image-rollback` (new): an older, correctly signed image is refused without `--allow-downgrade`; a signature from a different identity is refused |
| N-25 | Harness updates cannot become a persistence or egress channel | `test-agent-update` (new): a session cannot write to the installed harness store; no session can start an update; the updater microVM reaches only its vendor's hosts; a tampered artifact (symlink out of tree, setuid bit, oversized file) is rejected; a TLS-only update without `--accept-unverified-download` is refused; an out-of-range version warns and needs `--allow-untested`; rollback restores the previous version |

### 7.3 Footprint and capability criteria

| ID | Criterion | Test |
|---|---|---|
| P-24 | Memory and latency budget: idle VM memory, per-session overhead (Kata guest + gateway namespace), per-dependency overhead, minimum supported workstation memory, and session start/teardown latency are measured in S1 on supported hardware and published as absolute targets. A release fails P-24 only if it exceeds the published targets. (Revision 2's "must not exceed v2" cannot pass on Linux, where v2 has no VM.) First S1 measurements on an Apple M6 (`docs/design/spikes/S1.md`): about 7 s to start a nested Kata microVM with a cached image, about 197 MiB host-side per idle microVM, and 1.1 s to tear down two. | `test-footprint` (release-gating) |
| P-25 | Every v2 user-facing capability in Appendix A.5 works or has a decision-log entry naming its replacement | Release checklist |

---

## 8. Gating spikes

Each spike records its findings in `docs/design/spikes/<id>.md`, including
the exact commands, versions, environment, observed results, failure
conditions, and an explicit pass/fail against the exit criteria. Documentation
claims never substitute for a functional test.

**Order.** Run first the spikes that could invalidate the architecture; some
can run in parallel:

| Order | Spikes | Question |
|---|---|---|
| 1 | S6 + S1 | Does nested Kata work reliably on the team's Macs and Linux machines? |
| any | S3 | Best effort, in parallel; never blocks v3.0.0 (D-29) |
| 2 | S7 | Can VM root be kept off host services? |
| 3 | S4 | Can a host-side gate keep sync safe and git consistent? |
| 4 | S2 | Can every agent and credential workflow be brokered? |
| 5 | S5 | Can a mature proxy implement the gateway contract? |
| any, early | S8 | Can the policy layer be ported to Go with identical gate behaviour? |

### S1 — Kata without Kubernetes: storage, networking, sizing

- **Questions:**
  - Can containerd + the Kata shim run session microVMs with the full v2
    mount set (workspace, single-file empty masks, empty-dir masks, read-only
    file and directory overlays) under virtio-fs?
  - Is two-microVM concurrent writing to one shared directory coherent with
    `cache=never`, and is `git status` / build performance acceptable on a
    reference repo (≥100k files)?
  - Does the per-session namespace + link + nftables design in §5.8.2 work
    with Kata's networking model through standard CNI plugins (`ptp`/`bridge`,
    `firewall`) and go-cni, with no route except the gateway?
  - Do agent and dependency microVMs start, network, read the workspace, and
    tear down reliably on macOS (vz) and Linux (KVM)? (Windows is S3.)
  - What is the memory overhead per microVM and the idle VM footprint (P-24)?
  - Does Codex's bubblewrap sandbox work under Kata?
- **Exit:** P-12 and P-13 (in-guest halves), P-23, P-03 and P-09 prototypes
  pass; overhead and footprint numbers recorded.
- **Status:** partial (`docs/design/spikes/S1.md`). Runtime, mounts, coherence,
  first footprint numbers, and the per-session network topology (P-03 and P-09
  prototypes, CNI `ptp`), Codex bubblewrap, and a 100,000-file repository
  measured (large-repository `git status` is slow under either cache mode,
  OQ-17). Two unexplained microVM stalls seen early did not recur in about
  2,000 further operations, including a 1,112-operation soak test, so they are
  unexplained but unreproduced; `sandboxd`'s watchdog (§5.4.3) must still
  assume a microVM can hang. Linux is untested.
- **Fallback:** if file-level masks don't work under virtio-fs, rely on sync
  exclusion (masked files never present) plus directory-level overlays, and
  document the change in P-12. If containerd-direct networking cannot meet
  §5.8.2, evaluate a minimal CNI chain driven by `sandboxd`; Kubernetes is not
  a fallback.

### S2 — Per-agent OAuth and credential brokering

- **Questions, per agent (claude, codex, copilot, grok, opencode):** Which
  endpoints issue and refresh tokens? Does the client parse or verify tokens
  locally? Can it run a full login, refresh, and 8-hour session holding only
  placeholders? Which non-`GET` endpoints does it need on shared hosts like
  `api.github.com`? How does refresh-token rotation behave, and is there an
  identity endpoint to bind the account at onboarding? Which config,
  instruction, and memory files does it write at runtime (the §5.7 re-staged
  set)?
- **Harness updates (§5.7.1, Appendix D):** per agent, what is its documented
  install-a-specific-version path, which hosts does it download from, what
  integrity source exists (signed manifest, registry provenance, or none),
  how is its in-session self-updater disabled, and does a new version change
  its auth flow, endpoints, or runtime-written files (which would invalidate
  the adapter or the re-staged set)?
- **Exec plugins:** for every plugin proposed for the allowlist, what does its
  credential authorize (cluster-scoped vs general-purpose cloud credential)?
- **Exit:** for each agent, either a working adapter (N-04 passes) or a
  documented reason it cannot be brokered.
- **Fallback:** per OQ-01.
- **Status:** started (`docs/design/spikes/S2.md`). The harness-update
  questions are answered for all five agents on Linux arm64 (install and
  update commands, pinning, download hosts, integrity, switches to disable each
  harness's own updater). The OAuth and brokering questions, runtime-written
  files, and operation under the §5.5.2 posture are not started.

### S3 — Windows driver

- **Questions:** Can Lima's `hcs` driver (reported experimental as of Lima
  2.3; verify) boot the VHDX image with nested virtualization exposed, a
  stable SSH endpoint, explicit DNS, and repeatable start/stop? If not, does a
  direct Hyper-V driver meet the same bar? How is host reach (§5.2.6)
  restricted on Hyper-V?
- **Backend:** does the appliance guest get nested KVM (VMX/SVM exposed by
  Hyper-V), and does Kata + Cloud Hypervisor run on it? If not, is MSHV usable
  from a nested guest with the selected Kata and Cloud Hypervisor versions?
  Public material found so far documents MSHV for a Linux **root** partition
  (as AKS uses with Kata), not a nested guest, and Red Hat's only supported
  nested setup on a Windows 11 Hyper-V host is WSL2 in a Windows guest.
- **Corporate configuration:** test with VBS / Memory Integrity enabled, as on
  managed Windows machines (an unverified report says it blocks nested AMD
  virtualization).
- **Status: best effort (D-29).** No work-provisioned Windows machine is
  available. Initial testing uses the owner's personal Windows 11 machine
  (confirm the edition is Pro, since Home has no Hyper-V). Results from it
  MUST record the edition, CPU vendor, and whether VBS / Memory Integrity was
  on, and MUST NOT be read as evidence for managed corporate machines, whose
  policies (VBS, Credential Guard, Hyper-V restrictions) may differ.
- **Exit (for a Windows release):** the full capability probe (§5.2.3) passes
  on Windows 11 Pro and Enterprise, on Intel and AMD hardware, with VBS
  enabled, including at least one managed machine.
- **Fallback:** direct Hyper-V driver; track Lima HCS as F2. If no
  hardware-isolated backend works, there is no software fallback (D-04);
  Windows stays on v2 (OQ-13).

### S4 — Workspace sync

- **Questions:** Is Mutagen's licence and distribution model acceptable, and
  can it be bundled, pinned, and checksum-verified by the host binary? Can it
  stage VM → host changes for the host-side gate (§5.6.2) instead of applying
  them itself? Does the Git consistency contract (§5.6.4) hold? What is
  performance on APFS, ext4, and NTFS? What is the conflict and quarantine UX?
  Which auto-executing files belong in the exec-vector list (OQ-07)? Can the
  host binary parse, merge, and write the index (§5.6.2 rule 7) so that host
  `git status` is clean after a VM commit, a VM branch switch, a host merge,
  and an agent-resolved conflict, with no git execution on the host? If not,
  does the HEAD-derived reconcile fallback hold?
- **Adversarial cases (required):** a **tampered VM-side sync endpoint** (not
  just writes from inside the guest) attempting masked paths, exec-vector
  paths, case-only renames and case aliases, Unicode-normalization aliases,
  symlinks and hard links out of the repo, junctions/reparse points (NTFS),
  file-type changes, concurrent replacement, and oversized files.
- **Exit:** P-11, P-12, P-13, N-07, N-11, N-12, N-19, N-20, and N-23
  prototypes pass on APFS, ext4, and NTFS; the "what each side sees" table
  (§5.6.4) holds with seconds of latency; initial sync and incremental latency
  documented.
- **Status:** started (`docs/design/spikes/S4.md`). The git behaviours behind
  rules 6 to 8 are confirmed on git 2.56.0. A Go prototype read and rewrote
  100,000-entry v2, v3, and v4 indexes in tens of milliseconds, git accepted the
  output, and the decoder survived about 2.7 million fuzz inputs. The sync
  engine, the gate, the entry-level merge, path aliasing, and the adversarial
  cases are not built.
- **Fallback:** an alternative engine for host → VM, with the host-side gate
  unchanged; or, for git, transactional transfer by bundle (§5.6.4).

### S5 — Gateway

- **Questions:** Can Envoy (the default candidate, §5.8.4) with a small Go
  controller meet §5.8.4 and §5.9, including per-request authority checks,
  credential injection through a per-session broker (ext_proc or equivalent),
  mTLS re-origination with `tls-server-name`, ECH handling, DNS steering,
  HTTP/2, upgrades, SSE, chaining through a corporate TLS-intercepting proxy,
  IPv6, and wildcard semantics (§5.8.7)? Process per session or per
  namespace: start time and memory each. Should the gateway CA carry name
  constraints?
- **Exit:** P-03 through P-09, N-06, N-13, and N-14 prototypes pass; an agent
  session with model streaming, `npm install`, `git fetch`, and `kubectl exec`
  works through it.
- **Fallback:** another mature data plane; a purpose-built proxy only with a
  documented reason (D-27).
- **Status:** started (`docs/design/spikes/S5.md`). An Envoy 1.40.2 prototype
  in the per-session gateway namespace met the SNI allowlist, passthrough,
  no-SNI and `CONNECT` denial, single-label wildcard, authority-versus-SNI,
  L7 baseline, credential injection, misuse blocking, response scrubbing, and
  log-redaction items, with a Lua filter standing in for the broker. Blocked
  CIDRs are enforced in nftables, not in Envoy. About 65 MiB and 0.1 s per
  gateway. Upstream TLS needs an explicit SAN match and streaming scrubbing needs
  hold-back across chunks (§5.8.4, §5.9.3). A Go `ext_proc` prototype of the broker's data path
  (injection, misuse blocking, streaming scrub, fail-closed) works at about
  0.7 ms per request and 16 MiB. HTTP upgrades (raw handshake) and mTLS
  re-origination with an explicit server name also pass. Real WebSocket and
  SPDY framing, ECH, proxy chaining, and the unprivileged gateway posture are
  not tested. An encrypted store, per-session CA issuance, and broker start
  were prototyped (§5.9.2, §5.10).

### S6 — Fleet capability check

- **Questions:** Confirm Apple's nested-virtualization hardware and OS floor;
  run the capability probe on the team's actual Macs, Linux laptops, and
  Windows machines.
- **Exit:** a list of team machines that pass or fail; a decision on any that
  fail (refresh vs. exclude).

### S7 — Host-reach control per driver

- **First option:** a host-side userspace network stack as the VM's only NIC
  (gvisor-tap-vsock), run by `sandbox netd` (D-31), with allow/deny
  implemented in `netd` and configured only by the operator's declared
  endpoints. Confirm that Lima (vz and qemu) and Hyper-V accept an external
  socket as the VM's NIC. Measure throughput.
- **Alternative:** per-driver native controls for `lima-vz`, `lima-qemu`, and
  the Windows driver. Lima 2.3's `hostLoopback: false` is the first measured
  native control for `lima-vz` (`docs/design/spikes/S7.md`); it blocks all
  host reach, so it cannot scope declared endpoints by itself.
- **Questions:** How is the VM kept from host addresses, host aliases, and host
  loopback, over IPv4 and IPv6, by a control VM root cannot remove? How are
  declared Tier 3 host endpoints exposed only to one session's gateway? Do VPN
  routes on the host apply to the VM's traffic? Does split DNS work through
  the same path? How do host firewalls and corporate endpoint security see the
  traffic?
- **Exit:** N-02 passes on macOS and Linux (and Windows, best effort) after VM root removes every
  VM-local rule, including with the host CLI detached and after a `netd`
  restart; local k3d (via `host_endpoints`) and a VPN-only endpoint both work,
  including for a detached `--keep-alive` Tier 3 session.
- **Also confirm:** `plain: true` (or the ignore-all `portForwards` rule)
  stops Lima publishing VM listeners on host loopback, and removes nothing
  the appliance needs (§5.2.5); `netd` restart behaviour (the VM fails closed
  and recovers); and the detached `--keep-alive` case (§5.2.6).
- **Fallback:** the other option.

### S8 — Policy-layer port pilot

- **Questions:** Can the secret gate (betterleaks driving, encrypted-at-rest
  exemptions, vetted exceptions, audited overrides) and vetting verification
  (including the hardened git handling) be ported to Go with identical
  outcomes? What differential harness is needed (fixture repos, golden
  outputs, a bash-versus-Go runner, structured comparison of exit codes,
  stdout, audit records, and files written)? Which v2 tests are unit tests of
  bash functions that must be rewritten rather than re-run? What is the real
  size and shape of `bin/sandbox` and `lib/*.sh` (an inventory, so the port
  order and estimate rest on evidence)?
- **Exit:** zero differences between the bash and Go implementations on the
  full v2 corpus for the secret gate and vetting, plus new adversarial cases
  (hostile repo config, odd encodings, path aliasing); a harness reusable for
  every later module; a measured port plan with order and estimate; findings
  in `docs/design/spikes/S8.md`.
- **Fallback:** if a module cannot be ported with identical behaviour without
  redesign, record why and re-decide in writing (§0): either redesign that
  module with the owner's sign-off, or keep it in bash for v3.0.0 behind the
  same session-spec seam. An unverified port does not ship.
- **Status:** pilot 1 done (`docs/design/spikes/S8.md`). `finding_is_encrypted`
  (about 130 lines of awk-based bash) is ported to Go in `go/internal/gate` with
  zero divergences from the bash oracle on 35,057 cases, a corpus whose
  sensitivity was checked by planting 22 bugs, and a live Linux oracle. The
  oracle itself proved awk- and locale-dependent, and its column handling assumes
  an older scanner convention; both are recorded. Pilot 2 adds
  `is_path_masked`, `extract_yaml_list_from_file`, and
  `_leakscan_finding_accepted` (zero divergences on 42,601 further cases). The
  Pilot 3 ports `scan_repo_secrets` and its config, ignore-file, and scanner
  invocation helpers (zero divergences on 1,033 cases against a stub scanner,
  comparing stdout and the scanner's recorded arguments and generated config).
  Pilot 4 ports `secret_gate_repos` (zero divergences on 393 cases, including
  the interactive prompt on a pseudo-terminal), which completes the secret gate.
  Pilot 5 begins vetting verification with the posture and configuration layer
  (`go/internal/vetting`, zero divergences on 1,104 case groups). Pilot 6 adds
  repo classification and signed-tag verification (zero divergences on 270 cases,
  including a hostile workspace whose config names programs for every git hook
  point: none ran). Pilot 7 adds the drift decision and the launch gate (zero divergences on
  2,796 cases, 922 of them on a pseudo-terminal). Pilot 8 adds the committed-exception readers, the secret
  gate's accept-list source, and the signing-key state (zero divergences on 1,056
  cases). Pilot 9 ports attestation (signing, exception acknowledgment, the inline
  attest, signing setup; zero divergences on 997 cases with real SSH signing),
  which completes `lib/vetting.sh`. Along the way it found that git 2.43 (Ubuntu
  24.04) creates an unsigned tag when its SSH signer fails; see
  `docs/design/spikes/S8.md`. The rest of the policy layer is not ported. Summary and recommendation
  after nine pilots: `docs/design/spikes/S8.md`. About a quarter of the candidate
  bash is ported; the remaining units call external tools and will cost more per
  line, which the nine pilots do not measure.

---

## 9. Testing strategy

- **Policy layer:** the existing unit tests that do not depend on Kubernetes
  (about 62% of current test lines: secret gate, vetting, audit, link,
  profile, config, blocked lists, catalogue, onboarding) are ported to Go with
  their modules. Until a module's bash is deleted, its tests run against both
  implementations (differential, S8). They run on GitHub-hosted Linux runners
  on every PR, as today.
- **Go host binary:** unit tests with a mock driver on GitHub-hosted macOS,
  Linux, and Windows runners on every PR.
- **Enforcement suite (the bulk of §7):** runs against real sessions inside the
  appliance VM booted on a **self-hosted bare-metal Linux runner**, on every
  PR. GitHub-hosted runners are themselves VMs, and appliance VM → Kata guest
  on top of them would be triple nesting. Today all runtime enforcement tests
  are manual and most use hand-written pods and policies; this suite replaces
  them (`tests/test-probe.sh:12-17` documents why hand-written fixtures pass
  trivially).
- **Driver smoke tests:** a self-hosted macOS (M3+) runner, and a Windows 11
  Pro runner once Windows is supported (D-29),
  boot the release image, run the capability probe and host-reach test, launch
  one Tier 2 session through sync and the gateway, and tear down.
  Release-gating, not per-PR.
- **Adversarial-VM test class:** a named part of the enforcement suite that
  assumes the attacker holds the guest or VM root: hostile sync endpoint
  (N-11), hostile VM → host pulls (N-07), audit gaps (N-16), token identity
  (N-17), cross-session dials (P-09), gateway confinement (N-13), and
  protocol-confusion probes (N-14).
- **No silent skips:** a test that cannot run MUST fail in CI, not exit 0
  (today `skip()` exits 0, `tests/helpers.sh`).
- **Independent security review** of `sandboxd`, the sync gate, the gateway,
  the broker, and the ported policy gates (secret gate, vetting verification,
  blocked-destination checks) is a v3.0.0 release gate (§11). They replace widely tested
  components (kubelet, Cilium) with new security-critical code.
- **Parity matrix** is the release checklist; CI produces a matrix report per
  platform for every release candidate.
- **None of the self-hosted runners exist yet**; provisioning them is a
  migration step (§11).

---

## 10. Distribution, signing, upgrade

- **Host binary:** Homebrew tap, winget, `.deb` and `.rpm` (RHEL-family users
  exist), and direct download. macOS notarization, Windows Authenticode, and
  cosign signatures on all artifacts.
- **Image:** OCI artifact (§5.3.2), signature-verified before boot, against a
  pinned signing identity, with anti-rollback (below).
- **`sandbox upgrade`** updates the binary, then the image: download, verify,
  stop the VM, swap the system disk (keeping the previous one for rollback),
  boot, and run state-disk migrations. Sessions must be stopped first. The host
  binary refuses an image older than the highest installed `IMAGE_VERSION`
  unless `--allow-downgrade` is passed, which is audited. The retained
  previous system disk is used automatically only when the new image fails its
  first boot or capability probe, and that is audited too.
- **Releases MUST be signed tags.** v2 release tags are lightweight and
  unsigned and the update path only warns (`bin/sandbox:3330-3335`).
- **Air gap:** the binary accepts an alternate artifact source (internal OCI
  registry or file path) and verifies the same signatures. Catalogue images
  are pre-pulled into the image or the state disk.

---

## 11. Migration from v2 (options, not a schedule)

Each step leaves the tree releasable or gated behind a flag.

1. **Fix the v2 defects in Appendix B** on master. They are independent of v3.
2. **Merge the credential-brokering design** and the phase-5 dependency design
   from their branches to `master` (seven files on `master` already cite the
   phase-5 doc).
3. **Spikes S1–S8.** Provision the self-hosted runners.
4. **Image pipeline:** build, sign, and boot the appliance image with the v2
   bash CLI inside (still k3s + gVisor for this step only), on Linux and macOS
   via Lima. Remove host mounts. The bash CLI is a temporary scaffold here.
   **Policy-layer port** (D-34) runs in parallel from this step until release:
   S8 pilots the secret gate and vetting, then modules are ported in the order
   S8 records (shared rule tables, config, and checks first; the CLI and audit
   last), each differential-tested against the frozen bash before its bash is
   deleted.
5. **Go host binary** with `lima-vz` / `lima-qemu` drivers, the handshake,
   operator-state push, typed pulls, and the host operations. `bin/sandbox` on
   the host becomes the Go binary.
6. **Sync layer** (§5.6); delete the 9p and in-VM Mutagen path.
7. **`sandboxd` + Kata via containerd + per-session links and gateway**
   (§5.4.3, §5.5, §5.8): policy layer emits the session spec; remove k3s,
   Cilium, gVisor, CoreDNS from the image. P-03 through P-09 and P-21 must pass
   before this lands.
8. **Agent history model** (§5.7).
9. **Gateway CA and L7 baseline** (N-06).
10. **Credential broker:** static tokens, then kube (including exec plugins),
    then each agent's OAuth.
11. **Windows driver** (S3 outcome).
12. **v2 → v3 user migration:** `sandbox install` detects a v2 install,
    imports `~/.sandbox` state (onboarding agent tokens from
    `agent-home/` into the broker store, then deleting them from the host
    copy, and moving history into the per-agent/tier/repo layout only where
    v2 session logs attribute it to a repo and tier; anything unattributable
    goes to a read-only archive outside every session), and offers cleanup of the v2 stack: on Linux,
    uninstalling host-level k3s, Cilium, gVisor, buildkit, helm, the
    masquerade unit and firewalld rules (the v2 `uninstall.sh` logic is carried
    in the binary for this purpose only); on macOS deleting `sandbox-vm`; on
    Windows unregistering the WSL distro (v2 has no Windows uninstall today).
13. **Docs:** rewrite install, platform, architecture, and security-model
    pages; update `docs/explanation/comparisons.md`; update PRINCIPLES.md for
    the new boundaries, brokering, agent history, and teardown guarantees.
14. **Independent security review** of `sandboxd`, the sync gate, the
    gateway, the broker, and the ported policy gates; findings fixed or
    accepted in the decision log.
15. **Release v3.0.0** when §7 passes on macOS and Linux and the v2 bash is
    deleted from the v3 line. Windows follows in
    a later release when §7 passes there (D-29).

---

## 12. Future phases

- **F1 — Runtime detection inside each Kata guest.** Each sandbox has a real
  guest kernel, so standard detection tooling can run in the guest. An agent
  that compromises the guest kernel can blind it, so it is detection, not
  containment. The gateway log is the v3 audit baseline.
- **F2 — Lima HCS on Windows** (if S3 chose direct Hyper-V).
- **F3 — Policy layer in Go.** Promoted into v3.0.0 (D-34, S8); no longer a
  future phase.
- **F4 — Cluster deployment.** The session spec, gateway, broker, and policy
  layer are substrate-independent, so a shared-cluster deployment (for example
  on Agent Substrate) remains possible.
- **F5 — Operator-approved push.** Instead of a blanket push deny, the gateway
  holds a push and asks the operator on the host to approve it.
- **F6 — Suspend/resume of sessions** via microVM snapshots, so keep-alive
  sessions survive host sleep without holding memory.
- **F7 — Brokering R2+** (§5.9.9).
- **F8 — Gateway-produced transcript.** The gateway already terminates the
  model-API connection for credential injection, so it can record the model
  exchange as evidence the agent cannot rewrite. Large and privacy-sensitive;
  configurable per org.

---

## 13. Open questions

| ID | Question | Default if unanswered |
|---|---|---|
| OQ-01 | If S2 finds an agent cannot be brokered, is it disabled in v3.0.0 unless an org overlay explicitly allows the exception? | **Resolved (owner, 2026-11-27):** allowed with a warning: an agent that cannot be brokered runs with its real token in the sandbox, with a launch warning and an audit record per session |
| OQ-02 | Is the `git push` deny a hard org baseline, or overlay-configurable? | **Resolved (owner, 2026-11-25):** org baseline, applied by protocol to every intercepted host (§5.8.5); overlay may relax only for named hosts |
| OQ-03 | arm64 Linux and arm64 Windows hosts in scope for v3.0.0? | **Resolved (owner, 2026-11-27):** amd64 on Linux and Windows is required for v3.0.0; arm64 on those two is a bonus, not a requirement. macOS on Apple silicon as before |
| OQ-04 | Image hosting and retention | **Resolved (owner, 2026-11-27):** ghcr.io public + documented mirror procedure |
| OQ-05 | v2 support window after v3.0.0 | **Resolved (owner, 2026-11-27):** no v2 support after v3.0.0, Windows included; what v3 can do on Windows is revisited once everything else for v3 is done |
| OQ-06 | Refuse (rather than warn) Tier 3 sessions sharing a tree with lower-tier sessions? | **Resolved (owner, 2026-11-27):** warn; overlay may deny |
| OQ-07 | Final exec-vector list | **Resolved (owner, 2026-11-27):** the built-in list (§5.6.2, plus S4's findings), which an org overlay may extend but never shorten. Built: overlay `exec_vectors:`, read by the host's sync gate (`syncgate.OverlayExecVectors`) |
| OQ-08 | Log retention: enforce `retention_days`, or drop the claim? | **Resolved (owner, 2026-11-27):** drop the default claim: nothing expires by default; an overlay may set a minimum retention per tier, which `sandbox cleanup` never deletes below |
| OQ-09 | Exec-plugin tokens for a keep-alive session after the operator detaches | **Resolved (owner, 2026-11-27):** token expires; requests fail closed until the operator re-attaches |
| OQ-10 | Multi-label wildcard form: `**.` or a per-entry flag? | **Resolved (owner, 2026-11-25):** `**.` |
| OQ-11 | Keep `sandbox rebuild` (buildkit in the image) or ship agent images only through image releases? | **Resolved (rev. 5): neither alone.** Harness-only updates use operator-driven `sandbox agent update` (§5.7.1, D-35); `sandbox rebuild` stays for local image changes, with buildkit GC caps from v2 carried over; image releases carry the tested baseline |
| OQ-12 | Should agent history also be separated by tier? | **Resolved (rev. 3): yes**, agent + repo + tier (D-14) |
| OQ-13 | If S3 finds no hardware-isolated backend on Windows, does v3.0.0 wait? | **Resolved (rev. 3): no.** v3.0.0 ships on macOS and Linux; Windows stays on v2 until it passes §7 (D-29). **Superseded (owner, 2026-11-27, OQ-03 and OQ-05):** Windows amd64 is in scope for v3.0.0, worked on last; v2 gets no support after v3.0.0 |
| OQ-14 | Does the in-VM policy CLI shell out to `git` or use a Go git library? | **Resolved (owner, 2026-11-27):** move to a Go git library (no git binary in the gates' path). Until that work is done the CLI shells out, with v2's hardening ported (§5.4.1) |
| OQ-15 | virtio-fs cache mode for shared working trees (§5.13): `auto` (fast, up to 1 s stale-size window) or `never` (coherent, about 19× slower on metadata in S1)? | **Resolved (rev. 5, owner): `auto`**, with atomic-rename writes in the sync tool and the 1 s window stated in the release notes; revisit only on a stale-read report: S1's 100,000-file measurement found `never` about 2× slower than `auto` for `git status` (about 23 s against 10 to 13 s; 0.07 s natively) |
| OQ-16 | For Codex, take the two in-guest overrides that make its bubblewrap sandbox work under Kata (unmasked `/proc` and `/sys` paths, and a seccomp profile permitting user namespaces), or keep the v2 `danger-full-access` override with the full §5.5.2 posture intact? | **Resolved (owner, 2026-11-27):** keep `danger-full-access` and the full §5.5.2 posture (Codex's bubblewrap does not run under gVisor either) |
| OQ-17 | How do we keep `git status` fast on large repositories (about 10 s at 100,000 files in S1; 0.2 to 0.4 s at a few thousand)? | **Approved (owner): ship a system gitconfig in the image** (`core.untrackedCache`, `feature.manyFiles`), which S1 measured at about one third off. Defer a read-only git proxy in the appliance VM (S1.md, option 3) and a guest-local workspace (option 2) until users report repositories of about 20,000 files or more |

---

## 14. Decision log

| ID | Decision | Rationale | Alternatives rejected |
|---|---|---|---|
| D-01 (revised) | One hardened appliance VM per host; **no Kubernetes inside** | Two hardware boundaries on every OS; the Kubernetes surface used is small (Pods, Secrets, one ConfigMap, Services, policies), and the gaps it causes (eviction GC, no reaper, trap-based teardown) are closed by a supervisor | k3s inside the VM (rev. 1: keeps Cilium, CoreDNS, ResourceQuota, and their gaps); microVMs directly on the host (§D-18) |
| D-02 | Kata (Cloud Hypervisor) replaces gVisor as the default. **Amended 2026-11-27 (owner):** gVisor is kept as an operator-chosen runtime (`run --runtime gvisor`, `runtime:` in the user's config.yaml) | Hardware isolation between sessions; team hardware meets the nested-virt floor. Measured on Apple silicon, nesting makes Claude Code start in ~7 s and echo keys in 40-70 ms under Kata against ~0.5 s and v2's speed under gVisor (`v3-performance.md`), so the operator may trade the hardware boundary for speed | gVisor only (no cross-session hardware boundary); Firecracker (no virtio-fs); QEMU (attack surface) |
| D-03 | Same runtime everywhere. **Amended 2026-11-27 (owner):** the same two runtimes on every platform, chosen explicitly by the operator; never a fallback | One security model per choice, the same everywhere; no silent downgrade: a session asked to run under one runtime fails rather than run under the other | gVisor fallback (two models, silent-downgrade path) |
| D-04 | No fallback runtime; refuse on failed probe | See D-03 | — |
| D-05 | Drop WSL2; Hyper-V-backed VM on Windows; Windows Home unsupported | Same image and a real VM boundary | WSL2 (shared kernel, in-distro interop controls) |
| D-06 (reversed) | **Drop k3s** | Replaced by `sandboxd` + containerd + Kata (D-01) | Keep k3s (rev. 1 rationale "switching cost > gain" no longer holds once Cilium is gone and brokering needs a per-session gateway anyway) |
| D-07 (revised) | Thin Go host binary: no policy, plus an enumerated list of host operations | Operations that need the operator's host credentials (vet signing, private overlay fetch, trust stores, exec-plugin auth) cannot move into the VM without moving those credentials | No host operations (impossible without credential exposure); per-OS shell shims |
| D-08 (revised) | Egress by topology: per-session link + filtering resolver + per-session L7 gateway; **no Cilium** | Every Cilium job in v2 maps to the resolver, gateway, or link (Appendix A.3), and its workarounds disappear | Cilium as layer 1 (rev. 1); host-side eBPF (Linux-only) |
| D-09 | Credential brokering is a v3.0.0 requirement, specified by the brokering design | Credentials outside the boundary is the 2026 norm; v2 agent tokens and secrets are readable in the pod | Best-effort brokering |
| D-10 | Per-install gateway CA generated in-VM | A shipped CA key would let anyone impersonate any site to every sandbox | CA baked into the image |
| D-11 | Shared working tree by default, `--worktree` opt-in | Parity with Linux v2; behaviour change on macOS is called out | Per-session copies only |
| D-12 | Runtime detection is a future phase (F1) | Scope | — |
| D-13 | **One gateway and broker per session** | Required by the brokering design; makes session identity structural; no source-IP mapping | One shared gateway (rev. 1) |
| D-14 (amended rev. 3) | **Agent history per agent, repo, and tier; executable agent config and global instructions re-staged each launch as a discarded writable copy; tokens only in the broker** | v2's per-agent shared, writable home lets one session read tokens and plant config for another across repos and tiers. Separating by tier stops lower-tier history from steering an agent with higher-tier access; the cost (no cross-tier resume) is accepted by the owner | Per agent (v2); per agent and tier; per agent and repo (rev. 2) |
| D-15 | **VM reaches host services only via operator-declared Tier 3 endpoints**, enforced host-side | Keeps local k3d and VPN-only clusters working without exposing host loopback to VM root | No host reach (loses v2 capabilities); unrestricted Lima host access |
| D-16 | **VM → host flows are host-pulled, typed, validated, append-only** | VM root is in the threat model | VM writes host state directly |
| D-17 (reversed by D-34) | Keep the bash policy layer; it emits a session spec | Rev. 1–3 rationale: preserves the tested gates; only the Kubernetes-coupled parts are rewritten. The session-spec boundary itself stays (§5.4.2) | Full Go rewrite for v3.0.0 (F3), now adopted as D-34 |
| D-18 | Do not run sandboxes directly on the host as per-session microVMs | Loses the second boundary, needs three VMM integrations and three native egress stacks, and keeps untrusted-repo git on the host | — |
| D-19 (amended rev. 3) | Exec-plugin kubeconfigs supported via a host-side token pump; only cluster-scoped plugins by default | Brokering design R1; auth-provider state must stay on the host; general-purpose cloud tokens would widen what VM root can steal | Reject exec plugins (rev. 1, and a regression from v2's `--allow-exec-plugin`); pump every plugin |
| D-20 | Vetting attestations signed without git execution on the host: host reads refs as files and signs the canonical tag payload; VM assembles the tag | Removes the last host-side git run against an untrusted repo; tag format unchanged, so existing attestations stay valid | Host `git tag -s` with pinned programs (rev. 2; v2's approach) |
| D-21 | No VM → host token flow; rotated tokens live on the VM state disk; re-onboard after VM recreation | Closes token substitution by a hostile VM while keeping in-VM refresh, so detached keep-alive sessions keep working | Host keeps refresh tokens and mints access tokens on request (breaks detached keep-alive); pull with identity check only |
| D-22 | The in-VM virtualization backend may differ by host; the hardware-isolation contract may not | Windows Hyper-V may expose a different backend than KVM | Fixed `/dev/kvm` requirement; any software fallback |
| D-23 | `sandboxd` is a persistent, journaled state machine that reconciles before admitting sessions | A supervisor alone does not guarantee teardown across its own crashes | In-memory supervision |
| D-24 | VM → host workspace changes are applied only by a host-side sync gate; protected changes are quarantined for review | The sync engine runs partly in a VM that may be hostile; silent drops would surprise operators | Trusting the engine's ignore rules; silent drops |
| D-25 | Git is shared through an explicit consistency contract (§5.6.4); concurrent same-branch mutation unsupported, `--worktree` for concurrency | File sync does not preserve git transactions; v2 macOS already has this risk unmanaged | Silent best-effort sync |
| D-26 | Each session's gateway, resolver, and broker run unprivileged in a per-session network namespace under seccomp | They are the guest's first attack surface; a shared root namespace would turn one parser bug into VM root and make cross-session isolation depend on nftables alone | Gateways in the VM root namespace (rev. 2) |
| D-27 | Mature proxy data plane (Envoy default) with a small Go controller | Avoid writing security-critical TLS/HTTP parsing | Purpose-built proxy, unless S5 documents why |
| D-28 | mTLS client-certificate re-origination is R1 in v3 | The repo's own Teleport recipe produces client-cert kubeconfigs; deferring would ship the primary Tier 3 path as a readable exception | Defer to R2 (brokering design, rev. 2) |
| D-29 | **Windows is best effort for v3.0.0**; the release gates on macOS and Linux. **Amended 2026-11-27 (owner):** Windows amd64 is in scope for v3.0.0, worked on after everything else; what it can support is decided then (OQ-03, OQ-05) | No work-provisioned Windows machine is available to test the least certain assumption (nested Kata on Hyper-V, under corporate VBS policy); holding the release on it would block the platforms that can be verified. Windows keeps the same security contract when it ships | Gate v3.0.0 on all three platforms (rev. 2–3); ship a weaker Windows build |
| D-30 | **VM-origin refs, `HEAD`, and the index are merged by the host-side gate, not copied**: fast-forward-only on unprotected branches, validated `HEAD`, entry-level index merge; tags, remotes, reflogs, and alternates never | Closes review F1 (VM-written refs, tags, and alternates reaching the operator's publish path) while keeping commits on the operator's behalf, branch switching, staging, and conflict resolution seamless (G9). Protected-branch policy moves from a hook the agent can skip to the gate | Two-way ref sync with no gate (rev. 3); a per-session ref namespace with explicit promotion of every commit (rejected: friction); refs never sync (rejected: breaks commit workflows) |
| D-31 | **`sandbox netd`**, a mode of the signed host binary launched detached with the VM, owns the VM's NIC and the host-reach control | The control must outlive the CLI (detached keep-alive sessions) and fail closed. A named, signed owner removes the unspecified-owner default-allow risk, and our own policy code gives exact per-endpoint scope and lifetime | Lima host agent plus gvproxy with static configuration (acceptable if S7 shows it meets §5.2.6); a launchd/systemd service (install and endpoint-security footprint); a control that exists only while the CLI runs (breaks detached Tier 3 keep-alive) |
| D-32 | Broker store key held in the host keychain, pushed at VM start | A stolen or backed-up state disk cannot be read; the host binary starts the VM, so normal starts add no delay | Key on the state disk (cosmetic encryption); key file under `~/.sandbox` (copied by home backups; kept only as the headless-Linux fallback) |
| D-33 | The L7 baseline is protocol rules on every intercepted destination | A domain-keyed baseline leaves operator-added git hosts and registries with brokered credentials unprotected | Domain-keyed baseline (rev. 3) |
| D-34 | **Port the bash policy layer to Go for v3.0.0**: one language, one module, several binaries, trust boundaries kept. The v2 bash stays in the tree as a frozen test oracle until release, and each module is differential-tested before its bash is deleted (S8) | Two languages double the maintenance surface, let the sync gate, the host rule tables, and the policy layer drift apart, and put the fail-closed gates (secret gate, vetting, blocked destinations) in the language least suited to them. The team's Go experience has grown, and Go suits staged, AI-assisted implementation. The release is not time-boxed, so the port can be validated first | Keep bash for v3.0.0 and port later (rev. 3, D-17); port after release (rejected by the owner, to avoid carrying two languages into the first v3 release) |
| D-35 | **Agent harness updates are operator-driven and out-of-session**: a tested baseline ships in the image; `sandbox agent update` fetches a newer harness in a short-lived updater microVM, validates it, and mounts it read-only into later sessions | Harness releases are frequent. Rebuilding images per release (v2) and CI-built image releases per harness bump (a daily cadence) are both heavy. Running the vendor upgrade inside a session would create a persistence channel for a trojaned harness and widen every session's allowlist. Every supported harness documents an install path, but only some document an integrity source (Appendix D), so integrity levels and an overlay kill-switch are part of the design | Rebuild per harness change (v2); separate signed agent images built by CI on every harness bump; in-session `<agent> upgrade` with a persisted install |

---

## Appendix A — v2 facts this design depends on

Verified by reading the code on `master` at `a489a65`. If the code changes,
re-check the claim.

### A.1 Topology and boundaries

- Lima VM mounts `~` and `/tmp/lima` writable over 9p (the comment says
  virtiofs; the config is 9p): `lima/sandbox-vm.yaml.tmpl:36-46`.
- `setup.ps1` writes only `[boot]` and `[user]` to `wsl.conf`
  (`setup.ps1:277-288`); the shim runs the CLI as root from `/mnt/<drive>`
  (`bin/sandbox.ps1:40`).
- Pod runtime is gVisor: `lib/manifest.sh:153`; RuntimeClass
  `manifests/runtimeclass.yaml`.
- Platform branches: `lib/platform.sh:421` (`resolve_agent_home`), `:446`
  (`resolve_workspace_mount`), `:479` (`resolve_pod_uid`).
- macOS sync is Mutagen `two-way-safe` over the whole repo including `.git`,
  excluding only masked paths: `lib/lima.sh:285-307`.
- The Teleport recipe writes `client-certificate-data`, `client-key-data`, and
  `tls-server-name`: `examples/teleport/bake-kubeconfig.sh:145-150`.
- Claude keeps runtime-written `.claude.json` in its config directory:
  `lib/manifest.sh:283-287`.

### A.2 Kubernetes surface and gaps

- All `kubectl` calls go through a wrapper pinned to `~/.sandbox/kubeconfig`:
  `lib/platform.sh:15-17`.
- Attach is `kubectl exec -it` into a `sleep infinity` container:
  `bin/sandbox:1700`, `lib/manifest.sh:201`.
- Keep-alive auto-reap deferred (issue #94): `bin/sandbox:1734`.
- Signal trap does not cover pre-attach setup: `bin/sandbox:509-513`.
- Hubble export after endpoint deletion is unverified: `bin/sandbox:2183-2187`,
  `lib/cluster.sh:486-507`.
- Issuer-side revocation is a printed reminder: `bin/sandbox:2129-2145`.
- Dependency objects reaped by ownerRef + label sweep:
  `lib/dependency.sh:22-26, 604-614`.

### A.3 What Cilium enforces today (requirements for §5.8)

1. Default deny on every endpoint (`policyEnforcementMode=always`,
   `setup/common.sh:369-394, 634`) with a kube-system carve-out.
2. DNS only to kube-dns, L7-filtered to the exact allowlist plus the session's
   dependency Service names (`lib/policy.sh:108-113, 136-138, 264-276`).
3. Dependencies with no egress resolve nothing (`dns: []`,
   `lib/policy.sh:354-363`).
4. TCP 443 only, to IPs learned from allowed resolutions
   (`lib/policy.sh:279-284`).
5. Wildcards: apex added only when eTLD+1 and not blocked
   (`lib/policy.sh:63-78`); over-broad wildcards refused
   (`lib/checks.sh:371-381`); single-label matching forces per-plan Copilot
   entries (`lib/agents.sh:74-82`).
6. Blocked CIDRs, deny wins after resolution (`lib/policy.sh:226-243`); IPv6
   literals skipped at create time (`lib/checks.sh:269-289`).
7. `ndots:1` to avoid search-domain permutations
   (`lib/manifest.sh:159-171`).
8. `socketLB.hostNamespaceOnly=true` for gVisor (`setup/common.sh:604-614`).
9. gVisor network mode `sandbox`, `net-raw=false` (`setup/linux.sh:430-448`).
10. Distinct identity per session asserted at launch
    (`lib/cluster.sh:117-154`).
11. Dependency ingress only from the owning session
    (`lib/policy.sh:427-437`).
12. Tier 3 kube API by pinned IP via hostAliases and `toCIDR`; conditional
    host-entity grant; loopback refused (`lib/policy.sh:157-213`,
    `lib/manifest.sh:109-129`, `bin/sandbox:1150-1183`).
13. Pod SNAT: `bpf.masquerade` + iptables MASQUERADE + boot unit
    (`setup/common.sh:644-657`, `setup/linux.sh:379-409`).
14. firewalld trusted-zone sources for pod/service CIDRs
    (`setup/linux.sh:46-89`).
15. Split-horizon DNS for VPN zones, Linux only (`lib/dns.sh:136-166`).
16. Hubble flows as the network audit record (`lib/cluster.sh:469-509`).
17. Session ingress admits any cluster or world source; isolation is
    egress-side only (`lib/policy.sh:288-294`).

### A.4 Credentials today

- Agent OAuth tokens are staged into `~/.sandbox/agent-home/<agent>/`
  (`lib/onboard.sh:23-35`) and that directory is mounted read-write into every
  session of the agent (`lib/manifest.sh:38, 557-562`).
- Profile secrets become a session Secret consumed via `envFrom`
  (`lib/secrets.sh:188-214`, `lib/manifest.sh:91-101`).
- opencode's API key is an env var from a Secret (`lib/manifest.sh:311-325`,
  `lib/credentials.sh:169-175`).
- Host env blocklist: `lib/credentials.sh:26-48`.
- No brokering exists on `master`. The design is on branch
  `credential-brokering-design` (`docs/design/credential-brokering.md`,
  commit `0e8cbe3`).

### A.5 v2 user-facing capabilities that must survive (P-25)

`run` with all v2 flags (including repeatable `--repo`, `--infra-token
NAME=PATH`, repeatable `--infra-kubeconfig`, `--infra-kube-context`,
`--allow-exec-plugin`, `--keep-alive`, `--name`, `--dry-run`, the three
`--i-accept-*` overrides), `resume`, `list`, `logs`, `flows`, `stop`,
`cleanup`, `check`, `status`, `allow`, `onboard`, `secret`, `mask`,
`exceptions` (`add`/`list`/`migrate`), `vet` (incl. inline attest and signing
setup), `profile`, `link` (`status`/`sync`/`unlink`, run-path sync,
`min_sandbox_version`), `rebuild` (per-agent versions), `version`,
`setup-proxy-cert`; Tier 3 against local k3d/podman and VPN-only clusters;
Linux split DNS; corporate TLS-intercepting proxies; MCP and service
dependencies including the browser class; RHEL-family Linux hosts; every
config, overlay, and vetting key in `docs/reference/configuration.md` and
`docs/how-to/vetting.md`.

### A.6 Size of what is removed (estimates from a full read)

- Kubernetes + Cilium + gVisor code in `lib/`, `setup/`, `manifests/`,
  `uninstall.sh`: about 2,800 lines.
- Lima/WSL/PowerShell platform code: about 1,800 lines.
- `bin/sandbox`: about 33–35% (≈1,800 lines) is Kubernetes/Cilium-coupled;
  about 50% is pure policy and UX that is ported to Go (D-34).
- Tests: about 62% of lines are policy unit tests, ported with their modules; about 25%
  assert Kubernetes/Cilium/gVisor mechanisms and are replaced.

## Appendix B — v2 defects found during this review

Fix on v2 regardless of v3 (migration step 1).

1. A missing org `blocked-destinations.yaml` skips the overlay and user block
   lists too (`lib/checks.sh:42-45`). Should fail closed.
2. Mutagen is installed from "latest" with no checksum (`lib/lima.sh:219-229`);
   get-helm-3 is piped from `main`; nerdctl in the Lima VM is not verified.
3. PRINCIPLES.md says `.env.*` is masked; the code masks only `.env` and
   `.env.local` (`lib/filesystem.sh:23`).
4. Session pods accept inbound connections from any cluster or world source
   (`lib/policy.sh:288-294`).
5. `uninstall --keep-logs` leaves agent OAuth tokens in
   `~/.sandbox/agent-home/`; betterleaks is never uninstalled; there is no
   Windows uninstall.
6. The per-agent agent home is shared and writable across sessions, repos,
   and tiers (A.4): one session can plant settings or hooks for another.
7. A repo's `core.hooksPath` target (e.g. `.husky/`) and agent-tool config
   such as `.claude/settings.json` are not in the read-only exec-vector set
   (`lib/filesystem.sh:41-48`), so on Linux an agent can write files the host
   executes. Verify and add.
8. Retention days are recorded but not enforced (`lib/tier.sh:61-67`,
   `bin/sandbox:2546-2576`), while `docs/reference/audit-logs.md` implies they
   are.
9. Runtime enforcement tests are manual and mostly use hand-written pods and
   policies; several §7 rows of revision 1 cited tests that verify something
   else (§7.1 "v2 coverage today").
10. Release tags are unsigned and the update path only warns
    (`bin/sandbox:3330-3335`).
11. `.pre-commit-config.yaml`, `lefthook.yml`, `.git/config.worktree`, and
    `.lfsconfig` are not in the read-only set either (same class as item 7).
12. Egress targets are not syntax-checked before the block check
    (`lib/checks.sh:388-402`), which compares them as literal strings, while
    `lib/policy.sh:300-320` renders them into YAML double-quoted scalars that
    interpret backslash escapes. An escaped spelling of a blocked host passes the
    check and reaches the policy as that host. Found in the S8 port
    (2026-11-24); by the owner's decision this one is fixed in v3 only, as the
    `StrictEgressSyntax` deviation, not on v2. Two more paths skip even the
    wildcard and CIDR parts of `check_egress_target_not_blocked`, using
    `check_domain_not_blocked` alone: catalogue egress entries
    (`CatalogueEgressFullCheck`) and `sandbox allow --add-domain`
    (`bin/sandbox:3803-3805`, `AllowEgressFullCheck`, found 2026-11-25), which
    widens a live session's policy with `*.com` or an escaped blocked host.
13. `validate_cidr` (`lib/checks.sh:180-190`) is a shape check: it accepts
    `10.0.0.0/33`, octets over 255, and `:::/8`, which the enforcement layer
    rejects. Fixed in v3 (`StrictCIDRs`).
14. `ip_in_cidr` (`lib/checks.sh:248-257`) evaluates the prefix length as shell
    arithmetic: `/08` is an error that reports "not inside" and `/010` is octal
    `/8`. Fixed in v3 (`DecimalNumbers`).
15. `sandbox onboard` (`lib/onboard.sh:97-124`, `229-264`, `343-392`) copies
    and rewrites files in the agent home with `cp`, shell redirects, and
    `chmod`, all of which follow symlinks, and reads the staged configs through
    them. The agent home is writable from inside the sandbox (a hostPath on
    Linux; copied back with `cp -a` on macOS), so links left there by the agent
    let a later host-side onboard write or read host files outside the agent
    home. Found in the S8 port (2026-11-24); by the owner's decision fixed in v3
    only (`AgentHomeNoFollow`), where agent tokens also move to the broker store
    (5.9.6).
16. `sandbox exceptions add` (`bin/sandbox:4139-4230`) records each line of a
    `PATH:RULE:LINE` as a separate fingerprint. A file the agent names with
    embedded newlines, added through the command the gate itself suggests (which
    quotes the name with `$'...'`), records an extra fingerprint that suppresses
    a real finding in another file. Found in the S8 port (2026-11-25); fixed in
    v3 (`ExceptionSpecOneLine`), as items 12 and 15 are.

## Appendix C — External review dispositions (revision 3)

Two reviews of revision 2 were checked against the code and, where possible,
upstream sources. Reviewer A reviewed commit `282aa9f` on branch
`fix/gvisor-bzip2`, not `master`; its claims about `master` were re-checked and
hold. "Accepted" means the design changed; "partial" means the finding was
narrowed or answered differently.

### Reviewer A

| ID | Finding | Disposition | Where |
|---|---|---|---|
| — | Substrate defaults to gVisor; microVM is opt-in | Accepted (matches ate.dev) | §3.3 |
| R-01 | Gateway runs privileged in a shared namespace; "by construction" claim false under the weak-host model | Accepted | §4, §5.0, §5.8.2, §5.9.2, §5.9.8, D-26, P-09, N-13 |
| R-02 | Refreshed-token pull enables token substitution | Accepted, different remedy: the flow is removed (D-21) rather than moving refresh to the host, because host-side refresh would stop detached keep-alive sessions | §5.1.4, §5.1.5, §5.9.4, §5.9.6, N-17 |
| R-03 | Exec-plugin tokens differ in audience | Accepted | §5.1.3, §5.9.5, §5.9.8, D-19, S2 |
| R-04 | Teleport recipe would ship as a readable exception | Accepted (verified in `examples/teleport/bake-kubeconfig.sh`) | §5.9.4, §5.9.5, §5.9.9, D-28, P-08, N-04 |
| R-05 | Host-side sync enforcement unproven; quarantine UX; missing exec vectors | Accepted | §5.6.2, §5.1.6, S4, N-11, Appendix B.11 |
| R-06 | P-24 parity with v2 cannot pass on Linux | Accepted | G8, P-24 |
| R-07 | Read-only config breaks agents; instruction files missing | Accepted; per-project memory kept with history (functionality) | §5.7, S2, N-08 |
| R-08 | Transcript is agent-writable | Accepted; F8 added | §4, §5.12, §12 |
| R-09 | Dial the address that passed the CIDR check | Accepted | §5.8.4, P-07 |
| R-10 | Host userspace networking as the primary S7 candidate | Accepted | §5.2.6, S7 |
| R-11 | Standard CNI plugins over bespoke netlink | Accepted (SHOULD) | §5.8.2, S1 |
| R-12 | Audit `vm shell` on the host | Accepted | §5.1.6 |
| Scope | Independent security review; adversarial-VM test class | Accepted | §9, §11 |

### Reviewer B

| ID | Finding | Disposition | Where |
|---|---|---|---|
| F-01 | Windows backend may not be KVM; probe should be functional | Accepted, narrowed: §5.2.3 was already functional in intent; `/dev/kvm` is now diagnostic only. The MSHV material found documents a root partition, not a nested guest, so S3 tests both and adds VBS-enabled machines. This is the least certain assumption in the design | §5.2.2, §5.2.3, S3, D-22, OQ-13 |
| F-02 | Gateway enforcement contract and protocol edge cases | Accepted | §5.8.4, §5.8.10, N-14 |
| F-03 | Host-side git signing | Accepted; v2 already signs on the host with hardening, so rev. 2 was parity, but detached signing removes the host git run entirely | §5.1.3, N-09, D-20 |
| F-04 | Sync is a security boundary; filesystem aliasing | Accepted (case and normalization aliasing is a concrete exec-vector bypass on APFS and NTFS) | §5.6.2, S4, N-11, D-24 |
| F-05 | Git consistency under concurrent use | Accepted; the risk already exists in v2 on macOS (`lib/lima.sh:285-307`) | §5.6.4, N-12, D-25 |
| F-06 | Credential boundary wording; broker isolation; local vs issuer revocation | Accepted | §5.9.1, §5.9.2 |
| F-07 | Gateway is not authorization for Tier 3 | Accepted; PRINCIPLES.md already requires least privilege, now with a launch-time rights check | §5.9.5 |
| F-08 | Cross-tier history and workspace influence | Accepted for history: the owner chose agent + repo + tier (D-14). Shared working trees across tiers stay a warning (OQ-06): a repo is the work product and is reviewed, unlike history | §4, §5.7, D-14, OQ-12, N-18 |
| F-09 | Persistent reconciled state machine; attach leases | Accepted | §5.4.3, D-23, N-15 |
| F-10 | Audit suppression before export | Accepted; tamper-proofing against VM root explicitly not claimed | §4, §5.1.5, N-16 |
| F-11 | Token updates need semantic validation | Superseded by D-21 (no flow); identity check kept for in-VM refresh | §5.9.4, §5.9.6, N-17 |
| F-12 | Host isolation outside the appliance | Already addressed (§5.2.6, S7); IPv6, host aliases, and host DNS added | §5.2.6, S7 |
| F-13 | Prefer a mature proxy | Accepted | §5.8.4, D-27 |
| F-14 | "Immutable" image is ambiguous | Accepted | §5.2.5 |
| F-15 | Avoid SSH trust-on-first-use | Accepted | §5.2.5 |
| F-16 | L7 logs may capture secrets | Accepted | §5.12 |
| F-17 | Reproducibility levels | Accepted | §5.3.2 |
| F-18 | Explicit memory budget | Accepted (same as R-06) | P-24 |
| F-19 | Agent-native sandboxes optional | Already addressed in S1; wording added | §5.5.1 |
| Order | Spike order | Accepted | §8 |

### Reviewer C (revision 3, commit `6771431`)

The reviewer's line citations were checked against the document and match.
The git and Lima behaviours F1, F4, and F10 rely on were reported as tested or
read from source by the reviewer, and have since been re-run by the authors:
F4 on Lima 2.3.0 (`docs/design/spikes/S7.md`) and F1 and F10 on git 2.56.0
(`docs/design/spikes/S4.md`; git 2.43.0, the reviewer's version, was not
tested). Where a fix would have removed a
v2 collaboration workflow, it was reshaped to keep the workflow (G9) and the
protection together.

| ID | Finding | Disposition | Where |
|---|---|---|---|
| F1 | VM-origin refs, `HEAD`, tags, and objects reach the host `.git` unreviewed | Accepted, reshaped: fast-forward-only apply on unprotected branches (not a per-session namespace, which would add a manual step to every commit), validated `HEAD` switching, protected branches and non-fast-forward updates quarantined, tags, remotes, reflogs, alternates, and `shallow` never synced, object hash verification, a ledger surfaced at vet time, and entry-level index merge so collaboration stays seamless | §5.1.3, §5.6.2 rules 2 and 6–7, §5.6.4, §5.13, N-19, N-20, D-30 |
| F2 | Push and publish baseline keyed to named domains | Accepted: protocol rules on every intercepted destination; the passthrough residual is stated | §5.8.5, N-06, OQ-02, D-33 |
| F3 | Broker does not scrub injected values from responses | Accepted: response scanning, `credential_reflection` event, `TRACE`/`TRACK` denied; body scanning cost measured in S5 | §5.8.5, §5.9.3, N-04 |
| F4 | Lima default port forwarding publishes VM listeners on host loopback | Accepted: `plain: true` or an ignore-all rule is normative; S7 confirms | §5.2.5, S7, N-02 |
| F5 | Exec-plugin args and env have no stated source | Accepted: the invocation is captured on the host at `run`; the VM sends only an index | §5.1.3, §5.9.5, N-21 |
| F6 | VM-initiated browser open and device code allow phishing | Accepted: foreground onboard only, once, URL templates, host-side client label | §5.1.3, N-22 |
| F7 | Host-reach control has no owner and per-session scoping cannot be host-side | Accepted: `sandbox netd` named and required to fail closed; scoping wording corrected | §5.1.1, §5.2.6, S7, D-31 |
| F8 | Operator-state push sends all of `secrets/` and persists it | Accepted: bound secrets only, staging deleted, broker key in the host keychain | §5.1.4, §5.4.3, §5.9.2, D-32 |
| F9 | Gateway leaf-certificate source unspecified | Accepted: `sandboxd` issues a per-session name-constrained intermediate; the gateway never holds the CA key | §5.10, N-13 |
| F10 | `.gitattributes` can select operator git drivers | Accepted: driver attributes quarantined; the git-lfs triple passes | §5.6.2 rule 8, OQ-07, N-23 |
| F11 | No anti-rollback for signed images | Accepted, with a failed-boot rollback exception; `limactl` is path-pinned rather than hashed, since a hash would break on every Lima upgrade | §5.1.2, §5.3.2, §10, N-24 |
| F12 | Placeholder block possible only on intercepted connections | Accepted (wording) | §5.9.3, N-05 |
| F13 | Document hygiene | Accepted: blocks and rows reordered without changing any ID | §5.8.10, §7.2, §14 |

## Appendix D — Agent harness update paths (research notes, 2026-11-18)

Gathered from public documentation and secondary sources while designing
§5.7.1. **Not authoritative:** S2 MUST re-verify every row against the harness
version in use. "Official" means vendor documentation that was read directly;
"secondary" means blogs, changelog aggregators, or search-result summaries.

| Agent | Update and install paths | Pin a version | In-session updater switch | Integrity source | Basis |
|---|---|---|---|---|---|
| claude | `claude update`; native installs auto-update in the background; npm, Homebrew, WinGet, apt, dnf, and apk installs update manually. Downloads from `claude.ai` (installer) and `downloads.claude.ai` | Installer accepts a version or channel (`install.sh \| bash -s <version>`); `minimumVersion`; `autoUpdatesChannel` (`latest`, `stable`) | `DISABLE_AUTOUPDATER=1` stops background checks only; `DISABLE_UPDATES` blocks every path including `claude update` | Per-release `manifest.json` with SHA256 per platform, GPG-signed (releases from 2.1.89); macOS and Windows code signatures; signed apt, dnf, and apk repositories | Official |
| codex | Standalone installer (`chatgpt.com/codex/install.sh`) downloads from `releases.openai.com/codex` and falls back to GitHub Releases; npm `@openai/codex`; Homebrew cask `codex`. `codex update` (and `--check`) is described by secondary sources; the README read has no update command | npm version; GitHub release asset | None found | None documented in the README | Official for install, secondary for update |
| copilot | npm `@github/copilot`; WinGet `GitHub.Copilot`; Homebrew cask `copilot-cli`; install script `gh.io/copilot-install` (honours `VERSION` and `PREFIX`); executables on the `github/copilot-cli` releases page. The command reference reportedly lists `/update`; `copilot update` and auto-update for script and package installs come from secondary sources | `VERSION` for the script; npm tag | None found | None documented on the install page | Official for install, secondary for update |
| grok | `curl -fsSL https://x.ai/cli/install.sh \| bash`. `grok update` and an `auto_update` setting come from secondary sources only; the official page read does not mention them | Unknown | Unknown | None documented | Official for install; update unconfirmed |
| opencode | `opencode upgrade [version]` per secondary documentation. Official config docs: `update` set to `"disable"`, `"notify"` (default), or `"auto"`, read from global config only (project values are ignored); older documentation and reports use `autoupdate`, and reports conflict across v1 and v2 | `opencode upgrade <version>` (secondary) | `update: "disable"` (official); an environment variable is reported by secondary sources only | None documented | Mixed |

Takeaways for the design: every supported harness has a vendor-documented
install path, and most can be pinned, so an out-of-session updater is
feasible. Only claude documents a signed integrity source, so the other four
start at the TLS-only integrity level until S2 finds more (§5.7.1). Several
update commands are known only from secondary sources, so the updater runs
the vendor's documented install-a-version path, not `<agent> update`, wherever
possible.

**Verified on Linux arm64 on 2026-11-18** (`docs/design/spikes/S2.md`), which
supersedes the "secondary" entries above: `codex update` exists but takes no
version or channel option, and Codex's switch is `check_for_update_on_startup`;
`copilot update [stable|prerelease]` exists, with `COPILOT_AUTO_UPDATE=false`,
`--no-auto-update`, and an `autoUpdate` setting; `grok update` exists with
`--check`, `--version`, and channel flags, with `GROK_DISABLE_AUTOUPDATER` and an
`auto_update` key; opencode 1.0.180 has `opencode upgrade [target]`,
`OPENCODE_DISABLE_AUTOUPDATE`, and an `autoupdate` key. Download hosts:
`downloads.claude.ai`; `releases.openai.com` (GitHub fallback); `github.com` plus
`release-assets.githubusercontent.com` for Copilot and opencode; `x.ai` for
Grok. Of the five installers, one verifies a signed manifest's checksum
without checking the signature, two verify a same-origin digest, and two verify
nothing.

Sources: [Claude Code advanced setup](https://code.claude.com/docs/en/setup);
[Copilot CLI install](https://docs.github.com/copilot/how-tos/set-up/install-copilot-cli);
[opencode config](https://opencode.ai/docs/config);
[Codex README](https://github.com/openai/codex);
[Grok Build CLI announcement](https://x.ai/news/grok-build-cli);
[codex update article](https://codex.danielvaughan.com/2026/05/08/codex-cli-codex-update-self-update-command/).
