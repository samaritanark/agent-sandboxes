# Kata or gVisor

[← Documentation](../index.md)

Every session runs its agent, and each of its dependencies, under one of two
runtimes inside the sandbox VM:

- **Kata** (the default): each one runs in a microVM with its own Linux kernel,
  a hardware-virtualized guest of the sandbox VM.
- **gVisor**: each one runs in a gVisor sandbox, where gVisor's user-space
  kernel answers the agent's system calls instead of a Linux kernel.

Neither is recommended over the other. This page says how to choose, what changes
in use, and what changes in the security model, so that you can decide for your
own work.

## Why someone might choose gVisor

On macOS the sandbox VM is itself a virtual machine, so a Kata microVM is a VM
inside a VM. Apple silicon makes that second level expensive. Measured on a
4-CPU sandbox VM with Claude Code:

| | Kata | gVisor |
|---|---|---|
| launch to attach (tier 1) | 2.4–2.7 s | 0.5 s |
| launch to Claude Code's first screen | 6–7 s | about 1 s |
| keystroke echo (median) | 50–80 ms | 15–30 ms |

The gap comes from nested virtualization, so it is largest on macOS. On a Linux
machine, where the sandbox VM runs under KVM, it is expected to be much smaller
(not yet measured).

## Why someone might keep Kata

Kata puts a hardware boundary, a separate kernel in a separate VM, between the
agent and the sandbox VM, and between one session and another. gVisor's boundary
is software. See [Security differences](#security-differences) below.

## Choosing

- **For one session:** `sandbox run --runtime gvisor ...` or
  `sandbox run --runtime kata ...`.
- **As your default:** add `runtime: gvisor` (or `runtime: kata`) to
  `~/.sandbox/config.yaml`. `--runtime` overrides it for one session.
- **Not from a repository:** a repository's own `.sandbox/config.yaml` cannot
  choose the runtime; only your config and your command line can.

The session banner's `Runtime` line, and the `session_requested` record in the
session's audit log, say which runtime a session used. A session never falls
back from one runtime to the other: if the one asked for cannot start, the
launch fails.

## Differences in use

Most work is the same under both: the same images, workspace, tools, network
rules, credentials, and history. The differences:

- **Speed:** see the table above.
- **The kernel the agent sees:** under gVisor, `uname` reports gVisor's kernel
  (`4.19.0-gvisor`), not Linux's. A program that depends on a specific kernel
  feature or on reading kernel details from `/proc` or `/sys` can behave
  differently. gVisor implements most of Linux's system calls but not all of
  them; a tool that needs one it lacks fails under gVisor and works under Kata.
- **Dependencies:** a profile's `services:` and `mcps:` run under the session's
  runtime.
- **Codex's own sandbox** is off under both runtimes (`danger-full-access`, as
  in v2); the session itself is the boundary.

## Security differences

What is the same under both runtimes:

- The agent runs as uid 1000 with no capabilities and no privilege escalation,
  and the default seccomp profile applies to it (Kata enforces it in the guest
  kernel, gVisor in its own kernel).
- It sees only its own processes, cannot mount file systems or create user
  namespaces, and cannot open raw sockets.
- Its only network link goes to the session's gateway, which enforces the
  allowlist, the block lists, and the L7 rules, and records what it drops. Under
  gVisor, gVisor's own network stack sends the agent's packets over that link.
- Its workspace has the same masks and read-only paths, and its changes pass
  the same sync gate on your machine.
- The sandbox VM, `sandbox netd`, and the credential broker stand behind both.

What differs:

| | Kata | gVisor |
|---|---|---|
| Between the agent and the sandbox VM's kernel | a guest Linux kernel in a hardware-virtualized microVM | gVisor's user-space kernel, itself limited by seccomp to a small set of the VM kernel's system calls |
| Between two sessions | separate microVMs | separate gVisor sandboxes on the same VM kernel |
| To reach the sandbox VM, an agent needs | a guest kernel exploit, then an escape from Cloud Hypervisor or KVM | an exploit of gVisor's kernel, then an exploit of the VM kernel through the calls gVisor may make |

Reaching the sandbox VM is serious under either runtime: root there can read
the credential broker's store, other sessions' workspace copies, and the
brokers' memory (see [Accepted risks](../explanation/security-model.md#accepted-risks)).
It still cannot reach your machine beyond the SSH channel and the sync.

For comparison, v2 ran every session under gVisor, with no sandbox VM behind it
on Linux.
