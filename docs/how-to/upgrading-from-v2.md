# Upgrading from v2

[← Documentation](../index.md)

v3 replaces v2's k3s, Cilium, and gVisor stack with an appliance VM that runs
each session in a Kata microVM. Your settings carry over: v3 reads `~/.sandbox`
in v2's formats. A few things have to be redone, because v3 handles credentials
differently. This page covers what `sandbox install` does with a v2 install,
what you redo, and how to remove v2 when you're done with it.

## What carries over unchanged

v3 reads these from `~/.sandbox` as they are:

- `config.yaml`, `profiles/`, overlays (`overlays/` and `SANDBOX_OVERLAY`)
- `secrets/` (the values; see bindings below)
- `vetting/` (trust roots) and `extra-ca-certs/`
- `logs/` (v3 adds its own sessions beside v2's)

The commands and their flags are v2's, with v2's messages, apart from what is
listed under "What changes" below.

## What you redo

**Sign the agents in again.** v2 kept agent login tokens in
`~/.sandbox/agent-home/<agent>/`, readable by the agent. v3 keeps them in the
VM's credential broker and gives sessions placeholders. v2's token files are
not imported:

- Claude Code: v2 held short-lived OAuth tokens. v3 uses the long-lived token
  `claude setup-token` prints.
- Codex: reusing a v2 copy of a login would share it with another Codex, and
  each one's refresh would sign the other out. v3 makes a login of its own.

See [Signing agents in](onboarding-agents.md).

**Bind your secrets.** In v2 a profile's secret was a plain environment
variable in the agent's pod. In v3 a secret reaches a session only through a
binding: the hosts the broker may send it to, or `--allow-readable` for one the
agent must read itself. A secret without a binding is withheld, and `run` says
so. For each secret your profiles use:

```bash
sandbox secret bind JIRA_PAT --bind jira.example.com
sandbox secret bind NPMRC --allow-readable
```

See [Secrets](secrets.md).

**Build the agent images.** v2's images lived in k3s; v3 builds them in its VM:
`sandbox rebuild --agent base`, then each agent you use. See
[Rebuilding images](rebuilding-images.md).

## What `sandbox install` does with a v2 install

After the VM is up, `install` looks for v2: `~/.sandbox/agent-home`, the Lima VM
`sandbox-vm` on macOS, or k3s on Linux. If it finds one, it prints a report:

```
==> Found a v2 install (agent homes in ~/.sandbox/agent-home; the Lima VM sandbox-vm)
    Carried over as they are: 4 profile(s), 3 secret(s), config.yaml, overlays, vetting, logs.
    In v3 a secret reaches a session only through a binding; these have none and are withheld:
      JIRA_PAT NPMRC
      Bind each to the hosts it is for, e.g.: sandbox secret bind JIRA_PAT --bind api.example.com
    Agents signed in under v2. v3 keeps logins in its credential broker; sign in again:
      claude: run 'claude setup-token', then: sandbox onboard --agent claude
      codex:  sandbox onboard --agent codex
==> Importing Claude Code's v2 conversations into v3's per-tier, per-repository history
    12 conversation(s) imported; 30 stay in ~/.sandbox/agent-home (tier 1, or repositories not on this machine).
v2 is still installed. When you no longer need it: sandbox migrate --remove-v2
```

To install without this, pass `--skip-v2-migration`. Run it later, or again,
with:

```bash
sandbox migrate
```

## Conversation history

v2 kept one Claude Code history for every session of the agent. v3 keeps
history per agent, tier, and set of repositories, so a conversation at one tier
never feeds a session at another.

The import takes each Claude Code conversation whose v2 session record
(`~/.sandbox/logs/<session>/session.json`) names tier 2 or 3 and repositories
that exist on this machine, and adds it to that tier and repository set's
history in the VM. A later v3 session at the same tier on the same
repositories can continue it with Claude's `/resume`. The import keeps files
already there, so running `sandbox migrate` again is safe.

Conversations it can't place stay in `~/.sandbox/agent-home/claude/projects/`:
tier 1 sessions, repositories not on this machine, and conversations without a
session record. Codex's v2 sessions are not imported.

## Using v2 and v3 side by side

Both can be installed at once. They share `~/.sandbox`, use different VMs (v2's
Lima VM is `sandbox-vm`; v3's is a vfkit or qemu VM, or the Lima VM
`sandbox-v3` with `--driver lima`), and each needs its own memory. Give the v3
binary another name, such as `sandbox3`, while both are on your PATH.

> **Do not run `sandbox uninstall --purge` while you still use v2.** It removes
> `~/.sandbox` state that v2 shares: secrets, agent homes, logs, profiles, and
> settings. Plain `sandbox uninstall` asks about each kind of state; answer `n`
> to keep it.

## Removing v2

When you no longer need v2:

```bash
sandbox migrate --remove-v2
```

It shows what it will do and asks first (`--yes` skips the question; without a
terminal it refuses unless you pass `--yes`). Then it:

- deletes the Lima VM `sandbox-vm` (macOS);
- deletes the login token files from `~/.sandbox/agent-home` and moves the
  agent homes, with v2's Lima template, kubeconfig, and version pins, to
  `~/.sandbox/v2-archive/`.

On Linux, v2's k3s, Cilium, and gVisor are removed by `uninstall.sh` from your
v2 checkout; `migrate` only points you there. After this, v2's `sandbox`
command no longer works. v3 is not affected.

## What changes

- `sandbox install` creates the VM from an image (`--dev-image` for now) instead
  of running `setup.sh`; `sandbox status` reports the VM (`sandbox vm status`);
  `sandbox doctor` checks it.
- `sandbox onboard` signs agents in through the broker (above).
- `sandbox secret` gains bindings (`--bind`, `--inject`, `--allow-readable`,
  `sandbox secret bind`).
- `sandbox flows` reads the gateway's request log instead of Hubble.
- `sandbox sync review` shows workspace changes the sync withheld.
- Removed: `configure-network` (the VM follows the host's networking).
  Not built yet: `sandbox upgrade`, `--infra-kubeconfig`, resuming a session
  that was stopped, Copilot and Grok, and Windows.

The [CLI reference](../reference/cli.md) has the full list.
