# Resuming Sessions

[← Documentation](../index.md)

By default, disconnecting from a session (Ctrl-D, `exit`, or losing the terminal) tears it down.
What you keep depends on the tier:

- **Tiers 2 and 3** keep the agent's conversation history in the sandbox VM, per agent, tier,
  and repository (or set of repositories). A new session of the same agent at the same tier on the
  same repository sees it, so the agent's own `/resume` (Claude Code `--resume`, Codex's session
  list) picks up where you left off. History never crosses tiers.
- **Tier 1** history goes with the session.

To keep a session alive across disconnects (a long build in flight), pass `--keep-alive` to `run`
or `resume`, and reattach later:

```bash
sandbox run --agent claude --tier 2 --repo ~/repos/foo --keep-alive
sandbox list                              # its session ID
sandbox resume <SESSION_ID> [--keep-alive]
```

`resume` first syncs the session's repositories from the sandbox VM to your machine (and keeps
them in sync while you are attached), so work the agent did while you were away is there when you
reattach. Only repositories this machine has synced before are synced; see
[the workspace sync](#the-workspace-sync) below.

A kept-alive session ends on its own after 24 hours with nothing attached, or 7 days in all; a
session that is not kept alive ends about two minutes after its terminal goes away. `sandbox stop
<SESSION_ID>` ends one at once.

**A session that has stopped** is recreated by `resume` from its record, as v2 recreated its pod:
under the same ID, with its repositories, runtime, extra domains, and profile's dependencies. The
workspace gates run again first, and the agent picks up its conversation (tiers 2 and 3 keep it;
a tier 1 session's went with it). Three kinds cannot be recreated this way, and `resume` says why
and prints the `sandbox run` command for an equivalent session: tier 3 (its `--infra-token` files
are not recorded), opencode (its key comes from your shell at each launch), and a session whose
profile binds secrets (only `sandbox run` sends them from your machine).

## The workspace sync

The agent never works on your repository directly. Each repository a session names is copied
into the sandbox VM, the session works on that copy, and changes come back:

- at `sandbox run` (and `resume`), your repository is synced into its copy before the agent
  starts;
- while you are attached, every few seconds, the agent's changes come back to your repository;
- when the session ends, a last pass brings back the rest. `run` says how many files came back.

Changes that could run code on your machine (git config, hooks, `.gitattributes` filters, and the
like) are not applied: they are **withheld** for you to review, and so is a file both sides changed
(a conflict). The session's end reports how many; review them with:

```bash
sandbox sync review                    # what is withheld, with a diff against your checkout
sandbox sync review --apply <id>       # take one withheld change
sandbox sync review --discard <id>     # drop it
sandbox sync once --repo ~/repos/foo   # sync a repository now, outside any session
```

Changes a kept-alive session makes after you detach wait in its copy until the next `run`,
`resume`, or `sandbox sync once`.
