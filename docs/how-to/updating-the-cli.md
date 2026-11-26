# Updating the sandbox

[← Documentation](../index.md)

v3 has two parts to update: the host binary and the appliance image. The
planned `sandbox upgrade`, which will update both and keep the VM's state, is
not built yet. Until it is:

## The host binary

Move your checkout forward and rebuild:

```bash
git pull --ff-only
(cd go && go build -o ~/bin/sandbox ./cmd/sandbox)
```

The binary and the image check each other's control API version at every
command. If they no longer match, the command stops and says which side is
older.

## The appliance image

Build a new image ([Installing](installing.md#3-build-the-appliance-image)), then
replace the VM:

```bash
sandbox uninstall      # answer n to every question to keep your ~/.sandbox state
sandbox install --dev-image ~/sandbox-appliance.raw
```

Replacing the VM loses what lives only in it:

- **Agent logins** in the credential broker: run `sandbox onboard` again for
  each agent ([Signing agents in](onboarding-agents.md)).
- **Agent images**: `sandbox rebuild --agent base` and each agent again.
- **Conversation history** from tier 2 and 3 sessions.
- **Workspace copies**: the next `run` copies your repositories in again. Your
  repositories on the host are not touched. Review withheld changes
  (`sandbox sync review`) first; keep `quarantine/` and `sync/` when
  `uninstall` asks.

Stop your sessions first: `uninstall` deletes the VM with whatever is running in
it.

## Agent harnesses

The agents' CLIs (Claude Code, Codex, OpenCode) update when you rebuild their
images; Claude Code's and Codex's own updaters are turned off in sessions. See
[Rebuilding images](rebuilding-images.md).
