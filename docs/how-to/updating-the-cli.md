# Updating the sandbox

[← Documentation](../index.md)

v3 has two parts to update: the host binary and the appliance image.
`sandbox upgrade --image` replaces the image and keeps the VM's state. Signed
releases are not published yet, so you build both yourself for now.

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

Build a new image ([Installing](installing.md#3-build-the-appliance-image)),
stop your sessions, and upgrade:

```bash
sandbox upgrade --image ~/sandbox-appliance.raw
# ==> Replacing the sandbox VM's system disk (its state disk is kept)...
# The sandbox VM is upgraded: image 3.0.0-dev.29 → 3.0.0-dev.30 (control API 1). ...
```

The VM keeps everything that lives on its state disk: agent logins, built agent
images and the build cache, workspace copies, conversation history, agent
homes, and session records. Only the system disk (the image) is replaced, and
the previous one is kept:

- If the new image does not boot and answer, or is older than the installed one,
  the previous system disk is put back automatically (pass `--allow-downgrade`
  to accept an older image).
- `sandbox upgrade --rollback` puts the previous system disk back by hand.
- Each upgrade and roll-back is recorded in `~/.sandbox/logs/upgrades.log`.

A VM installed before 3.0.0-dev.30 keeps its state on its system disk, so it
cannot be upgraded this way: `upgrade` says so. Replace it once:

```bash
sandbox uninstall      # answer n to every question to keep your ~/.sandbox state
sandbox install --dev-image ~/sandbox-appliance.raw
```

Replacing the VM loses what lives only in it: agent logins (onboard again),
agent images (`sandbox rebuild`), conversation history from tier 2 and 3, and
the workspace copies (the next `run` copies your repositories in again; review
withheld changes with `sandbox sync review` first). With `--driver lima` the VM
has no state disk, so replacing it is the only way.

## Agent harnesses

The agents' CLIs (Claude Code, Codex, OpenCode) update when you rebuild their
images; Claude Code's and Codex's own updaters are turned off in sessions. See
[Rebuilding images](rebuilding-images.md).
