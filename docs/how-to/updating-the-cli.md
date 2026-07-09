# Updating the CLI

[← Documentation](../index.md)

The `sandbox` CLI runs directly from your git checkout — there's no separate
"installed" copy. So updating the app means moving that checkout forward to the
latest release, which is exactly what `sandbox upgrade` does by default:

```bash
# Update the CLI to the latest release (the default target).
sandbox upgrade

# Preview only — show current -> target, change nothing.
sandbox upgrade --dry-run

# Pin an exact release instead of the newest.
sandbox upgrade --to v2.4.0

# Update the CLI, then rebuild the agent images from the new code.
sandbox upgrade --rebuild
```

`--app` is the explicit spelling of the default, for when you want to be
unambiguous or pair it with infra work (`sandbox upgrade --all`).

## What it does, and what it won't

The app phase **fast-forwards** your checkout to the latest release **tag** —
never the tip of a branch, and only when it's a clean fast-forward. That means:

- **Local edits are safe.** A dirty working tree is refused up front; commit or
  stash first.
- **Local commits are safe.** If your checkout has diverged from the release
  line, the update refuses rather than merging or rewriting. Reconcile with git
  (or re-clone) and try again.
- **It stays on your branch.** A fast-forward moves the branch to the release
  commit; it doesn't detach HEAD or switch branches.

After a successful update the CLI re-stamps its embedded version, so
`sandbox version` and `sandbox status` immediately report the new release.

## Rebuild images if needed

The agent container images are built from this code. A CLI update that changes
`docker/` or bumps a pinned agent version leaves the images stale until you
rebuild — `sandbox upgrade --rebuild` chains it, or run
[`sandbox rebuild`](rebuilding-images.md) yourself when convenient.

## Released tarballs

If you installed from a downloaded release tarball rather than a git clone,
there's no history to fast-forward. `sandbox upgrade` detects this and points
you at the [releases page](https://github.com/samaritanark/agent-sandboxes/releases/latest)
to download the newer tarball and re-run `./setup.sh`.

## Related

- [Upgrading infrastructure (k3s / Cilium / gVisor)](upgrading-infra.md) — the
  `--infra` side of the same command.
- [Rebuilding agent images](rebuilding-images.md) — refresh the agent CLIs that
  live inside the container images.
