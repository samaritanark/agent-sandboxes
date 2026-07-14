# Upgrading Infrastructure

[← Documentation](../index.md)

The isolation stack — **k3s** (the cluster), **Cilium** (CNI + network
policy), and **gVisor** (the `runsc` runtime) — is version-pinned in one
place: [`setup/versions.sh`](../../setup/versions.sh). Pinning makes a
checkout reproducible and gives you a concrete answer to "what am I running,
and is it current?" — which matters when a version reaches end-of-life or a CVE
lands.

This guide covers checking versions, bumping the pins, and rolling the running
cluster forward.

## See what you're running

`sandbox status` shows an **Infra versions** section: the pinned version next
to what is actually installed, with a drift flag when they differ.

```text
Infra versions:
  k3s:     pinned v1.35.5+k3s1   installed v1.35.5+k3s1   ok
  Cilium:  pinned 1.19.4         installed v1.19.4        ok
  gVisor:  pinned 20260601.0     installed 20260601.0     ok
  (provisioned 2026-07-08T12:00:00Z; pins from setup/versions.sh)
```

Drift means either the cluster was set up from an older checkout, or the pins
were bumped and an upgrade hasn't run yet.

## How the pins get bumped

- **Automatically (recommended):** [Renovate](../../renovate.json5) watches each
  pin in `setup/versions.sh` and opens a PR when a new version is available
  (k3s, Cilium chart, gVisor release, helm, nerdctl). Infra bumps are labelled
  `infra` / `security` so they get a deliberate review. Renovate owns these
  pins; Dependabot owns GitHub Actions and the Docker base image.
- **Manually:** edit the relevant `SANDBOX_*_VERSION` line in
  `setup/versions.sh`. Setting a pin to an empty string restores the historical
  "install whatever is latest" behavior for that one component.

Merging a bump changes the *intended* version. It does not touch a running
cluster until you upgrade it.

## Roll the cluster forward

> **Infra is opt-in.** Bare `sandbox upgrade` now updates the **CLI itself** to
> the latest release (see [Updating the CLI](updating-the-cli.md)). Infra work —
> which restarts k3s and can drop live sessions — is requested explicitly with
> `--infra` or the individual component flags.

```bash
# Preview: what would change, nothing touched.
sandbox upgrade --infra --dry-run

# Move all infra components to the pinned versions.
sandbox upgrade --infra

# Or just one component (e.g. a Cilium CVE patch), leaving the rest alone.
sandbox upgrade --cilium

# Jump to an explicit version without editing the pins.
sandbox upgrade --gvisor --to-gvisor 20260701.0

# Refresh the host-side betterleaks secret scanner only (no cluster impact).
sandbox upgrade --betterleaks

# Update the CLI and then the infra, in that order.
sandbox upgrade --all
```

`--infra` also refreshes **betterleaks**, the host-side secret scanner that gates
Tier 2/3 launches. Unlike the cluster stack it is just a binary on the host, so
it upgrades on any platform (macOS included) and without the running-session
guard below — swapping it neither restarts k3s nor drops sessions. It is a no-op
when the installed copy already meets the pin.

The infra phase re-runs the component installers with the target versions and
re-records `~/.sandbox/infra-versions`, so `sandbox status` reflects the result.
With `--all`, the app is updated first and the CLI then re-executes itself so the
infra phase applies the newly pulled pins.

### It disrupts running sessions

An infra upgrade restarts k3s and can briefly interrupt the Cilium datapath,
which **kills live agent sessions**. So the infra phase refuses to run while
sessions are active:

```text
ERROR: 2 running session(s). An upgrade restarts k3s and can drop live
       sessions. Stop them ('sandbox stop' / 'sandbox cleanup'), or re-run
       with --force to override.
```

Stop the sessions first, or pass `--force` if you accept the disruption.

## macOS

On macOS the whole stack runs inside the Lima VM, and in-place VM upgrades
aren't supported yet. `sandbox upgrade --infra` prints the re-provisioning path
instead: bump the pins, delete the VM, and re-install.

```bash
limactl delete --force sandbox-vm
sandbox install
```

`sandbox install` provisions the fresh VM with the versions in
`setup/versions.sh`, so the effect is the same — you just get there by
recreating the VM rather than mutating it.

## What isn't covered here

- **Agent CLIs** (Claude Code, Codex, Copilot, OpenCode, Grok) live in the container
  images — refresh those with [`sandbox rebuild`](rebuilding-images.md).
- **Base-image tools** (uv, gitleaks, terraform, the in-image helm) are pinned
  as build args in `docker/Dockerfile.base` / `Dockerfile.infra`.
