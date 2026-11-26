# Rebuilding Images

[← Documentation](../index.md)

The agents' container images are built inside the sandbox VM from v2's
Dockerfiles (`docker/`), with nerdctl and buildkit, straight into the store
sessions start from. The appliance image does not ship them yet, so build them
once after installing, and again whenever you want a newer agent release
(Claude Code, for example, updates whenever Anthropic ships a new model).

```bash
# The base image, needed by all the others.
sandbox rebuild --agent base

# Pull the latest Claude Code release into a fresh sandbox:claude image.
# Cache-busts the install layer automatically.
sandbox rebuild --agent claude

# Also rebuild the Tier 3 variant (sandbox:claude-infra).
sandbox rebuild --agent claude --tier3

# Pin an exact version for codex, opencode, copilot, or grok.
sandbox rebuild --agent codex --codex-version 0.2.1
sandbox rebuild --agent opencode --opencode-version 1.3.17

# Everything (base, every agent, every Tier 3 variant), ignoring cached layers.
sandbox rebuild --agent all --no-cache
```

Each build downloads from the network inside the VM and takes several minutes.
A built image is pinned by digest: `run` uses exactly the image `rebuild`
recorded, and a new build is used by the next session.

Each build is recorded in `~/.sandbox/logs/image-builds.log` (in the VM's copy of
your state) with its digest. v2 recorded the agent's `--version`; v3 does not run
a freshly built image outside a session to ask it.

The build cache lives on the VM's disk beside your sessions. buildkit keeps it
to about 10 GB and prunes after a build when free space falls below 30% of the
disk.

## Changing an image

Edit `docker/Dockerfile.<agent>` (or `Dockerfile.base`), then rebuild the image
and install it into the VM: the Dockerfiles `rebuild` uses are the ones in the
appliance image (`/usr/lib/sandbox/docker`), so a change needs a new appliance
image ([Installing](installing.md#3-build-the-appliance-image)).

Corporate CA certificates are no longer built into the images, as v2 did from
`config/extra-ca-certs/`: v3 gives every session the trust bundle at run time,
including `~/.sandbox/extra-ca-certs/` and the overlay's. See [TLS-intercept
proxies](tls-intercept-proxies.md).
