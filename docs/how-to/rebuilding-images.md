# Rebuilding Images

[← Documentation](../index.md)

`./setup.sh` builds and imports every image for you. You only need
this when an agent CLI ships a new release (Claude Code, for
example, must be updated each time Anthropic releases a new model)
or you've changed something in `docker/`.

`sandbox rebuild` is the supported one-shot path — it rebuilds the
selected image(s) and re-imports into k3s containerd:

```bash
# Pull the latest Claude Code release into a fresh sandbox:claude image.
# Cache-busts the install.sh layer automatically.
sandbox rebuild --agent claude

# Also rebuild the Tier 3 variant (sandbox:claude-infra).
sandbox rebuild --agent claude --tier3

# Pin an exact version for codex or opencode.
sandbox rebuild --agent codex --codex-version 0.2.1
sandbox rebuild --agent opencode --opencode-version 1.3.17

# Full rebuild, ignoring all cached layers.
sandbox rebuild --agent all --no-cache
```

Version info for each rebuilt image is appended to
`~/.sandbox/logs/image-builds.log` — useful for whatever image-refresh
cadence your organization sets.

<details>
<summary><b>Manual build (advanced — only when sandbox rebuild can't be used)</b></summary>

Both `docker` and `podman` work. Always tag with the fully-qualified
`docker.io/library/` prefix — podman defaults to `localhost/...`,
which k3s' containerd will not match.

```bash
# Build base (required for all others)
docker build -t docker.io/library/sandbox:base -f docker/Dockerfile.base docker/

# Build agent images
docker build -t docker.io/library/sandbox:claude   -f docker/Dockerfile.claude   docker/
docker build -t docker.io/library/sandbox:codex    -f docker/Dockerfile.codex    docker/
docker build -t docker.io/library/sandbox:opencode -f docker/Dockerfile.opencode docker/

# Shell image — used by tests/test-gvisor.sh, not by normal agent sessions
docker build -t docker.io/library/sandbox:shell -f docker/Dockerfile.shell docker/

# Build infra variants (Tier 3)
docker build --build-arg BASE_IMAGE=sandbox:claude \
  -t docker.io/library/sandbox:claude-infra -f docker/Dockerfile.infra docker/
docker build --build-arg BASE_IMAGE=sandbox:codex \
  -t docker.io/library/sandbox:codex-infra -f docker/Dockerfile.infra docker/
docker build --build-arg BASE_IMAGE=sandbox:opencode \
  -t docker.io/library/sandbox:opencode-infra -f docker/Dockerfile.infra docker/
```

On Linux, import each image into k3s's containerd after building:

```bash
docker save docker.io/library/sandbox:claude | sudo k3s ctr images import -
# or with podman:
podman save docker.io/library/sandbox:claude | sudo k3s ctr images import -
```

</details>
