# Rebuilding Images

[← Documentation](../index.md)

`./setup.sh` builds every image for you (via nerdctl + buildkit, straight into
k3s's containerd — no host Docker/Podman required). You only need
this when an agent CLI ships a new release (Claude Code, for
example, must be updated each time Anthropic releases a new model)
or you've changed something in `docker/`.

`sandbox rebuild` is the supported one-shot path — it rebuilds the
selected image(s) directly into k3s containerd:

```bash
# Pull the latest Claude Code release into a fresh sandbox:claude image.
# Cache-busts the install.sh layer automatically.
sandbox rebuild --agent claude

# Also rebuild the Tier 3 variant (sandbox:claude-infra).
sandbox rebuild --agent claude --tier3

# Pin an exact version for codex, opencode, or grok.
sandbox rebuild --agent codex --codex-version 0.2.1
sandbox rebuild --agent opencode --opencode-version 1.3.17
sandbox rebuild --agent grok --grok-version 0.2.93   # semver only; "latest" is rejected

# Full rebuild, ignoring all cached layers.
sandbox rebuild --agent all --no-cache
```

Version info for each rebuilt image is appended to
`~/.sandbox/logs/image-builds.log` — useful for whatever image-refresh
cadence your organization sets.

<details>
<summary><b>Manual build (advanced — only when sandbox rebuild can't be used)</b></summary>

On Linux, build with `nerdctl` pointed at k3s's own containerd (the `k8s.io`
namespace), so each image lands directly where k3s reads it — no separate import
step. `sandbox install` sets up nerdctl + buildkit for you. Always tag with the
fully-qualified `docker.io/library/` prefix (the images are referenced that way
and k3s' containerd will not match a bare `localhost/...`).

```bash
# All commands go through k3s's containerd:
nerdctl="sudo nerdctl --address /run/k3s/containerd/containerd.sock --namespace k8s.io"

# Build base (required for all others)
$nerdctl build -t docker.io/library/sandbox:base -f docker/Dockerfile.base docker/

# Build agent images
$nerdctl build -t docker.io/library/sandbox:claude   -f docker/Dockerfile.claude   docker/
$nerdctl build -t docker.io/library/sandbox:codex    -f docker/Dockerfile.codex    docker/
$nerdctl build -t docker.io/library/sandbox:opencode -f docker/Dockerfile.opencode docker/

# Shell image — used by tests/test-gvisor.sh, not by normal agent sessions
$nerdctl build -t docker.io/library/sandbox:shell -f docker/Dockerfile.shell docker/

# Build infra variants (Tier 3)
$nerdctl build --build-arg BASE_IMAGE=sandbox:claude \
  -t docker.io/library/sandbox:claude-infra -f docker/Dockerfile.infra docker/
$nerdctl build --build-arg BASE_IMAGE=sandbox:codex \
  -t docker.io/library/sandbox:codex-infra -f docker/Dockerfile.infra docker/
$nerdctl build --build-arg BASE_IMAGE=sandbox:opencode \
  -t docker.io/library/sandbox:opencode-infra -f docker/Dockerfile.infra docker/
```

Because the build writes straight into k3s's containerd there is no `save | ctr
import` step. You do still need to pin each image so the kubelet's image garbage
collector never reclaims it (these images have no backing registry and cannot be
re-pulled — an evicted image fails the next launch with `ErrImageNeverPull`).
`setup.sh` and `sandbox rebuild` pin for you; by hand:

```bash
# Pin against kubelet image GC (re-run after every rebuild — a rebuild resets it):
sudo k3s ctr -n k8s.io images label docker.io/library/sandbox:claude \
  io.cri-containerd.pinned=pinned
```

> On macOS the build runs inside the Lima VM — run the equivalent `nerdctl`
> commands there via `limactl shell sandbox-vm`, or just use `sandbox rebuild`.

</details>
