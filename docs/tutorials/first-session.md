# Your First Session

[← Documentation](../index.md)

This walks Linux and macOS users from a clean checkout through Tier 1, 2, and 3
sessions. **Windows users:** follow the [Windows / WSL2 setup](../how-to/platforms/windows.md)
guide instead (it uses a dedicated WSL2 distro), then rejoin at step 4 here.

> **Behind a TLS-intercepting proxy (Zscaler, Netskope, etc.)?** Run
> `./bin/sandbox setup-proxy-cert` before `./setup.sh`. Without it, the
> image build's HTTPS fetches will fail. See [Corporate TLS-intercept
> proxies](../how-to/tls-intercept-proxies.md). `./setup.sh` also runs a TLS
> probe up front and aborts with a pointer there if it detects interception.

## 1. Install prerequisites

k3s + Cilium + gVisor on Linux; a Lima VM on macOS (Homebrew + Lima are
installed automatically if missing).

```bash
./setup.sh

# If your host network uses 100.64.0.0/10 (CGNAT), pick a non-overlapping pod CIDR:
./setup.sh --pod-cidr 172.16.128.0/17

# If your host network overlaps the default service CIDR (10.43.0.0/16):
./setup.sh --service-cidr 172.16.0.0/20

# If you already run another local Kubernetes endpoint on 6443 (e.g. Ansible
# or kubectl tooling pointed at a cluster on OpenStack), move the sandbox
# cluster's API server off 6443 so the two don't collide:
./setup.sh --apiserver-port 7443
```

See [Cluster CIDRs](../explanation/architecture.md#cluster-cidrs) and [API
server port](../explanation/architecture.md#api-server-port) for the reasoning.

Once the CLI is on your PATH (step 2), `sandbox install` is the exact equivalent
of `./setup.sh` (same flags), and `sandbox uninstall` tears everything back
down. `./setup.sh` still works — use whichever you prefer.

## 2. Put the CLI on PATH

Add `bin/` to PATH and load completions for this shell. To make it permanent,
add both lines to your `~/.bashrc` or `~/.zshrc`.

```bash
export PATH="$(pwd)/bin:$PATH"
source bin/completions/sandbox.bash   # or sandbox.zsh
```

## 3. Smoke-test the install

Cluster, Cilium, gVisor, and namespace should all be green (and an **Infra
versions** section shows what's installed vs pinned). If any are missing, re-run
`./setup.sh` (or `sandbox install`) before continuing.

```bash
sandbox status
```

### 3b. (Optional) Stage existing OAuth tokens

If you've already logged into Claude Code or Codex on the host, this stages
those OAuth tokens into `~/.sandbox/agent-home/<agent>/` so your first sandbox
session doesn't make you re-auth. It also writes a starter
`~/.sandbox/config.yaml`. It skips opencode (API key — use
[`sandbox secret`](../how-to/secrets.md) for that).

```bash
sandbox onboard
```

## 4. Launch a Tier 1 session

First run prints an OAuth URL — open it in a browser, log in, paste the returned
code back. (If you ran `sandbox onboard` above and the host-side OAuth was
valid, this just works.) Tokens persist in `~/.sandbox/agent-home/<agent>/` so
you only do this once per agent.

```bash
sandbox run --agent claude --tier 1
```

## 5. Launch a Tier 2 session with your repo

Tier 2 requires a git repo (so changes can be diffed against a baseline). If
your project isn't one yet, run `git init` in it.

```bash
sandbox run --agent claude --tier 2 --repo ~/repos/my-project
```

Working across more than one repo in a single session — pass `--repo` more than
once. With one `--repo` the workspace is `/workspace` (as above); with two or
more, each is mounted at `/workspace/<basename>` so the agent can `cd` between
them. Basenames across `--repo` flags must be unique; the tool refuses on
collision.

```bash
sandbox run --agent claude --tier 2 \
  --repo ~/repos/frontend --repo ~/repos/backend
```

## 6. Launch a Tier 3 session against a dev cluster

`--infra-kubeconfig` is minified to one context and mounted at
`/home/agent/.kube/config` inside the pod; the API server hostname/port is
auto-added to the egress allowlist.

> **Most ambient kubeconfigs won't work as-is.** Kubeconfigs written by
> `tsh kube login`, `aws eks update-kubeconfig`, `gcloud container clusters
> get-credentials`, or `az aks get-credentials` use exec credential plugins
> that cannot run in the pod. `sandbox run` detects this and prompts — pressing
> `y` launches a session that loads but every kubectl call fails. See [Tier 3
> Infra Credentials](../how-to/tier3-infra-credentials.md) for how to produce a
> kubeconfig with static credentials.

```bash
sandbox run --agent claude --tier 3 --repo ~/repos/infra \
  --infra-kubeconfig ~/.kube/sandbox-dev.yaml
```

## 7. List sessions / view logs

```bash
sandbox list
sandbox logs ses-20260401-143022-a7b3
```

## 8. Resume a session

Only works while the pod is still running; see [Resuming
Sessions](../how-to/resuming-sessions.md) for how sessions behave on disconnect.

```bash
sandbox resume ses-20260401-143022-a7b3
```

## Where to next

- [Profiles](../how-to/profiles-and-overlays.md) so you don't retype flags.
- [Persistent extra domains](../how-to/persistent-domains.md) for internal hosts.
- [Secrets](../how-to/secrets.md) for non-OAuth credentials.
