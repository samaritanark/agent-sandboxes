# Your First Session

[← Documentation](../index.md)

This walks macOS and Linux users from a clean checkout through Tier 1, 2, and 3
sessions with Claude Code. Windows is not available in v3 yet. Coming from v2?
Read [Upgrading from v2](../how-to/upgrading-from-v2.md) as well.

> **Behind a TLS-intercepting proxy (Zscaler, Netskope, etc.)?** Run
> `sandbox setup-proxy-cert` before you install. See [Corporate TLS-intercept
> proxies](../how-to/tls-intercept-proxies.md).

## 1. Install

Build the host binary, build an appliance image, and install it. The details
are in [Installing](../how-to/installing.md) (coming from v2, first see
[Upgrading from v2](../how-to/upgrading-from-v2.md): the checkout's `bin/sandbox`
is v2's script); in short:

```bash
(cd go && go build -o ~/bin/sandbox ./cmd/sandbox)
image/build-in-lima.sh <lima-vm> 3.0.0-dev.1 ~/sandbox-appliance.raw   # macOS
sudo image/build.sh 3.0.0-dev.1                                        # or on Linux
sandbox install --dev-image ~/sandbox-appliance.raw
```

## 2. Check it

```bash
sandbox doctor
```

Every line should say `ok`. `sandbox vm status` shows the VM and its image
version.

## 3. Build the agent image

```bash
sandbox rebuild --agent base
sandbox rebuild --agent claude
```

This runs in the VM and downloads from the network; give it about 10 minutes.

## 4. Sign Claude Code in

```bash
claude setup-token             # on your machine; prints sk-ant-oat01-...
sandbox onboard --agent claude # paste the token
```

The token goes into the sandbox VM's credential broker. The agent only ever
sees a placeholder. See [Signing agents in](../how-to/onboarding-agents.md),
which also covers Codex and OpenCode.

## 5. Launch a Tier 1 session

```bash
sandbox run --agent claude --tier 1
```

The banner shows the session, its tier, and its egress. Claude Code starts
signed in. When you leave it (`/exit`, or Ctrl-D), the session is torn down.
Tier 1 keeps no history beyond the session.

## 6. Launch a Tier 2 session with your repository

Tier 2 needs a git repository. If your project isn't one, run `git init` in it.

```bash
sandbox run --agent claude --tier 2 --repo ~/repos/my-project
```

The repository is copied into the VM (`==> Syncing ... into the sandbox VM...`)
and mounted at `/workspace`. While the agent works, its changes come back to
your repository every few seconds and once more when the session ends.
Changes to executable configuration (`.git/config`, hooks, and the like) and
conflicts with your own edits are withheld instead; `run` says how many, and
you review them with:

```bash
sandbox sync review
```

Claude's conversation history for this repository at Tier 2 is kept, so a later
session can continue it with `/resume`.

Several repositories in one session: pass `--repo` more than once. Each is
mounted at `/workspace/<basename>`; basenames must be unique.

```bash
sandbox run --agent claude --tier 2 \
  --repo ~/repos/frontend --repo ~/repos/backend
```

## 7. Launch a Tier 3 session

Tier 3 adds infrastructure access. Give the token as a file and the endpoint it
is for; the agent gets a placeholder in `INFRA_TOKEN_<NAME>`, and the gateway
puts the token into its requests to that endpoint's host:

```bash
sandbox rebuild --agent claude --tier3     # once: the claude-infra image
sandbox run --agent claude --tier 3 --repo ~/repos/infra \
  --infra-token vault=~/.vault-token --infra-endpoint https://vault.example.com
```

`--infra-kubeconfig` is not available in v3 yet. See [Tier 3 infra
credentials](../how-to/tier3-infra-credentials.md).

## 8. List sessions, view logs and flows

```bash
sandbox list
sandbox logs  ses-20261126-143022-a7b3
sandbox flows ses-20261126-143022-a7b3    # every connection and request the gateway saw
```

## 9. Keep a session alive and resume it

```bash
sandbox run --agent claude --tier 2 --repo ~/repos/my-project --keep-alive
# leave the agent; the session keeps running. Later:
sandbox resume ses-20261126-143022-a7b3
sandbox stop   ses-20261126-143022-a7b3
```

`resume` syncs the repositories first. It works while the session is running;
resuming a session that was stopped is not available in v3 yet. See [Resuming
sessions](../how-to/resuming-sessions.md).

## Where to next

- [Profiles](../how-to/profiles-and-overlays.md) so you don't retype flags.
- [Persistent extra domains](../how-to/persistent-domains.md) for internal hosts.
- [Secrets](../how-to/secrets.md) for API tokens your agent needs, bound to the hosts they are for.
- [Egress (L7) rules](../how-to/egress-rules.md) to limit what an agent may do on an allowed host.
