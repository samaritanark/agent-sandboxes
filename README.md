# Agent Sandbox

Sandboxed execution environment for AI coding agents
(Claude Code, OpenAI Codex CLI, OpenCode).
Provides kernel-level isolation (gVisor), network policy enforcement
(Cilium), and filesystem masking. Design intent and operator guidance
in PRINCIPLES.md.

## When to use this

Use this sandbox when you want an AI agent to run shell commands, edit
files, and reach the network on your behalf — **and you don't fully
trust what it might do**. Each session runs in its own gVisor-isolated
pod with a default-deny egress policy: the agent can only reach the
domains its tier whitelists, can't see your `~/.ssh/`, `~/.aws/`, or
`~/.kube/`, and any destructive command it runs is contained to a
single pod that you can `sandbox stop` at any time.

You probably **don't** need this if you're just chatting with an LLM
through its hosted UI, or running the official CLI yourself on a repo
you'd let any colleague edit. The sandbox exists for the "agent
autonomously executes things" case — code generation, infra work,
multi-step tasks — where a mistake or jailbreak could touch real
systems.

Before your first session, skim **PRINCIPLES.md** — it covers what
this sandbox defends against, what it doesn't, and your accountability
as the operator (credential handling, tier escalation, what's never
permitted regardless of configuration).

## Quick Start

Linux and macOS users — follow the bash block below. **Windows users**:
skip to the "Windows quick start" section below for the PowerShell
equivalent (uses a dedicated WSL2 distro).

> **Behind a TLS-intercepting proxy (Zscaler, Netskope, etc.)?** Run
> `./bin/sandbox setup-proxy-cert` before `./setup.sh`. Without it, the
> image build's HTTPS fetches will fail. See "Corporate TLS-intercept
> proxies" below. `./setup.sh` also runs a TLS probe up front and
> aborts with a pointer here if it detects interception.

```bash
# 1. Install prerequisites (k3s + Cilium + gVisor on Linux; Lima VM on macOS).
#    Installs Homebrew + Lima automatically on macOS if missing.
./setup.sh

# If your host network uses 100.64.0.0/10 (CGNAT), pick a non-overlapping pod CIDR:
./setup.sh --pod-cidr 172.16.128.0/17

# If your host network overlaps the default service CIDR (10.43.0.0/16):
./setup.sh --service-cidr 172.16.0.0/20

# If you already run another local Kubernetes endpoint on 6443 (e.g. Ansible
# or kubectl tooling pointed at a cluster on OpenStack), move the sandbox
# cluster's API server off 6443 so the two don't collide:
./setup.sh --apiserver-port 7443

# 2. Add bin/ to PATH and load completions for this shell.
#    To make it permanent, add both lines to your ~/.bashrc or ~/.zshrc.
export PATH="$(pwd)/bin:$PATH"
source bin/completions/sandbox.bash   # or sandbox.zsh

# 3. Smoke-test the install — cluster, Cilium, gVisor, namespace all green.
#    If any are missing, re-run ./setup.sh before continuing.
sandbox status

# 3b. (Optional) If you've already logged into Claude Code or Codex on the
#     host, stage those OAuth tokens into ~/.sandbox/agent-home/<agent>/ so
#     your first sandbox session doesn't make you re-auth. Also writes a
#     starter ~/.sandbox/config.yaml. Skips opencode (API key — use
#     `sandbox secret` for that).
sandbox onboard

# 4. Launch a Tier 1 Claude session.
#    First run prints an OAuth URL — open it in a browser, log in, paste
#    the returned code back. (If you ran `sandbox onboard` above and the
#    host-side OAuth was valid, this just works.) Tokens persist in
#    ~/.sandbox/agent-home/<agent>/ so you only do this once per agent.
sandbox run --agent claude --tier 1

# 5. Launch a Tier 2 session with your repo.
#    Tier 2 requires a git repo (so changes can be diffed against a
#    baseline). If your project isn't one yet, run `git init` in it.
sandbox run --agent claude --tier 2 --repo ~/repos/my-project

# 5b. Working across more than one repo in a single session — pass --repo
#     more than once. With one --repo the workspace is /workspace (as
#     above); with two or more, each is mounted at /workspace/<basename>
#     so the agent can `cd` between them. Basenames across --repo flags
#     must be unique; the tool refuses on collision.
sandbox run --agent claude --tier 2 \
  --repo ~/repos/frontend --repo ~/repos/backend

# 6. Launch a Tier 3 session against a dev cluster.
#    --infra-kubeconfig is minified to one context and mounted at
#    /home/agent/.kube/config inside the pod; the API server hostname/port
#    is auto-added to the egress allowlist.
#
#    IMPORTANT: most ambient kubeconfigs (written by tsh kube login,
#    aws eks update-kubeconfig, gcloud container clusters get-credentials,
#    az aks get-credentials) use exec credential plugins that cannot run
#    in the pod. `sandbox run` will detect this and prompt — pressing
#    `y` will launch a session that loads but every kubectl call fails.
#    See "Tier 3 Infra Credentials" below for how to produce a kubeconfig
#    with static credentials (the Teleport bake script + the ServiceAccount
#    token recipe cover the common cases).
sandbox run --agent claude --tier 3 --repo ~/repos/infra \
  --infra-kubeconfig ~/.kube/sandbox-dev.yaml

# 7. List sessions / view logs
sandbox list
sandbox logs ses-20260401-143022-a7b3

# 8. Resume a session (only works while the pod is still running;
#    see "Resuming Sessions" below for how sessions behave on disconnect)
sandbox resume ses-20260401-143022-a7b3
```

> **opencode users:** `OPENCODE_API_KEY` must be set in the host environment,
> and you must supply an OpenAI-compatible endpoint URL — either via
> `OPENCODE_BASE_URL` in the env, or per-invocation with `--base-url <URL>`
> (`https://api.openai.com/v1`, an internal vLLM/Ollama proxy, etc.). The CLI
> will refuse to start if either is missing. claude and codex use OAuth and
> require nothing in advance.

## Supported Agents

| Agent    | Image            | Auth    | Allowed domains                                                                                  |
|----------|------------------|---------|--------------------------------------------------------------------------------------------------|
| claude   | sandbox:claude   | OAuth   | `claude.ai`, `api.anthropic.com`, `console.anthropic.com`, `statsig.anthropic.com`, `sentry.io`  |
| codex    | sandbox:codex    | OAuth   | `api.openai.com`, `auth.openai.com`, `auth0.openai.com`, `cdn.openai.com`, `chatgpt.com`         |
| opencode | sandbox:opencode | API key | hostname of `OPENCODE_BASE_URL` (any OpenAI-compatible endpoint; operator chooses)               |

Allowlists are exact-match FQDNs — wildcard subdomains are not allowed. See
`lib/agents.sh` for the authoritative list.

## Tiers

| Tier | Workspace     | Extra domains                                                                                                                              | Requirements                                                  |
|------|---------------|--------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| 1    | emptyDir      | none                                                                                                                                       | none                                                          |
| 2    | hostPath repo(s) | `github.com`, `api.github.com`, `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org`, `registry.terraform.io`    | `--repo` (repeatable, each must be a git repo)                |
| 3    | hostPath repo(s) | Tier 2 + URLs from `--infra-endpoint`; API server host/port from `--infra-kubeconfig`                                                      | `--repo` (repeatable) + at least one of `--infra-token` or `--infra-kubeconfig` |

Tier 3 also swaps in the `sandbox:<agent>-infra` image variant, which carries
the infra tooling layer. See `lib/tier.sh` for the authoritative domain list.

## Persistent extras

If your team always needs the same extra domain reachable (an internal Git
host, an artifact registry, etc.), you don't have to type `--allow-domain`
on every invocation. Three persistent sources are loaded automatically on
every `sandbox run` and merged with the built-in tier allowlist:

```yaml
# ~/.sandbox/config.yaml — per-user defaults
extra_allowed_domains:
  - git.example.com
  - artifactory.example.com
```

```bash
# Shell env (comma-separated) — convenient for CI / shell-rc
export SANDBOX_EXTRA_ALLOWED_DOMAINS="git.example.com,artifactory.example.com"
```

```yaml
# <repo>/.sandbox/config.yaml — per-repo defaults, checked in alongside code
extra_allowed_domains:
  - go.private.example.com   # private Go module proxy
  - npm.private.example.com
```

The per-repo source lets a project ship its own allow-list additions
(private package indexes, internal mirrors, etc.) without every
contributor having to add them to their personal config. **Because anyone
with push access to the repo can edit it, every session start prints a
banner listing what each repo's `.sandbox/config.yaml` contributed** —
that keeps slipped-in additions visible to the operator launching the
session.

All three sources are subject to the same blocked-destinations check as
`--allow-domain`, so an entry that matches `config/blocked-destinations.yaml`
is still rejected.

### Live-updating a running session

If a session hits a domain that's not in its allowlist, you don't have
to stop and restart the pod. `sandbox allow` regenerates the
CiliumNetworkPolicy with extra entries and applies it in place — the
pod isn't restarted and in-flight connections are preserved:

```bash
sandbox allow ses-20260527-...-a7b3 --add-domain go.private.example.com
```

Each `--add-domain` goes through the same blocked-destinations check
as `--allow-domain` at launch. The change is recorded in
`~/.sandbox/logs/<session>/session.json` (both in `allowed_domains` and
as an event). `sandbox allow` is add-only — narrowing a live
allowlist requires `sandbox stop` and a fresh `sandbox run`.

## Profiles and overlays

A **profile** is a named bundle that declares a tier plus an optional
agent, default `--repo`, and extra allowed domains. Numeric profiles
(`--profile 1`, `--profile 2`, `--profile 3`) are pure aliases for
`--tier`. Named profiles resolve a YAML file:

```bash
sandbox run --profile dev-app
```

```yaml
# ~/.sandbox/profiles/dev-app.yaml
tier: 2                           # required — passes the same validate_tier check
agent: codex                      # optional — used when --agent is absent; if
                                  #   neither is set, run falls back to claude
default_repo: ~/repos/dev-app     # optional; used when --repo is absent
extra_allowed_domains:            # optional; merged with --allow-domain
  - api.dev-app.example.com
secrets: []                       # Phase 4
mcps: []                          # Phase 5
```

**Only `tier` is required** — every other field, `agent` included, is
optional. An explicit `--agent` / `--repo` / `--tier` on the command
line overrides the profile (a *conflicting* explicit `--agent` or
`--tier` is rejected so a launch is never ambiguous about which it
used).

You don't have to hand-write the YAML — `sandbox profile save` generates
it from the same flags you'd pass to `run`:

```bash
# Saves ~/.sandbox/profiles/stratum-codex.yaml
sandbox profile save --tier 2 --agent codex \
  --repo ~/git/public/stratum --name stratum-codex

# --name is optional; omitted, it's derived from the repo and agent
# (here → "stratum-codex"). --agent is optional too:
sandbox profile save --tier 2 --repo ~/git/public/stratum   # → "stratum"

sandbox profile list                  # user + overlay profiles
sandbox profile show stratum-codex    # print one
sandbox profile delete stratum-codex  # remove one of yours
sandbox run --profile stratum-codex   # launch it
```

`save` only writes YAML — it never launches anything, and every value is
re-validated at `run` time (the tier check, and the blocked-destinations
check on each domain), so a saved profile can never widen what a session
is allowed to do. Domains are also checked at save time, so a profile
that `run` would reject is never written in the first place. Profiles are
written to `~/.sandbox/profiles/` only; `save`/`delete` never touch an
overlay (those are team-shipped — see below), though `list`/`show` read
them. A single `--repo` is supported per profile; multi-repo launches
still use `run --repo … --repo …`.

An **overlay** is a directory a team ships to layer their own profiles,
governance doc, and additional blocked-destinations on top of the org
install. Point at it via either source:

```bash
export SANDBOX_OVERLAY=/path/to/overlay-myteam
```

```yaml
# ~/.sandbox/config.yaml
overlay: /path/to/overlay-myteam
```

The CLI searches `~/.sandbox/profiles/<name>.yaml` first, then
`<overlay>/profiles/<name>.yaml`. Overlay
`blocked-destinations.yaml` is unioned with the org's at session-launch
time — overlays are **additive only on the safety side**, they cannot
weaken the org's controls or the tier model. See
`examples/overlay-template/` for the layout and a starter
`GOVERNANCE.md`.

## Secret store

For credentials that aren't OAuth (Jira PATs, Gitea tokens, internal API
keys), the sandbox keeps a host-side store at `~/.sandbox/secrets/`
(mode 0600 per file) and injects what a profile declares as
session-scoped Kubernetes Secrets. Values **never persist in the
cluster across sessions** — they're created when the session launches
and deleted when it stops (PRINCIPLES.md "Credential isolation" rule 2).

```bash
# Add a secret. Name must match [A-Z_][A-Z0-9_]* — it's the env var
# the agent sees inside the pod.
printf '%s' 'abcd1234' | sandbox secret set JIRA_PAT

# Pull from a host env var with the same name (direnv / 1password-cli /
# .envrc / `export` — anything already in your shell). Defaults the source
# var name to the secret name; pass --from-env=OTHER_VAR to override.
sandbox secret set JIRA_PAT --from-env

# Or from a file on disk
sandbox secret set GITEA_TOKEN --from-file ~/.gitea-token

# Inspect (values are never printed)
sandbox secret list

# Remove
sandbox secret delete JIRA_PAT
```

Then list those names in a profile to inject them at session launch:

```yaml
# ~/.sandbox/profiles/dev-app.yaml
tier: 2
secrets:
  - JIRA_PAT
  - GITEA_TOKEN
```

At `sandbox run --profile dev-app` time, those values are read from the
host store and packed into one Secret (`session-secrets-<id>`); the pod
gets them via `envFrom: secretRef`, so each lands as `$JIRA_PAT` /
`$GITEA_TOKEN` inside the container. If a declared secret is missing
from the host store the launch is aborted before any cluster resources
are created.

### Using a secret inside the session

Each declared secret is a plain environment variable in the agent's
shell, named exactly as you stored it. So once you're in the session you
(or the agent) just reference it like any other env var — no unlock step,
no file to read:

```bash
# Inside the sandbox, the value is already in the environment:
curl -H "Authorization: Bearer $JIRA_PAT" https://jira.example.com/rest/...
git clone https://oauth2:$GITEA_TOKEN@gitea.example.com/team/repo.git
```

When you're driving the agent in natural language, tell it the env var
name rather than the value — e.g. "authenticate with the token in
`$JIRA_PAT`". The agent can use the variable without the secret ever
appearing in the transcript. To confirm what's present without printing
values, run `env | grep -o '^[A-Z_]*=' | sort` inside the session (or
check `printenv JIRA_PAT >/dev/null && echo set`); `sandbox secret list`
on the host shows the same names from the outside.

## CLI Reference

```text
sandbox run [OPTIONS]
  --agent <claude|codex|opencode>    default: claude
  --tier <1|2|3>                     default: 1
  --profile <NAME>                   numeric (1|2|3) aliases --tier; named
                                     resolves ~/.sandbox/profiles/<name>.yaml
                                     or <overlay>/profiles/<name>.yaml
  --repo <PATH>                      required for tier 2/3; repeatable —
                                     with one repo the workspace is
                                     /workspace, with two or more each
                                     mounts at /workspace/<basename>
  --allow-domain <DOMAIN>            repeatable; blocked list applies
  --base-url <URL>                   opencode: OpenAI-compatible endpoint;
                                     overrides OPENCODE_BASE_URL env var
  --infra-token <PATH>               tier 3; injected as $INFRA_TOKEN
  --infra-kubeconfig <PATH>          tier 3; mounted at /home/agent/.kube/config
                                     (auto-minified to a single context,
                                     API server host/port auto-allowlisted)
  --infra-kube-context <NAME>        context inside --infra-kubeconfig
                                     (default: kubeconfig's current-context)
  --allow-exec-plugin                skip the exec-plugin confirmation prompt
                                     (only useful for scripted runs; plugin
                                     will still fail at auth time)
  --infra-endpoint <URL>             tier 3, repeatable
  --dry-run
  --name <name>                      human-readable label (auto-set if omitted)
  --keep-alive                       leave pod running after disconnect
                                     (default: tear down to free cluster resources)

sandbox resume <SESSION_ID> [--keep-alive]
sandbox list
sandbox logs <SESSION_ID>
sandbox flows <SESSION_ID>
sandbox stop <SESSION_ID>
sandbox profile save [--tier N] [--agent NAME] [--repo PATH]
                     [--allow-domain DOMAIN]... [--name NAME]
                     [--force] [--dry-run]
                     # --tier required; --agent and --repo optional.
                     # name auto-derived from repo + agent if omitted.
sandbox profile list
sandbox profile show <NAME>
sandbox profile delete <NAME> [--yes]
sandbox secret set <NAME> [--from-file PATH | --from-env[=VAR]]  # else reads stdin
                     # NAME must match [A-Z_][A-Z0-9_]* — it's the env var
                     # the agent sees inside the pod. --from-env defaults
                     # the source var to NAME; use =VAR to override.
sandbox secret list                           # names + sizes + mtimes; values never printed
sandbox secret delete <NAME>
sandbox cleanup [--older-than DAYS]            default: 90
sandbox check <WORKSPACE_PATH>
sandbox status
sandbox setup [--pod-cidr CIDR] [--service-cidr CIDR] [--apiserver-port PORT]
sandbox configure-network                       # Linux only; re-detect host
                                                # interfaces, re-apply to Cilium
                                                # (also auto-run by `sandbox run`)
sandbox rebuild [--agent NAME] [--tier3] [--no-cache]
                [--codex-version VER] [--opencode-version VER]
sandbox version
```

### Diagnostic subcommands

- **`sandbox status`** — single-screen health check: cluster reachable,
  Cilium policy mode, gVisor RuntimeClass present, sandbox namespace
  exists, running session count. Run this first when anything looks
  wrong, or right after `./setup.sh` to confirm install succeeded.
- **`sandbox check <PATH>`** — dry-run of the pre-session workspace
  scan. Reports which files in the directory would be masked
  (`.env`, `.npmrc`, `kubeconfig`, `*.pem`, …) before you actually
  launch a Tier 2/3 session against it. Useful for catching credentials
  in a repo you've never sandboxed before.
- **`sandbox flows <SESSION_ID>`** — dumps the Hubble network flow
  records captured for that session (`~/.sandbox/logs/<id>/flows.json`,
  or live from Hubble if the pod is still running). Use this when a
  network request from inside the pod is silently failing — flow records
  show whether the packet was allowed, dropped by policy, or never sent.

## Session Naming

Sessions are automatically named for easy identification:

- **Tier 1**: `<agent>` — e.g. `claude`
- **Tier 2/3, single repo**: `<repo-basename>/<agent>` — e.g. `my-project/claude`
- **Tier 2/3, multiple repos**: `multi/<agent>` — e.g. `multi/claude`

The name is used as the pod name prefix, making `kubectl get pods` output
readable. Override with `--name <label>` to set a custom name. The name
appears in the session banner at launch and in `sandbox list`.

## Session ID Format

`ses-<YYYYMMDD>-<HHMMSS>-<4hex>` — e.g. `ses-20260401-143022-a7b3`

## Tier 3 Infra Credentials

Tier 3 sessions need at least one credential slot — the two are orthogonal
and can be combined:

- **`--infra-token <PATH>`** — flat file containing a single bearer-style
  token. The contents are stored in a per-session K8s Secret and injected
  into the pod as `$INFRA_TOKEN`. Use for Vault, custom internal APIs, or
  any service that takes one opaque secret.
- **`--infra-kubeconfig <PATH>`** — kubeconfig the agent should use to talk
  to a Kubernetes cluster. The file is minified to a **single context**
  (`--infra-kube-context <NAME>`, defaulting to the kubeconfig's
  `current-context`) and flattened so any externally-referenced CA/cert
  paths are inlined. The result is stored in a per-session K8s Secret and
  mounted read-only at `/home/agent/.kube/config`; `$KUBECONFIG` is set
  inside the pod. The API server's hostname and port (extracted from
  `clusters[].cluster.server`) are auto-added to the egress allowlist, so
  you don't also need `--infra-endpoint` for the cluster itself.

Example:

```bash
# Pass a kubeconfig generated by your auth system (e.g. tsh kube login,
# aws eks update-kubeconfig, gcloud container clusters get-credentials).
# The minify step ensures only the dev context is shipped to the pod,
# even if ~/.kube/config has many clusters.
sandbox run --agent claude --tier 3 --repo ~/repos/infra \
  --infra-kubeconfig ~/.kube/config --infra-kube-context dev
```

The minified kubeconfig only exists in a 0600 temp file long enough to be
loaded into the Secret, after which the temp file is deleted. The Secret
is deleted on session teardown.

**Exec credential plugins are not supported.** If the chosen context auths
via an `exec:` block (e.g. `tsh`, `aws eks get-token`,
`gke-gcloud-auth-plugin`, `kubelogin`), kubectl inside the pod will load
the kubeconfig but every API call will fail because the plugin binary
isn't in the sandbox image — and even if it were, its host-side state
(`~/.tsh/`, `~/.aws/`, etc.) is intentionally not mounted. `sandbox run`
detects this and refuses to launch unless you confirm at the prompt,
or pass `--allow-exec-plugin` for scripted use.

You need a kubeconfig that uses static credentials (`token:`,
`client-certificate-data:`, `client-key-data:`). Generation is
provider-specific; example scripts live in `examples/`:

- `examples/teleport/bake-kubeconfig.sh` — Teleport (`tsh kube credentials`
  → short-lived static certs, Teleport proxy URL preserved). The file's
  header also points to the equivalent recipe in the AWS / GCP / Azure
  ecosystems for operators who aren't on Teleport.

For everything else, the provider-agnostic recipe is a ServiceAccount
token. Run this once on the target cluster (using your normal
operator-credentialed kubectl), then mount the resulting file:

```bash
# On the target dev cluster (as a human with kubectl access):
kubectl create sa sandbox-agent -n default
kubectl create clusterrolebinding sandbox-agent-edit \
  --clusterrole=edit --serviceaccount=default:sandbox-agent

# Mint a short-lived token (default 1h; --duration=8h or 24h as needed):
TOKEN=$(kubectl create token sandbox-agent --duration=8h)
APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
CA_DATA=$(kubectl config view --minify --raw \
            -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')

# Write a static kubeconfig the sandbox can mount.
cat > ~/.kube/sandbox-dev.yaml <<EOF
apiVersion: v1
kind: Config
clusters:
- name: dev
  cluster:
    server: ${APISERVER}
    certificate-authority-data: ${CA_DATA}
users:
- name: sandbox-agent
  user:
    token: ${TOKEN}
contexts:
- name: dev
  context: { cluster: dev, user: sandbox-agent }
current-context: dev
EOF
chmod 0600 ~/.kube/sandbox-dev.yaml

# Now launch the sandbox.
sandbox run --agent claude --tier 3 --repo ~/repos/infra \
  --infra-kubeconfig ~/.kube/sandbox-dev.yaml
```

Adjust `--clusterrole=edit` to the lowest role the agent actually
needs — `view`, a namespace-scoped Role, or a custom Role with only
the verbs/resources required. `cluster-admin` is never appropriate for
an agent session — see PRINCIPLES.md "Credential isolation".

Credential lifetime is the operator's responsibility — if the kubeconfig
expires mid-session, kubectl starts failing and you should re-run
`sandbox run` with a freshly issued one.

## Resuming Sessions

By default, disconnecting from a session (Ctrl-D, `exit`, or losing the
terminal) tears the pod down to free cluster resources. Conversation
history is preserved on the host at `~/.sandbox/agent-home/<agent>/`
and survives pod deletion, so a fresh `sandbox run` followed by the
agent's own `/resume` command (Claude Code, Codex, OpenCode) restores
prior conversations.

To keep the pod alive across disconnects — e.g. while a long-running
build is in flight — pass `--keep-alive` to `run` or `resume`. With
the pod still running, reconnect via `kubectl exec`-style attach:

```bash
sandbox run --agent claude --tier 2 --repo ~/repos/foo --keep-alive
sandbox resume <SESSION_ID> [--keep-alive]
```

Sessions use `restartPolicy: Always` — the pod's `sleep infinity`
container automatically restarts after a node reboot, so a kept-alive
session survives reboots too. (The agent itself is launched via
`kubectl exec`, not as PID 1; the container just waits.)

A systemd service (`sandbox-masquerade.service`) re-applies the pod
egress MASQUERADE iptables rule on every boot so network access is
restored alongside the pod. The rule is scoped to the pod CIDR
(default `100.64.0.0/10`) so pods can reach hosts on the host's own
network (including corporate `10.x.x.x` ranges). Use `--pod-cidr`
at setup time if your network overlaps with the default.

## Reaching Clusters Behind a Corporate VPN (Linux)

If `--infra-kubeconfig` points at a Kubernetes API server reachable only
through a host VPN tunnel (e.g. an internal `10.x.x.x` address routed
via `tun0`/`wg0`/`utun0`), Cilium needs to know about the VPN interface
so pod egress to VPN-routed subnets gets SNAT'd to the tunnel's source
IP. Otherwise the packet leaves with the raw pod IP and the VPN gateway
drops it as unknown.

**Setup-time** (`setup.sh`): if a VPN interface is up when you run
setup, the installer detects it (via the `POINTOPOINT` link flag) and
applies three Cilium settings via `helm upgrade`:

- `devices='{<primary>,<vpn>}'` — list of interfaces Cilium manages.
- `extraConfig.direct-routing-device=<primary>` — required when
  `devices` has more than one entry.
- `extraConfig.egress-masquerade-interfaces=''` — default behavior;
  Cilium SNATs to the IP of whichever interface a packet exits through.

No VPN at setup time? The installer skips the change and Cilium uses
its single-NIC default.

**When the host network changes.** Two distinct kinds of drift can
strand the cluster:

1. **Interface names change.** You move between wifi, wired ethernet,
   and a dock/USB adapter, or the VPN drops and reconnects — often
   across a reboot. Cilium's pinned `devices` /
   `direct-routing-device` list ends up pointing at an interface that
   is now down or has no IP. Cilium reads that list only at agent
   startup, so the stale pin survives until the DaemonSet restarts.
   Visible symptom: **new sandboxes stuck in `ContainerCreating`** with
   `cilium-cni` endpoint errors and `IPv4 direct routing device IP not
   found` in the Cilium agent log.

2. **Primary IPv4 changes but the interface name stays the same.** The
   canonical case on Windows: every reboot, the WSL2 `sandbox-vm`
   distro comes up with a fresh address from the Hyper-V virtual NAT,
   but `eth0` is still `eth0`. Also happens on Linux laptops with DHCP
   lease changes or SSID swaps. kubelet keeps the old node
   `InternalIP`, the k3s API-server serving cert SANs are stale, and
   Cilium's BPF masquerade source still points at the prior IP — fix
   requires a `systemctl restart k3s` plus a Cilium DaemonSet restart.

You normally don't need to do anything about either: **`sandbox run`
checks both on every launch** and reconciles whichever has drifted. An
IP change triggers a heavier restart (k3s + Cilium + CoreDNS bounce,
~1-2 min); a name-only change is the lighter Cilium-only restart. Any
sandboxes already running may see a brief network blip. When nothing
has changed the checks are silent no-ops.

To re-apply without starting a sandbox — e.g. right after reconnecting
a VPN, or after a WSL2 distro restart, so already-running sandboxes
pick up the new routing — run it explicitly:

```bash
sandbox configure-network
```

That re-detects the current primary IPv4 and the primary + VPN
interface names, reconciles k3s and Cilium to match, and restarts
whichever components need it. It is idempotent — it does nothing if
nothing has drifted. The VPN-down case is handled symmetrically: if a
VPN was configured earlier and is now gone, the stale multi-device
list is reset to a single-NIC pin so the dead `tun0`/`wg0` entry can't
break endpoint creation. Both the explicit command and the automatic
check on `run` are skipped on non-Linux hosts.

**macOS / Lima**: not supported. The cluster runs inside the Lima VM,
which doesn't see the macOS host's `utun*` interfaces — VPN-routed
clusters from macOS would need a different topology (e.g. running the
VPN inside the Lima VM, or an egress proxy on the host).

## Corporate TLS-intercept proxies (Zscaler, Netskope, etc.)

If your laptop egresses through a TLS-intercepting proxy — Zscaler is
the common case, also Netskope, Forcepoint, Cisco Umbrella, Palo Alto
Prisma, internal MITM appliances — the sandbox image build and the
running agents will fail TLS validation against the re-signed certs
unless the proxy's root CA is trusted inside the sandbox image.

Symptom during the image build (most often hit on **first-time
`./setup.sh`**):

```
curl: (60) SSL certificate problem: unable to get local issuer certificate
```

Symptom at runtime: `claude` / `codex` / `opencode` failing to
authenticate, or `npm install` / `pip install` / `git clone` inside a
sandbox failing to reach its registry.

`./setup.sh` runs a TLS probe before the image build and aborts early
with a pointer here if it sees interception, so you don't lose a build
to it.

### Fix

Drop the proxy's root CA into `config/extra-ca-certs/` as a PEM `.crt`
file, then run (or re-run) setup:

```bash
./setup.sh             # first-time install
sandbox rebuild        # already installed, refreshing the images
```

`Dockerfile.base` copies anything in `config/extra-ca-certs/` into the
image's trust store via `update-ca-certificates`. Because all the agent
images (`:claude`, `:codex`, `:opencode`, `:shell`, `:*-infra`) derive
from `:base`, the same trust applies inside every running pod — one
fix, build-time and runtime.

### Getting the cert

The repo ships a helper that auto-extracts the cert from the host. It
runs straight out of the checkout (no PATH setup needed) so you can use
it during a first-time install before the `sandbox` CLI is on PATH:

```bash
./bin/sandbox setup-proxy-cert        # first time, before setup.sh
sandbox setup-proxy-cert              # already installed
```

It writes `config/extra-ca-certs/proxy-ca.crt` and tells you what to
do next. Behavior by platform:

- **Linux**: scans `/usr/local/share/ca-certificates/` and the system
  bundle for certs whose Subject matches known proxy-vendor names.
- **macOS**: queries the System keychain via the `security` command.
- **WSL2**: tries the Linux distro store first; if empty, falls back to
  the Windows `LocalMachine\Root` store via `powershell.exe` (which is
  always on PATH inside WSL). This handles the common case where the
  corporate root was installed only on Windows, not in the distro.

Useful flags (see `./bin/sandbox setup-proxy-cert --help`):

- `--vendor <substring>` — Subject filter when your org's CA doesn't
  match the built-in vendor list (Zscaler, Netskope, Forcepoint, Cisco
  Umbrella, Palo Alto/Prisma, Symantec/Blue Coat, iboss, Menlo).
- `--from-wire <host[:port]>` — last-resort extraction by opening a
  TLS connection to a known-public host (e.g. `deb.nodesource.com`)
  and capturing whatever proxy chain the network actually presents.
  Useful when nothing matches in the trust store.
- `--list` — print what was found without writing the file.

### Doing it by hand

If `setup-proxy-cert` doesn't fit (e.g. you already know the cert
location), the equivalent one-liners are:

```bash
# Linux — IT often pre-installs corporate roots here:
cp /usr/local/share/ca-certificates/Zscaler*.crt config/extra-ca-certs/

# macOS — System keychain via the Security framework CLI:
security find-certificate -a -c Zscaler -p /Library/Keychains/System.keychain \
  > config/extra-ca-certs/zscaler.crt
```

```powershell
# Windows — run in PowerShell BEFORE setup.ps1, since WSL doesn't inherit
# the Windows trust store:
Get-ChildItem Cert:\LocalMachine\Root |
  Where-Object { $_.Subject -like '*Zscaler*' } |
  ForEach-Object {
    $b64 = [Convert]::ToBase64String($_.RawData, 'InsertLineBreaks')
    "-----BEGIN CERTIFICATE-----`n$b64`n-----END CERTIFICATE-----"
  } | Out-File -Encoding ascii config\extra-ca-certs\zscaler.crt
```

The certs themselves are gitignored — your org's MITM root is unique to
your environment and shouldn't be committed.

## Audit Logs

All sessions are logged to `~/.sandbox/logs/<SESSION_ID>/`:

- `session.json` — metadata, domains, timestamps
- `transcript/` — agent conversation transcript (commands run, tool calls, outcomes)
- `files.log` — workspace file changes (Tier 2/3)
- `flows.json` — Hubble network flows

Retention: 90 days (Tier 1/2), 180 days (Tier 3).

## Security Model

- **Kernel isolation**: gVisor (runsc) for all pods
- **Network**: Cilium with `policyEnforcementMode: always`;
  per-session CiliumNetworkPolicy
- **Filesystem**: `.env`, `.npmrc`, `clouds.yaml`, and any `kubeconfig`/`.kube/`
  in the workspace are masked with emptyDir overlays. The only kubeconfig that
  ever enters the pod is one explicitly passed via `--infra-kubeconfig`, which
  is minified to a single context, mounted as a K8s Secret at
  `/home/agent/.kube/config`, and deleted on teardown.
- **Credentials**: claude/codex use OAuth (no API key injection);
  opencode key via K8s Secret; tier 3 infra creds via per-session Secrets
  (`--infra-token` → `$INFRA_TOKEN`; `--infra-kubeconfig` → mounted file)
- **Pod security**: non-root UID 1000, all capabilities dropped,
  no privilege escalation
- **Service account**: `automountServiceAccountToken: false`,
  no RBAC bindings

## Troubleshooting

Diagnose with `sandbox status` first — it surfaces most install-level
issues. For runtime failures, the patterns below cover the common
cases. See "Diagnostic subcommands" above for the full toolkit.

**Agent CLI can't reach `api.anthropic.com` / `api.openai.com`**
(`ECONNREFUSED` or `ETIMEDOUT` shortly after the agent banner appears).
First time you ran the agent? Step through OAuth — the agent prints a
URL; open it in a browser, log in, paste the code back. Already
OAuth'd? Check the cluster is healthy:

```bash
kubectl --kubeconfig ~/.sandbox/kubeconfig -n kube-system \
  get pods -l k8s-app=cilium     # all Running, 1/1 Ready?
sandbox status
```

If you switched networks or reconnected a VPN while a sandbox was
already running, that pod's networking can go stale — `sandbox run`
re-checks interfaces for *new* sessions, but a live pod won't pick up
the change. Run `sandbox configure-network` to re-apply and restart
Cilium.

**`kubectl` inside the pod times out reaching the API server.** Almost
always a route or DNS problem, not auth. From the **host**:
`getent hosts <api-server-host>` must return an IP, and
`ip route get <that-ip>` must show a real interface. If the IP routes
via your VPN's `tun0`/`wg0`, run `sandbox configure-network` so the
pod's egress packets get SNAT'd to the VPN interface IP. See
"Reaching Clusters Behind a Corporate VPN" for the full story.

**`kubectl` inside the pod fails with `ECONNREFUSED` or
`exec: ... no such file or directory`.** Your kubeconfig has an
`exec:` credential plugin (tsh / aws / gcloud / kubelogin) that the
sandbox image doesn't carry. Bake static credentials before mounting
— see the ServiceAccount-token recipe in "Tier 3 Infra Credentials"
or `examples/teleport/bake-kubeconfig.sh` for Teleport.

**Pod stuck in `Pending` after `sandbox run`.** Usually one of:

- *Image not present in k3s containerd.* `kubectl --kubeconfig
  ~/.sandbox/kubeconfig -n sandbox describe pod <pod-name>` will say
  "ErrImageNeverPull". Fix with `sandbox rebuild --agent <name>`
  (and `--tier3` if you were launching Tier 3).
- *gVisor RuntimeClass missing.* `sandbox status` will say so; re-run
  `./setup.sh`.
- *Out of cluster resources.* Single-node k3s is small; check
  `kubectl describe pod` for Insufficient CPU/memory and stop other
  sessions with `sandbox stop`.

**New sandboxes stuck in `ContainerCreating` after a reboot or network
change.** `kubectl --kubeconfig ~/.sandbox/kubeconfig -n sandbox
describe pod <pod-name>` shows `failed to setup network ... plugin
type="cilium-cni"` errors (`429`, `timeout exceeded`, or `EOF`), and
`kubectl -n kube-system logs -l k8s-app=cilium` repeats `IPv4 direct
routing device IP not found`. Cilium's pinned device list points at an
interface that is now down — typically a wifi/ethernet/dock switch or
an unplugged USB adapter. `sandbox run` auto-corrects this on its next
launch; to fix it immediately run `sandbox configure-network`. See
"Reaching Clusters Behind a Corporate VPN" for the full story.

**`Cannot reach Kubernetes cluster` from any sandbox command.** k3s
isn't running. `sudo systemctl status k3s` then `sudo systemctl start
k3s`; if it won't start, `sudo journalctl -u k3s --no-pager -n 50`.

**`Tier 3 requires at least one of --infra-token or --infra-kubeconfig`.**
You asked for `--tier 3` but didn't pass a credential. Either pass
one of the flags or drop to `--tier 2` if you only need package
registry access.

**`kubeconfig uses exec credential plugin '<binary>'`** at launch.
The detector saw an `exec:` block in your kubeconfig. Answer `n` and
bake static credentials (see "Tier 3 Infra Credentials"). Answer `y`
only if you also passed `--infra-token` and the kubeconfig is a
non-essential fallback — kubectl calls will fail.

**Hostname for the API server doesn't resolve inside the pod.** The
sandbox auto-pins a `hostAlias` for the API server hostname using
the host's resolver, so this should be rare. If it still fails, your
hostname only resolves via a VPN-side DNS that the host's
`/etc/resolv.conf` doesn't see either — fix `getent hosts <name>` on
the host first, then re-run `sandbox run`.

If a session reaches the cluster but then gets unexpected `403 Forbidden`
from `kubectl`, that's RBAC on the target cluster — the
ServiceAccount your token came from doesn't have the verb/resource the
agent tried. Widen the role, or scope the agent's task narrower. See
the ServiceAccount-token recipe above.

## Platform Requirements

**Linux**: k3s, gVisor, Cilium, kubectl, helm, jq, xxd, sha256sum,
curl, git

**macOS**: Lima (`brew install lima`) — provisions an Ubuntu 24.04 VM
with identical stack

**Windows**: WSL2 (`wsl --install`) plus an installed Ubuntu-24.04 distro
(`wsl --install -d Ubuntu-24.04`) used as a one-time seed. See the
"Windows quick start" section below.

## Windows quick start

Windows is supported via a dedicated WSL2 distro named `sandbox-vm`,
which plays the same role Lima plays on macOS: it isolates the k3s,
Cilium, and gVisor stack from any other Linux distro you already use.

### PowerShell version

`setup.ps1` works with **Windows PowerShell 5.1** (the default shell
on every Windows install) as well as **PowerShell 7+** (`pwsh`).
PowerShell 7 is recommended -- it reads source files as UTF-8 by
default, so any non-ASCII slip in our scripts can't mis-decode under
the ANSI codepage and produce confusing parser errors. Install it
with:

```powershell
winget install Microsoft.PowerShell
```

### Prerequisites

```powershell
# 1. WSL2 itself (one-time, requires reboot on a fresh install).
wsl --install

# 2. A source Ubuntu-24.04 distro to clone from (one-time).
#    Walk through its first-launch UNIX username/password prompts.
#    setup.ps1 reads it once via 'wsl --export' and otherwise never
#    touches it -- you can remove or keep it independently.
wsl --install -d Ubuntu-24.04
```

> **Behind a corporate TLS-intercepting proxy (Zscaler, Netskope,
> etc.)?** WSL distros don't inherit the Windows trust store, so the
> in-distro image build inside `.\setup.ps1` will fail on HTTPS unless
> the proxy root is staged first. You have two options:
>
> 1. **Stage the cert from Windows ahead of time** — paste the
>    PowerShell snippet from "Corporate TLS-intercept proxies" below
>    into your current PowerShell session, then run `.\setup.ps1`.
> 2. **Let `.\setup.ps1` fail at the build step** — it aborts early
>    with a clear error pointing at the in-distro helper. By that
>    point the `sandbox-vm` distro exists, so you can extract from
>    inside it (with automatic Windows-store fallback) and re-run:
>
>    ```powershell
>    wsl -d sandbox-vm --cd "$PWD" -- ./bin/sandbox setup-proxy-cert
>    .\setup.ps1
>    ```
>
> See "Corporate TLS-intercept proxies" below for details.

> **WSL2 requires an explicit DNS resolver (`-Dns`).** WSL hands the
> distro a tunnel sentinel (`10.255.255.254`) for DNS that only answers
> in the host's network namespace. CoreDNS runs inside a pod namespace,
> where that address is a black hole — so without `-Dns`, every in-pod
> lookup times out and agents fail to reach their APIs. `setup.ps1`
> stops with a clear error until you name a resolver pods can actually
> reach. Pass a public resolver, or your organization's internal DNS IP
> if you need Tier 3 pods to resolve internal names. See "Windows/WSL2
> DNS" below.

Provision and run:

```powershell
# 3. Run the Windows setup script from the agent-sandbox checkout.
#    Forwards the same flags as ./setup.sh on Linux/macOS.
#    -Dns is required on WSL2 (see the note above).
.\setup.ps1 -Dns 1.1.1.1,8.8.8.8
.\setup.ps1 -Dns 1.1.1.1,8.8.8.8 -PodCidr 172.16.128.0/17
.\setup.ps1 -Dns 1.1.1.1,8.8.8.8 -ApiserverPort 7443

# 4. Put the CLI on PATH for this session (and add to your $PROFILE
#    to make it permanent).
$env:Path = "$PWD\bin;$env:Path"

# 5. Smoke-test.
sandbox status

# 6. Launch a Tier 1 session.
sandbox run --agent claude --tier 1
```

**If `setup.ps1` fails partway through**, the work it has already done
is recoverable -- the PowerShell wrapper is a convenience, not
load-bearing. Its job is (a) clone Ubuntu-24.04 into a new `sandbox-vm`
distro, (b) enable systemd, (c) run `setup.sh` inside it.

If `setup.ps1` failed **after** the clone step (i.e. `wsl --list`
already shows `sandbox-vm`), finish the bash half by hand from any
shell:

```powershell
wsl -d sandbox-vm --cd "$PWD" -- ./setup.sh
```

If it failed **before** the clone step, the dedicated distro doesn't
exist yet -- re-run `setup.ps1` once the PowerShell-side issue is
fixed, or as a last resort run `setup.sh` directly inside your seed
`Ubuntu-24.04` distro (no dedicated-distro isolation, but everything
else works the same).

**Repo placement for Tier 2/3.** Clone repos *inside* the `sandbox-vm`
distro, not on a Windows drive. `/mnt/c/...` paths cross the NTFS<->WSL
filesystem boundary on every syscall — git status and builds run 10-20x
slower than on native ext4 inside the distro. The CLI refuses Windows
paths with a clear error directing you to clone inside the distro:

```powershell
wsl -d sandbox-vm -- bash -c 'git clone https://example/your.git ~/repos/your'
sandbox run --agent claude --tier 2 --repo ~/repos/your
```

To shell into the sandbox distro directly (debugging, manual `kubectl`,
etc.), use `wsl -d sandbox-vm`.

**Caveat:** all WSL2 distros on a Windows host share one kernel and one
lightweight utility VM, so the `sandbox-vm` isolation is at the userland/
rootfs layer — not a separate hypervisor VM the way Lima provides on
macOS. The security boundary that matters for sandboxed agents is still
gVisor at the container layer; the dedicated distro exists to keep
sandbox state from colliding with your everyday Linux work.

### Windows/WSL2 DNS

WSL2 hands the distro a DNS-tunnel sentinel (`10.255.255.254`) in
`/etc/resolv.conf` that WSL intercepts in the *host* network namespace.
That works fine for commands you run in the distro directly, but CoreDNS
runs inside a pod network namespace where the sentinel is unreachable —
so every cluster DNS lookup times out, and agents come up only to fail
reaching their APIs (`could not resolve host`, `FailedToOpenSocket`).
Bare Linux and macOS/Lima don't hit this; they get a pod-reachable
resolver from the host automatically.

The fix is to tell CoreDNS which resolver to use, with `-Dns`
(`--dns` for `setup.sh`). It's **required** on WSL2 — `setup.ps1` errors
out until you set it — and accepts a comma- or space-separated list:

```powershell
# A public resolver is the simplest choice for Tier 1/2 (the agent APIs
# are all public). Confirm it's reachable from the distro first:
wsl -d sandbox-vm -- dig @1.1.1.1 +short api.anthropic.com

.\setup.ps1 -Dns 1.1.1.1,8.8.8.8
```

If you need **Tier 3** pods to resolve *internal* names, a public
resolver won't see them — point `-Dns` at an internal DNS server your
pods can actually reach instead (the corporate resolver behind WSL's
tunnel sentinel is not one of them):

```powershell
.\setup.ps1 -Dns 10.20.30.40
```

The same flag works from bash as an opt-in override on any Linux host —
handy if a bare-Linux box behind its own split-DNS needs CoreDNS pinned
to a specific upstream:

```bash
./setup.sh --dns 10.20.30.40
```

`-Dns` is wired into the k3s install, so changing it means re-running
setup (it's not a live restart). On macOS it's ignored with a warning —
Lima handles DNS on its own.

## Rebuilding Images

`./setup.sh` builds and imports every image for you. You only need
this section when an agent CLI ships a new release (Claude Code, for
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

## Running Tests

```bash
# Cross-platform / unit tests (no cluster needed)
bash tests/test-audit.sh
bash tests/test-blocked-domains.sh
bash tests/test-cross-platform.sh

# Cluster tests (cluster required)
bash tests/test-gvisor.sh
bash tests/test-default-deny.sh
bash tests/test-claude-tier1.sh
bash tests/test-codex-tier1.sh
bash tests/test-opencode-tier1.sh
bash tests/test-tier2-network.sh
bash tests/test-tier3-network.sh
bash tests/test-filesystem.sh
bash tests/test-credentials-claude.sh
bash tests/test-credentials-opencode.sh
bash tests/test-serviceaccount.sh
```

## Uninstalling

```bash
./uninstall.sh           # Interactive — prompts before each destructive step
./uninstall.sh --yes     # Non-interactive (skip all prompts)
./uninstall.sh --keep-logs   # Remove everything except ~/.sandbox/logs/
```

| Option             | Effect                                          |
|--------------------|-------------------------------------------------|
| `--yes` / `-y`     | Skip all confirmation prompts                   |
| `--keep-logs`      | Preserve `~/.sandbox/logs/` (audit records)     |
| `--keep-images`    | Skip sandbox container image removal            |
| `--keep-lima`      | macOS: delete the Lima VM but leave Lima        |
| `--keep-kubetools` | Leave Helm (and kubectl on Linux) in place      |

The uninstaller removes, in order:

1. Active pods, CiliumNetworkPolicies, and secrets from the cluster
2. The `sandbox` namespace, ServiceAccount, and `gvisor` RuntimeClass
3. Container images (`sandbox:*`) from k3s containerd / Docker or Podman
4. **Linux**: k3s (and Cilium), gVisor binaries, runsc config,
   `sandbox-masquerade.service`
5. **macOS**: Lima VM `sandbox-vm` (and optionally Lima itself)
6. `~/.sandbox/` — config, kubeconfig, and session logs
7. Helm from `/usr/local/bin/helm` if setup.sh installed it (optional)

The uninstaller does **not** remove this repository directory,
Homebrew, or other Lima VMs.

## Architecture Notes

Background on the trickier choices in the install. Operators don't
need to read this to use the sandbox; it's here so that whoever has
to debug an unfamiliar failure mode has the rationale on hand.

### Cluster CIDRs

The setup script passes `--cluster-cidr` and `--service-cidr` to k3s
explicitly:

- **Pod CIDR** (default `100.64.0.0/10`): allocated by Cilium IPAM in
  cluster-pool mode and used by the egress MASQUERADE rule. Also passed
  as k3s `--cluster-cidr` so the Node's `.spec.podCIDR` matches the
  range Cilium actually allocates from — otherwise `kubectl get nodes`
  reports k3s' default `10.42.0.0/24` and operators waste triage time
  chasing a phantom mismatch.
- **Service CIDR** (default `10.43.0.0/16`, k3s' default): used for
  Kubernetes Service VIPs. Override with `--service-cidr` if your host
  network overlaps.

CIDRs are baked in at install time. To change them on an existing
cluster, run `./uninstall.sh` and re-run `./setup.sh` with the new
flags.

### API server port

The Kubernetes API server listens on `6443` by default — the k3s and
upstream-Kubernetes default. That default collides with anything else
on the host that expects a Kubernetes endpoint on `6443`: a common
case is local Ansible or `kubectl` tooling pointed at a cluster on
OpenStack, which silently talks to the sandbox cluster instead once
the sandbox is up.

`--apiserver-port` moves the sandbox cluster off `6443`:

```bash
./setup.sh --apiserver-port 7443
```

Unlike the CIDRs, the port can be changed on an existing cluster —
just re-run setup with the new value:

- **Linux:** `./setup.sh --apiserver-port <PORT>` is idempotent. If
  k3s is already installed on a different port it rewrites the k3s
  config (`/etc/rancher/k3s/config.yaml`, the `https-listen-port`
  key), restarts k3s, refreshes `~/.sandbox/kubeconfig`, and
  `helm upgrade`s Cilium's `k8sServicePort` to match. Running pods
  survive the restart.
- **macOS:** the port is baked into the Lima VM's host port forward
  at VM-creation time. To change it, recreate the VM:
  `limactl delete sandbox-vm` then `./setup.sh --apiserver-port <PORT>`.

The chosen port is recorded in `~/.sandbox/kubeconfig` (the `server:`
URL), so every `sandbox` command picks it up automatically.

### Resource quota sizing

The namespace `ResourceQuota` is **sized to the node at setup time**,
not hardcoded. `lib/resources.sh` reads the node's allocatable
CPU/memory, subtracts a host reservation (default `2` CPU / `6Gi` for
the OS, the k3s/Cilium stack, and your IDE/browser), and derives how
many concurrent sandbox pods fit. `setup` then generates and applies
the quota — re-run `sandbox setup` after a hardware change to resize.

Memory and CPU are treated differently, on purpose:

- **Memory is not overcommitted.** The quota's `limits.memory` equals
  the per-pod memory limit times the pod ceiling, so even if every
  sandbox bursts to its full limit at once it still fits in RAM — no
  host OOM. This is what gates concurrency.
- **CPU is overcommitted.** CPU is compressible: an over-subscribed
  core just throttles, it never OOM-kills. Per-pod CPU limits are
  allowed to sum past the core count, so CPU is not the limiter.

With the defaults (per-pod `2Gi` request / `6Gi` limit), the ceiling
is `floor((allocatable_RAM − 6Gi) ÷ 6Gi)` — e.g. a 30Gi laptop fits
4 concurrent sandboxes. To retune, edit the constants at the top of
`lib/resources.sh` (`POD_MEM_LIMIT_GI`, `HOST_RESERVE_MEM_GI`, …) and
re-run `sandbox setup`: a smaller per-pod memory limit trades single-
session burst headroom for more concurrent sessions.

### gVisor + Cilium ClusterIP routing

Cilium is installed with `socketLB.hostNamespaceOnly=true`. This is
**required** for gVisor pods to reach ClusterIP services (including
CoreDNS).

Cilium's default socket-LB rewrites Service ClusterIPs at the host
kernel's cgroup `connect()` hook. gVisor pods never reach that hook
because their `connect()` syscall is handled by gVisor's userspace
netstack, not the host kernel — so without this flag, ClusterIP→PodIP
translation never happens for sandbox pods. Symptoms include `nslookup`
hangs, TLS handshake timeouts to external services (because DNS to the
in-cluster CoreDNS service times out), and silent packet loss to
`10.43.0.10:53`. The pattern is especially severe on hosts with an
active VPN (`tun0` etc.), where the untranslated ClusterIP packet falls
through to the VPN as the default route and is dropped at the corporate
edge.

With `socketLB.hostNamespaceOnly=true`, Cilium installs TC-based LB
programs on pod veths instead. These run on the host side of the veth
and DNAT the packet in transit — after gVisor builds it, before host
routing — so gVisor pods can reach Service VIPs normally.

To apply this on an existing cluster without a full reinstall:

```bash
helm upgrade cilium cilium/cilium \
  --kubeconfig ~/.sandbox/kubeconfig \
  --namespace kube-system \
  --reuse-values \
  --set socketLB.hostNamespaceOnly=true
kubectl --kubeconfig ~/.sandbox/kubeconfig -n kube-system rollout restart ds/cilium
```

## Principles and threat model

**PRINCIPLES.md** covers the design intent behind this tool: what the
sandbox defends against, what it explicitly doesn't, the tier model's
reasoning, the credential-isolation rules, and the small set of things
that are off-limits regardless of how you configure the sandbox. Read
it before you operate this for anyone other than yourself; skim the
"Accountability" and "Never permitted regardless of tier" sections
even if it's just you.

It is intentionally not an organizational policy — it captures the
assumptions the tool is built on so the policy you write around it
(rotation cadence, approval flows, audit retention, incident response,
onboarding) can reference them.

## How this compares (Apple Containers and friends)

People sometimes look at this project next to a container runtime and
ask "isn't that the same thing?" — most recently Apple's
[`container`](https://github.com/apple/container). It's a fair question,
and the answer is no, but for a reason worth spelling out: those tools
are a *box*, and this is the *box plus a leash, a locked filing cabinet,
and a guarded exit*. A stronger box doesn't replace the leash.

The axis that matters is **containment boundary** (how hard it is to
break *out* of the sandbox) versus **policy layer** (what the thing
inside is allowed to *do* while it stays in). A container runtime gives
you the first. This sandbox is built on a boundary and then spends most
of its code on the second — egress allowlisting, credential isolation,
filesystem masking, the tier model. For an *untrusted agent*, the policy
layer is the half that does the heavy lifting: the everyday risk isn't
the agent escaping its sandbox, it's the agent inside the sandbox
exfiltrating data, phoning home, or misusing a credential — exactly what
a runtime alone does nothing about.

| Tool | What it is | Containment boundary | Default-deny egress | Credential isolation | Overlaps this tool? |
|------|------------|----------------------|---------------------|----------------------|----------------------|
| **Agent Sandbox** (this) | Policy layer over a gVisor pod | gVisor (syscall interception) | Yes — per-tier allowlist | Yes — OAuth / per-session Secrets | — |
| **Apple `container`** | macOS container runtime | Hardware VM, one per container (*stronger* than gVisor) | No | No | No — complementary |
| **Docker / Podman** | Container runtimes | Shared-kernel namespaces (weaker) | No | No | No — we *use* them to build images |
| **Dev Containers** (VS Code) | Reproducible dev environment | Same as Docker | No | No — assumes trusted code | No — different goal |
| **Hosted agent sandboxes** (E2B, Daytona, Codex cloud, etc.) | Cloud code-execution for agents | Provider microVMs (strong) | Provider-controlled | On the provider's infra | Closest in *intent*, different in *place* |

A few notes on the rows worth a sentence each:

- **Apple Containers** is genuinely interesting here, and not as a
  competitor. Its per-container hardware VM is a *stronger* containment
  boundary than gVisor's syscall interception — philosophically more
  aligned with "agents are untrusted," not less. But it's a runtime, not
  a policy engine: out of the box a `container run` has open egress,
  whatever credentials you hand it, and whatever mounts you configure.
  Swapping this tool for raw Apple Containers upgrades the boundary that
  matters less for agents and discards the policy layer that matters
  more. The compelling version isn't "instead of" — it's "underneath":
  Apple's VM as the box, this tool's controls around it. That would be an
  isolation-backend change, not a drop-in, and it's macOS-on-Apple-Silicon
  only (macOS 26+), so it's a someday, not a today.

- **Docker / Podman** aren't rivals at all — the sandbox shells out to
  whichever you have to *build* its images (see "Rebuilding Images"). The
  confusion is only ever "can't I just `docker run` the agent?" You can,
  and you'd be running it in a box with the door open.

- **Hosted agent sandboxes** are the closest in intent — they also exist
  to run agents you don't fully trust. The difference is where the agent
  ends up and what it can reach: those run on the provider's
  infrastructure and are pointed at the provider's network, while this
  runs on your own host or cluster and is meant to let an agent reach
  *your* internal systems (Tier 3 dev clusters, infra endpoints) under a
  policy you control. Different tool for "ship code to a clean cloud
  box" versus "let an agent touch our stuff, carefully."

If your takeaway is "I like the stronger boundary Apple Containers
offers" — good instinct, and noted. The point of this section is just
that the boundary is one ingredient, and on its own it leaves the egress
and credential controls described in **PRINCIPLES.md** on the table.
