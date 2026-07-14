# CLI Reference

[← Documentation](../index.md)

```text
sandbox run [OPTIONS]
  --agent <claude|codex|opencode|copilot|grok>    default: claude
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
  --i-accept-unmasked-secrets        launch despite secrets the mask won't
                                     hide (printed; the agent will see them)

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
sandbox mask add --repo <PATH> <RELPATH>...    # hide file(s) from the agent (per-repo)
sandbox mask list --repo <PATH>               # built-in + configured masked paths
sandbox exceptions add --repo <PATH> <RELPATH:RULE:LINE>... [--reason TEXT]
                     # record reviewed secret-gate false positive(s); honored
                     # only on a vetted repo. RELPATH:RULE:LINE is what the gate
                     # prints. Re-scans to resolve the value hash.
sandbox exceptions list --repo <PATH>         # recorded accepted_secrets fingerprints
sandbox vet --repo <PATH> [--message MSG] [--yes]   # sign an agent-vetted/<sha> tag
                     # --yes: acknowledge recorded secret exceptions non-interactively
sandbox vet --status --repo <PATH>            # print vetting state, sign nothing
sandbox cleanup [--older-than DAYS]            default: 90
sandbox check <WORKSPACE_PATH>
sandbox status
sandbox install [--pod-cidr CIDR] [--service-cidr CIDR] [--apiserver-port PORT] [--dns IPS]
sandbox setup   [...]                           # alias of `install` (compat)
sandbox uninstall [--yes] [--keep-logs] [--keep-images]
                  [--keep-lima] [--keep-kubetools]
sandbox upgrade [--app]                          # default: update the CLI itself
                [--to vX.Y.Z] [--remote NAME] [--rebuild]
sandbox upgrade --infra | --k3s | --cilium | --gvisor | --betterleaks | --all
                [--to-k3s VER] [--to-cilium VER] [--to-gvisor REL] [--to-betterleaks VER]
                [--force]
                [--dry-run] [--yes]              # shared by both phases
sandbox configure-network                       # Linux only; re-detect host
                                                # interfaces, re-apply to Cilium
                                                # (also auto-run by `sandbox run`)
sandbox rebuild [--agent NAME] [--tier3] [--no-cache]
                [--codex-version VER] [--opencode-version VER]
                [--copilot-version VER] [--grok-version VER]
sandbox version [--short | --json]              # reads the identity embedded at
                                                # release/install time; a fresh,
                                                # never-installed checkout: "dev"
```

## Versioning

`sandbox version` reports an identity that is **resolved once and embedded**, never
recomputed from git at runtime (so two clones of the same commit can't disagree
because one hasn't fetched tags):

- **Released tarball** — `task release` stamps the exact release version into a
  `.version` file in the artifact.
- **Source checkout** — `sandbox install` runs `scripts/stamp-version.sh`, which
  derives the version from git (`describe --tags --always --dirty`) and writes
  `.version` (gitignored). Re-run it any time with `task stamp` — e.g. after
  committing or switching branches.
- **Fresh checkout, never installed** — no `.version`, so it honestly reports
  `dev`.

Because the stamp is frozen at install time, `sandbox version` won't reflect
edits made afterward until you re-stamp (`task stamp`); use `git status` for the
live working-tree state.

## Diagnostic subcommands

- **`sandbox status`** — single-screen health check: cluster reachable,
  Cilium policy mode, gVisor RuntimeClass present, sandbox namespace
  exists, running session count. Also shows an **Infra versions** section —
  the k3s / Cilium / gVisor versions pinned in `setup/versions.sh` next to
  what is actually running, flagging drift. Run this first when anything looks
  wrong, or right after `sandbox install` to confirm install succeeded.
- **`sandbox check <PATH>`** — dry-run of the pre-session workspace
  scan. Reports which files in the directory would be masked
  (`.env`, `.npmrc`, `kubeconfig`, `*.pem`, …) and previews the
  betterleaks secret gate (which **unmasked** secrets would block a real
  `sandbox run`) before you actually launch a Tier 2/3 session against it.
  Useful for catching credentials in a repo you've never sandboxed before.
- **`sandbox flows <SESSION_ID>`** — dumps the Hubble network flow
  records captured for that session (`~/.sandbox/logs/<id>/flows.json`,
  or live from Hubble if the pod is still running). Use this when a
  network request from inside the pod is silently failing — flow records
  show whether the packet was allowed, dropped by policy, or never sent.

## Lifecycle subcommands

- **`sandbox install`** — installs and configures everything a host needs to
  run sessions: the k3s cluster, Cilium (CNI + network policy), the gVisor
  runtime, and the container images. Idempotent — safe to re-run to reconcile.
  Thin wrapper over `setup.sh`; `sandbox setup` is a retained alias, and running
  `./setup.sh` directly still works. Component versions come from
  `setup/versions.sh` (see [Upgrading infrastructure](../how-to/upgrading-infra.md)).
- **`sandbox uninstall`** — tears the cluster and host artifacts back down
  (mirror of install). `--yes` skips the prompt; `--keep-logs` / `--keep-images`
  / `--keep-lima` / `--keep-kubetools` preserve individual pieces. Wrapper over
  `uninstall.sh`.
- **`sandbox upgrade`** — moves your install forward. Two phases, one verb:
  - **App (default, `--app`)** — fast-forwards this CLI checkout to the latest
    release tag (or `--to vX.Y.Z`), only when it's a clean fast-forward, so
    local edits and commits are never discarded. `--remote` picks the git remote
    (default `origin`); `--rebuild` rebuilds agent images afterward. A released
    tarball (no `.git`) can't self-update — the command prints the download link.
    See [Updating the CLI](../how-to/updating-the-cli.md).
  - **Infra (`--infra`, or `--k3s` / `--cilium` / `--gvisor` / `--betterleaks`)**
    — moves the pinned host components to the versions in `setup/versions.sh`
    (which Renovate keeps current), or to an explicit `--to-*` target. The
    isolation stack (k3s/Cilium/gVisor) restarts k3s and can briefly disrupt the
    Cilium datapath, so it **refuses to run while sessions are active** unless
    `--force`; on macOS that stack runs inside the Lima VM and is not upgraded in
    place yet — the command prints the re-provisioning steps instead.
    `--betterleaks` is the exception: the secret scanner is a host binary, so it
    upgrades on any platform without the session guard. See
    [Upgrading infrastructure](../how-to/upgrading-infra.md).
  - **`--all`** — does the app first, then re-executes the updated CLI so the
    infra phase applies the newly pulled pins.

  `--dry-run` (show the plan, change nothing) and `-y`/`--yes` are shared.

## Session naming

Sessions are automatically named for easy identification:

- **Tier 1**: `<agent>` — e.g. `claude`
- **Tier 2/3, single repo**: `<repo-basename>/<agent>` — e.g. `my-project/claude`
- **Tier 2/3, multiple repos**: `multi/<agent>` — e.g. `multi/claude`

The name is used as the pod name prefix, making `kubectl get pods` output
readable. Override with `--name <label>` to set a custom name. The name
appears in the session banner at launch and in `sandbox list`.

## Session ID format

`ses-<YYYYMMDD>-<HHMMSS>-<4hex>` — e.g. `ses-20260401-143022-a7b3`
