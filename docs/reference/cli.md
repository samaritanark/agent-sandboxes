# CLI Reference

[← Documentation](../index.md)

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

## Diagnostic subcommands

- **`sandbox status`** — single-screen health check: cluster reachable,
  Cilium policy mode, gVisor RuntimeClass present, sandbox namespace
  exists, running session count. Run this first when anything looks
  wrong, or right after `./setup.sh` to confirm install succeeded.
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
