# Profiles and Overlays

[← Documentation](../index.md)

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
secrets: []                       # host-side secrets to inject (see Secret store)
mcps: []                          # MCP servers run alongside the session
services: []                      # non-MCP service deps (DB, broker, …)
```

`secrets`, `mcps`, and `services` are covered in [Secrets](secrets.md) and
[MCP & service dependencies](mcp-and-dependencies.md).

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

## Overlays

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
