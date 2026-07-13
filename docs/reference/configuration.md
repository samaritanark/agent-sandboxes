# Configuration

[← Documentation](../index.md)

The CLI reads defaults from three `config.yaml` sources and a handful of
environment variables. This page is a key-by-key reference; the how-to guides
linked from each section show them in context.

## config.yaml locations

| Location | Scope | Notes |
|----------|-------|-------|
| `~/.sandbox/config.yaml` | per-user | your personal defaults |
| `<repo>/.sandbox/config.yaml` | per-repo | checked in alongside code; every session start prints a banner listing what it contributed |
| `<overlay>/…` | team overlay | shipped by a team; see [profiles & overlays](../how-to/profiles-and-overlays.md) |

## Keys

```yaml
# ~/.sandbox/config.yaml

overlay: /path/to/overlay-myteam     # team overlay dir (or SANDBOX_OVERLAY env)

extra_allowed_domains:               # merged with the tier allowlist on every run
  - git.example.com                  #   (also settable per-repo and via env)
  - artifactory.example.com

blocked_domains:                     # deny-only, additive; a block always beats an allow
  - "*.prod.internal"
blocked_cidrs:
  - 10.0.0.0/8
```

Per-repo `<repo>/.sandbox/config.yaml` additionally holds:

```yaml
extra_allowed_domains:
  - go.private.example.com
masked_paths:                        # written by `sandbox mask add`; hidden from the agent
  - config/prod/secrets.yaml
leakscan_dep_exclusions: off         # scan gitignored dependency trees too (stricter)
```

The **team overlay** `config.yaml` additionally holds:

```yaml
leakscan_extra_dep_dirs:             # extra dependency-dir names the secret gate skips
  - .cache-npm                       #   when gitignored (OVERLAY-ONLY — see note)
  - my-vendored-libs
```

- `extra_allowed_domains` — see [Persistent extra domains](../how-to/persistent-domains.md).
- `blocked_domains` / `blocked_cidrs` — see [Never-allow block list](../how-to/persistent-domains.md#never-allow-a-personal-block-list). All three domain sources are still subject to the blocked-destinations check.
- `masked_paths` — see [Extending the mask](../explanation/security-model.md#extending-the-mask).
- `leakscan_dep_exclusions` / `leakscan_extra_dep_dirs` — control which gitignored dependency trees the secret gate skips; see [Dependency-tree exclusion](../explanation/security-model.md#dependency-tree-exclusion). `leakscan_extra_dep_dirs` is honored **only** in the overlay: adding a skip loosens the scan, so a repo or user cannot do it (only disable exclusions, which is stricter).
- The overlay may also ship a `.betterleaksignore` / `.gitleaksignore` **file** at its root (not a `config.yaml` key) — a baseline of betterleaks fingerprints the secret gate should accept. Like `leakscan_extra_dep_dirs` it is operator-only, since suppressing a finding loosens the scan; see [Owning betterleaks' allowlist inputs](../explanation/security-model.md#owning-betterleaks-allowlist-inputs).

## Environment variables

| Variable | Equivalent |
|----------|------------|
| `SANDBOX_EXTRA_ALLOWED_DOMAINS` | comma-separated `extra_allowed_domains` (convenient for CI / shell-rc) |
| `SANDBOX_OVERLAY` | `overlay:` |
| `OPENCODE_API_KEY` | required in host env for the opencode agent |
| `OPENCODE_BASE_URL` | opencode endpoint (or `--base-url`) |

## Profiles

A profile is a named YAML bundle (`tier`, and optionally `agent`,
`default_repo`, `extra_allowed_domains`, `secrets`, `mcps`, `services`). See
[Profiles and overlays](../how-to/profiles-and-overlays.md) for the full field
reference and `sandbox profile save`.
