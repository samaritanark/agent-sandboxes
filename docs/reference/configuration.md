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
accepted_secrets:                    # written by `sandbox exceptions add`; reviewed
  - "deploy/values.yaml:generic-api-key:155:3cd3c4be828647be"  # false positives, honored only when vetted
leakscan_dep_exclusions: off         # scan gitignored dependency trees too (stricter)
```

The **team overlay** `config.yaml` additionally holds:

```yaml
leakscan_extra_dep_dirs:             # extra dependency-dir names the secret gate skips
  - .cache-npm                       #   when gitignored (OVERLAY-ONLY — see note)
  - my-vendored-libs
trusted_inference_endpoints:         # internal model endpoints trusted with secrets
  - vllm.internal.example.org        #   (OVERLAY-ONLY — see note)
```

- `extra_allowed_domains` — see [Persistent extra domains](../how-to/persistent-domains.md).
- `blocked_domains` / `blocked_cidrs` — see [Never-allow block list](../how-to/persistent-domains.md#never-allow-a-personal-block-list). All three domain sources are still subject to the blocked-destinations check.
- `masked_paths` — see [Extending the mask](../explanation/security-model.md#extending-the-mask).
- `accepted_secrets` — reviewed secret-gate false positives, written by `sandbox exceptions add`. Each is a value-bound `relpath:rule:line:hash` fingerprint the gate honors **only when the repo is vetted** (the vetting signature over the tree is its authority); an unvetted repo's list is ignored. See [Accepting secret-gate false positives](../how-to/secret-exceptions.md).
- `leakscan_dep_exclusions` / `leakscan_extra_dep_dirs` — control which gitignored dependency trees the secret gate skips; see [Dependency-tree exclusion](../explanation/security-model.md#dependency-tree-exclusion). `leakscan_extra_dep_dirs` is honored **only** in the overlay: adding a skip loosens the scan, so a repo or user cannot do it (only disable exclusions, which is stricter).
- The overlay may also ship a `.betterleaksignore` / `.gitleaksignore` **file** at its root (not a `config.yaml` key) — a baseline of betterleaks fingerprints the secret gate should accept. Like `leakscan_extra_dep_dirs` it is operator-only, since suppressing a finding loosens the scan; see [Owning betterleaks' allowlist inputs](../explanation/security-model.md#owning-betterleaks-allowlist-inputs).
- `trusted_inference_endpoints` — exact bare hosts of internal model endpoints trusted to receive secret-bearing prompts. When a session's inference endpoint is on this list, a would-be-blocking secret finding is downgraded from a hard refusal to a single interactive confirmation (fails closed with no TTY). Overlay-only, no wildcards; today only the `opencode` agent (`OPENCODE_BASE_URL`) can match. See [Trusted internal model endpoints](../how-to/secret-exceptions.md#trusted-internal-model-endpoints-a-different-lever).

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
