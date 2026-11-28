# Configuration

[← Documentation](../index.md)

The CLI reads defaults from three `config.yaml` sources and a handful of
environment variables. This page is a key-by-key reference; the how-to guides
linked from each section show them in context.

v3 reads `~/.sandbox` in v2's formats: your `config.yaml`, profiles, overlays,
vetting files, and secrets carry over unchanged. Before each command the host
copies the settings the VM needs (`config.yaml`, `profiles/`, `vetting/`,
`extra-ca-certs/`, `egress-rules.yaml`, `agent-config/`) into the VM; secrets
never go there in bulk (see [Secrets](../how-to/secrets.md)).

## ~/.sandbox in v3

| Path | What it is |
|------|------------|
| `config.yaml`, `profiles/`, `overlays/`, `vetting/` | as in v2 |
| `extra-ca-certs/` | CAs added to every session's trust store (for example `proxy-ca.crt` from `sandbox setup-proxy-cert`) |
| `egress-rules.yaml` | your L7 rules (see [Egress rules](../how-to/egress-rules.md)) |
| `secrets/` | the secret store: one file per secret, mode 0600 |
| `secrets/.bindings/` | each secret's binding (hosts and injection, or readable) |
| `agent-config/<agent>/` | the agent settings `sandbox onboard` copied (`settings.json` and `CLAUDE.md` for Claude Code; `config.toml`, `AGENTS.md`, and the account's `identity.json` for Codex). No logins. |
| `vm/` | the VM's driver state, SSH keys, and pinned host key |
| `sync/` | the sync engine's state per repository |
| `quarantine/` | workspace changes the sync gate withheld (`sandbox sync review`) |
| `logs/` | session records pulled from the VM (see [Audit logs](audit-logs.md)), and `vm-shell.log` |
| `agent-home/` | v2 only. v3 does not use it; `sandbox migrate --remove-v2` archives it to `v2-archive/` |

The credential broker's key is kept in the macOS keychain (item
`agent-sandboxes broker key`), and on Linux in `~/.sandbox/broker.key`
(mode 0600).

## config.yaml locations

| Location | Scope | Notes |
|----------|-------|-------|
| `~/.sandbox/config.yaml` | per-user | your personal defaults |
| `<repo>/.sandbox/config.yaml` | per-repo | checked in alongside code; loosening keys (e.g. `extra_allowed_domains`) are **not** honored from here — the launch prints what it requested |
| `<overlay>/…` | team overlay | shipped by a team; see [profiles & overlays](../how-to/profiles-and-overlays.md) |

## Keys

```yaml
# ~/.sandbox/config.yaml

overlay: /path/to/overlay-myteam     # team overlay dir (or SANDBOX_OVERLAY env)

runtime: gvisor                      # kata (default) or gvisor; run --runtime overrides it.
                                     #   Read only from this file, never a repo's config.
                                     #   See how-to/runtimes.md

extra_allowed_domains:               # merged with the tier allowlist on every run
  - git.example.com                  #   (also settable via env or an overlay profile)
  - artifactory.example.com

blocked_domains:                     # deny-only, additive; a block always beats an allow
  - "*.prod.internal"
blocked_cidrs:
  - 10.0.0.0/8
```

Per-repo `<repo>/.sandbox/config.yaml` additionally holds:

```yaml
extra_allowed_domains:               # requested, but NOT honored from a repo config
  - go.private.example.com           #   (loosens egress; the launch only surfaces it —
                                     #    see persistent-domains.md). Grant it operator-side.
masked_paths:                        # written by `sandbox mask add`; hidden from the agent
  - config/prod/secrets.yaml
leakscan_dep_exclusions: off         # scan gitignored dependency trees too (stricter)
```

A repo's `extra_allowed_domains:` is **not** honored by default because a repo
tree is writable by the in-sandbox agent; a team that wants it honored opts in
once in the overlay with `honor_repo_allowed_domains: true` (overlay-only). Even
then only the repo's **vetted committed** list is honored — the domains in its
signed `HEAD`, while an `agent-vetted/<sha>` attestation verifies — so an agent
editing the working-tree config still cannot self-grant a host without a human
re-vetting. See [Persistent extra domains](../how-to/persistent-domains.md).

Reviewed secret-gate false positives are **not** in this file — they live in a
`.betterleaksignore` at the repo root (betterleaks' native format, so the same
file serves the team's CI/pre-commit scans), written by `sandbox exceptions add`:

```
# <repo>/.betterleaksignore
# documented example key, reviewed
deploy/values.yaml:generic-api-key:155
```

The **team overlay** `config.yaml` additionally holds:

```yaml
leakscan_extra_dep_dirs:             # extra dependency-dir names the secret gate skips
  - .cache-npm                       #   when gitignored (OVERLAY-ONLY — see note)
  - my-vendored-libs
trusted_inference_endpoints:         # internal model endpoints trusted with secrets
  - vllm.internal.example.org        #   (OVERLAY-ONLY — see note)
leakscan_inline_allow: off           # ignore inline betterleaks:allow comments (OVERLAY-ONLY, stricter)
leakscan_config_url: https://git.example.org/security/betterleaks-config/raw/branch/main/betterleaks.toml
                                     # betterleaks config the gate uses verbatim (OVERLAY-ONLY)
min_sandbox_version: 2.12.0          # oldest CLI allowed to use this overlay
exec_vectors:                        # more paths whose changes from the VM are held for
  - Justfile                         #   `sandbox sync review` (OVERLAY-ONLY; adds, never removes)
  - tools/release/
shared_tree_policy: deny             # refuse, instead of warn about, sessions sharing a repo
                                     #   across tiers or allowlists (OVERLAY-ONLY)
```

- `extra_allowed_domains` — see [Persistent extra domains](../how-to/persistent-domains.md).
- `blocked_domains` / `blocked_cidrs` — see [Never-allow block list](../how-to/persistent-domains.md#never-allow-a-personal-block-list). All three domain sources are still subject to the blocked-destinations check.
- `masked_paths` — see [Extending the mask](../explanation/security-model.md#extending-the-mask).
- `.betterleaksignore` (repo-root file, **not** a `config.yaml` key) — reviewed secret-gate false positives, written by `sandbox exceptions add`. Each is a native betterleaks `relpath:rule:line` fingerprint, so the same committed file is honored by the team's CI and pre-commit betterleaks runs. The sandbox launch gate honors it **only when the repo is vetted** (the vetting signature over the tree is its authority — CI tools honor it unconditionally); an unvetted repo's list is ignored by the sandbox. Fingerprints must be repo-relative; an absolute entry fails the gate closed. Repos on the retired `accepted_secrets:` key convert with `sandbox exceptions migrate`. See [Accepting secret-gate false positives](../how-to/secret-exceptions.md).
- `leakscan_dep_exclusions` / `leakscan_extra_dep_dirs` — control which gitignored dependency trees the secret gate skips; see [Dependency-tree exclusion](../explanation/security-model.md#dependency-tree-exclusion). `leakscan_extra_dep_dirs` is honored **only** in the overlay: adding a skip loosens the scan, so a repo or user cannot do it (only disable exclusions, which is stricter).
- The overlay may also ship a `.betterleaksignore` / `.gitleaksignore` **file** at its root (not a `config.yaml` key) — a baseline of betterleaks fingerprints the secret gate should accept. Like `leakscan_extra_dep_dirs` it is operator-only, since suppressing a finding loosens the scan; see [Owning betterleaks' allowlist inputs](../explanation/security-model.md#owning-betterleaks-allowlist-inputs).
- `leakscan_inline_allow` — whether the secret gate honors inline `# gitleaks:allow` / `# betterleaks:allow` comments on a flagged line. **Default is on** (honored): a reviewed, annotated line is suppressed, matching how the team's CI and pre-commit betterleaks runs treat the same comment. Set it to `off` to make the gate ignore inline comments and re-flag those lines — the stricter posture for an org that does not trust workspace-authored suppression. Read **only** from the overlay: the knob only tightens, so a repo or user config cannot change it. It governs only the workspace scan — the explicit `.git/config` scan never honors inline comments regardless of this setting. See [Owning betterleaks' allowlist inputs](../explanation/security-model.md#owning-betterleaks-allowlist-inputs).
- `leakscan_config_url` — a URL to a betterleaks config the secret gate uses **verbatim** in place of the one it generates, so the gate and another betterleaks-based tool (CI, a GitOps scanner) can share a single source of truth — point both at the same file. It is fetched, validated (`betterleaks config check`), and cached locally at `sandbox link` / `sandbox link sync` time and before each launch — never inside the scan, so the fail-closed gate never touches the network. The cache is sha256-pinned (recorded with its source URL in `~/.sandbox/config.yaml`); a changed remote is announced on the next fetch, not silently adopted. Fail-safe on a bad or unreachable fetch: the previous cached copy stands, or the gate falls back to its generated (strict) config and warns — it never skips scanning. Read **only** from the overlay, since supplying the scan config is a loosening authority (like `leakscan_inline_allow`). An operator who prefers to ship the file directly can instead commit a `betterleaks.toml` at the overlay root, used the same way with no fetch. See [Owning betterleaks' allowlist inputs](../explanation/security-model.md#owning-betterleaks-allowlist-inputs).
- `min_sandbox_version` — the minimum CLI version the overlay needs. An older CLI silently ignores overlay keys it does not know, so once an overlay relies on a newer feature this key makes "too old" a hard refusal instead: `sandbox link`, `sandbox link sync`, and `sandbox run` all refuse while the installed CLI is older (the fix is a newer CLI; `sandbox upgrade` is not available in v3 yet). A leading `v` is accepted; an unversioned dev checkout warns and proceeds (nothing to compare).
- `exec_vectors` — paths that can make code run on your machine when they change (a task runner's file, a script your tooling runs). The sync gate already holds changes from the VM to git's config and hooks, `.gitmodules`, editor and agent settings, and the like; each entry here is held the same way, for `sandbox sync review`. A bare name (`Justfile`) matches a file or directory of that name at any depth; an entry with a slash (`tools/release/`) is a path from the repository root and everything under it. Read only from the overlay, on your machine; the built-in list cannot be shortened.
- `shared_tree_policy` — sessions on one repository share its working tree in the VM, so what one agent writes the other reads. When a launch would share a repository with a running session of a different tier or allowlist, `sandbox run` warns and records a `shared-tree` event in the session's record; with `shared_tree_policy: deny` it refuses the launch instead. Read only from the overlay.
- `trusted_inference_endpoints` — exact bare hosts of internal model endpoints trusted to receive secret-bearing prompts. When a session's inference endpoint is on this list, a would-be-blocking secret finding is downgraded from a hard refusal to a single interactive confirmation (fails closed with no TTY). Read only from the overlay (an operator-side input, never a repo-local config, so the in-sandbox agent cannot add one), no wildcards; today only the `opencode` agent (`OPENCODE_BASE_URL`) can match. See [Trusted internal model endpoints](../how-to/secret-exceptions.md#trusted-internal-model-endpoints-a-different-lever).

## Environment variables

| Variable | Equivalent |
|----------|------------|
| `SANDBOX_EXTRA_ALLOWED_DOMAINS` | comma-separated `extra_allowed_domains` |
| `SANDBOX_OVERLAY` | `overlay:` |

In v3 the policy layer runs in the VM; the host passes it these settings from
your shell: `SANDBOX_EXTRA_ALLOWED_DOMAINS`, `SANDBOX_MAX_DEPS_PER_SESSION`,
`SANDBOX_NO_LINK_CHECK`, `NO_COLOR`, `USER`, and `OPENCODE_BASE_URL`. An
overlay directory on your machine (`SANDBOX_OVERLAY` or `overlay:`) is sent to
the VM with your settings and used from there. Nothing else of your environment
reaches the VM.

| Variable | Read on the host |
|----------|------------------|
| `SANDBOX_SECRETS_DIR` | the secret store (default `~/.sandbox/secrets`) |
| `OPENCODE_API_KEY` | opencode's key, read from your shell on the host at each opencode launch; sealed for the broker, never given to the agent |
| `OPENCODE_BASE_URL` | opencode's endpoint (or `--base-url`); forwarded to the VM |
| `CLAUDE_CODE_OAUTH_TOKEN` | read by `sandbox onboard --agent claude` instead of asking for the token |

## Profiles

A profile is a named YAML bundle (`tier`, and optionally `agent`,
`default_repo`, `extra_allowed_domains`, `secrets`, `mcps`, `services`). In v3
a profile's `secrets:` reach a session only through each secret's binding. See
[Profiles and overlays](../how-to/profiles-and-overlays.md) for the full field
reference and `sandbox profile save`.
