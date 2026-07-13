# Overlay template

An **overlay** is a directory a team ships to layer their own profiles,
governance, and additional restrictions on top of the org-level Agent
Sandbox install. Overlays are additive on the safety side: they can add
to the blocked-destinations list and narrow profile domain allow-lists,
but nothing in an overlay can weaken the org's controls or the tier
model — see `PRINCIPLES.md` ("Default-deny egress") for the rationale.

Copy this directory somewhere your team can version-control (a separate
git repo, an `infra/` subdirectory, an internal package, etc.), then
point the CLI at it via any of:

```bash
export SANDBOX_OVERLAY=/path/to/overlay-myteam
```

```yaml
# ~/.sandbox/config.yaml
overlay: /path/to/overlay-myteam
```

### Or link it from a (private) git repo

If your team keeps this overlay in its own git repo — commonly a
**private** one, so the sandbox tool itself stays public while your
profiles, blocked/allowed destinations, and vetted MCP catalogue stay
internal — let `sandbox link` clone and track it for you:

```bash
# Clone the overlay repo, pin it to a ref, and wire the overlay: pointer.
sandbox link git@github.com:acme/sandbox-overlay.git --ref v1.4.0

# See where it points and whether it's behind the pinned ref.
sandbox link status

# Deliberately advance to a new ref (shows a diff, re-validates first).
sandbox link sync --ref v1.5.0

# Stop using it.
sandbox link unlink
```

> **The repo root must be the overlay root.** `link` clones the whole
> repo and treats its top level as the overlay, so `profiles/`,
> `catalogue/`, and `blocked-destinations.yaml` must sit at the repo root
> — not nested under an `infra/overlays/myteam/` subdirectory. (Nesting is
> fine if you instead point `overlay:` / `SANDBOX_OVERLAY` at the subdir by
> hand; it only breaks the `link` workflow.) The fastest way to a
> correctly-shaped repo is to copy this template and commit it:
>
> ```bash
> cp -r examples/overlay-template /path/to/sandbox-overlay
> cd /path/to/sandbox-overlay && git init && git add -A && git commit -m "initial overlay"
> # push to your private remote, then:  sandbox link <that-remote-url>
> ```

`link` clones into `~/.sandbox/overlays/<name>/` and records the source
URL, ref, and checked-out commit in `~/.sandbox/config.yaml`. The link is
**pinned**: it never advances on its own. `sandbox run` does a cached,
rate-limited fetch and only *hints* when the overlay is behind its ref
(set `SANDBOX_NO_LINK_CHECK=1` to disable that check for CI/air-gapped
hosts); `sandbox link sync` is the one deliberate, reviewed step that
moves the checked-out commit. Every clone and sync re-validates the
overlay's shape, and the additive-only safety rule below still holds —
nothing a linked repo ships can weaken the org's controls.

`sandbox run --profile <name>` will then resolve `<name>` against
`overlay/profiles/<name>.yaml` (after checking
`~/.sandbox/profiles/<name>.yaml` first), and every session passes its
allowed-domain list through both the org's
`config/blocked-destinations.yaml` and this overlay's.

## Layout

```
overlay-myteam/
├── README.md                    your team's onboarding doc
├── GOVERNANCE.md                your team's policy doc (referenced
│                                from PRINCIPLES.md as the team layer)
├── config.yaml                  overlay-wide policy: `vetting:` posture,
│                                `leakscan_extra_dep_dirs:` (operator-only
│                                secret-scan skips) — see docs/reference/configuration.md
├── blocked-destinations.yaml    additional blocked domains/patterns
├── .betterleaksignore           operator-owned secret-scan baseline: betterleaks
│                                fingerprints the gate should accept (operator-only,
│                                like leakscan_extra_dep_dirs) — see security-model.md
├── extra-ca-certs/              extra root CAs (see note below)
│   └── *.crt
├── profiles/                    launch profiles (schema below)
│   ├── <profile-name>.yaml
│   └── ...
└── catalogue/                   vetted MCP/service entries a profile may
    ├── <entry-name>.yaml        declare via `mcps:` / `services:`
    └── ...
```

Every entry here is optional — an overlay can be as small as a single
`profiles/` directory. See the sibling `catalogue/*.yaml` files in this
template for the catalogue entry schema (image digest, port, egress
allowlist, declared secrets).

> `extra-ca-certs/` is documented as the intended layout for team-shipped
> root CAs but isn't yet wired into the image build in this branch.
> Drop CAs in `config/extra-ca-certs/` on the install side for now; the
> overlay-side wiring will land in a follow-up.

## Profile schema

```yaml
# profiles/dev-app.yaml
profile: dev-app                  # informational; the filename is canonical
tier: 2                           # required (1|2|3) — passes validate_tier
default_repo: ~/repos/dev-app     # optional; used when --repo is absent
extra_allowed_domains:            # optional; appended to --allow-domain
  - internal-registry.example.com
  - api.dev-app.example.com
secrets:                          # Phase 4 — injected as session Secrets
  - jira-pat
mcps:                             # Phase 5 — deployed alongside session
  - dev-app-mcp
```

Every entry in `extra_allowed_domains` still passes the
blocked-destinations check, so an overlay cannot allow a host that the
org has globally blocked.
