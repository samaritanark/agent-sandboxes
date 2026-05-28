# Overlay template

An **overlay** is a directory a team ships to layer their own profiles,
governance, and additional restrictions on top of the org-level Agent
Sandbox install. Overlays are additive on the safety side: they can add
to the blocked-destinations list and narrow profile domain allow-lists,
but nothing in an overlay can weaken the org's controls or the tier
model — see `PRINCIPLES.md` ("Default-deny egress") for the rationale.

Copy this directory somewhere your team can version-control (a separate
git repo, an `infra/` subdirectory, an internal package, etc.), then
point the CLI at it via either of:

```bash
export SANDBOX_OVERLAY=/path/to/overlay-myteam
```

```yaml
# ~/.sandbox/config.yaml
overlay: /path/to/overlay-myteam
```

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
├── blocked-destinations.yaml    additional blocked domains/patterns
├── extra-ca-certs/              extra root CAs (see note below)
│   └── *.crt
└── profiles/
    ├── <profile-name>.yaml
    └── ...
```

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
