<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Samaritan's Purse -->

# Dependency catalogue (Phase 5)

Each `<name>.yaml` in this directory is a **vetted dependency entry** a profile
may request via `mcps:` (an MCP server registered with the agent) or `services:`
(a plain service the session connects to directly). Users *select* an entry by
name; they never author arbitrary workload YAML inline. See
`docs/design/phase5-mcp-dependencies.md` and `lib/catalogue.sh`.

This directory ships one live entry — `everything-mcp.yaml`, the official MCP
reference server used by the hands-on tutorial
(`docs/tutorials/mcp-dependency.md`). Otherwise an organization vets and pins the
images its agents are allowed to run: add entries here (or in a team overlay's
`catalogue/`), copying the templates in `examples/overlay-template/catalogue/`.

## Resolution order

1. `config/catalogue/<name>.yaml` — org install (canonical, wins on collision)
2. `<overlay>/catalogue/<name>.yaml` — team overlay (may **add** new entries)

An overlay can never override an org entry (org-first resolution), so an overlay
can never *broaden* an org-defined dependency — the additive-only safety
property from `PRINCIPLES.md`.

## Entry schema

```yaml
name: innkeeper-mcp                  # informational; filename is canonical
kind: mcp                           # required: mcp | service
image: ghcr.io/org/innkeeper-mcp@sha256:<64hex>   # required, DIGEST-PINNED
port: 8080                          # required: container port the dep serves
version: "1.2.3"                    # optional; recorded in the audit trail

# Resource limits — optional; lib/catalogue.sh supplies small defaults.
cpu_request: "250m"
cpu_limit: "1"
mem_request: "256Mi"
mem_limit: "512Mi"
ephemeral_limit: "1Gi"

# kind: mcp only — how the agent reaches it over the in-cluster Service.
mcp_transport: http                 # http | sse  (default http)
mcp_path: /mcp                      # URL path    (default /mcp)

# The dependency's OWN egress allowlist (443/TCP). Default empty = DNS-only.
# Every entry is checked against blocked-destinations exactly like
# --allow-domain; a bare '*' (allow-all) is refused.
egress:
  - api.internal.example.com

# Session-scoped secrets (Phase 4 names) provisioned into the dep pod.
secrets:
  - INNKEEPER_TOKEN
```

## Admission requirements

- **Digest pinning is mandatory.** `image:` must end `@sha256:<64 hex>`. A
  mutable tag would let the image change under a vetted name.
- **Egress is checked, not trusted.** Each `egress:` domain must pass the
  org + overlay blocked-destinations list.
- **High-value images** (notably the Playwright browser) additionally require
  signature verification (cosign) and a scan gate at admission — see §2.7 #2.
- Entries must **not** point at production or production-seeded data (§2.2).
