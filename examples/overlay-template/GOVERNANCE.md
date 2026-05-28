# Team governance — TEMPLATE

This file is where your team layers its own policy on top of the
org-level `PRINCIPLES.md` shipped with the Agent Sandbox. The principles
file describes what the *tool* defends against and the assumptions it's
built on; this file describes what *your team* expects of operators and
agents using the tool. Customize freely.

## Scope

Profiles defined in this overlay are intended for: <describe the team /
project / set of repos this overlay applies to>.

Out of scope: <call out what this overlay does NOT cover — production
access, customer data, etc.>.

## Per-profile expectations

Document each profile's intended use case, who its primary users are,
and what additional review the team requires beyond the org-level
defaults. For example:

- `dev-app` — day-to-day work against the dev-app repos. Reviewer must
  verify any PR touching `payments/` is also approved by the payments
  team.
- `research` — exploratory work with broader web access. Output must be
  treated as untrusted until reviewed.

## Operator responsibilities (team layer)

- Confirm you have read both the org-level PRINCIPLES.md and this file
  before your first session under this overlay.
- <add team-specific items: rotation cadence, retention, incident
  response contacts, etc.>

## Reviewing agent-produced changes from this overlay

- <add team-specific review rigor — e.g. "all PRs from a `research`
  profile session must be reviewed by two engineers">

## What this overlay does NOT change

The following remain governed by the org-level controls and cannot be
weakened by this overlay:

- The tier model (1 ephemeral / 2 project / 3 infra) and its defaults.
- The org-level `config/blocked-destinations.yaml`. Anything added by
  this overlay's `blocked-destinations.yaml` is on top of that list.
- Credential isolation (no API keys in images; session-scoped infra
  credentials; no auth-provider state forwarded).
- The "never permitted regardless of tier" list in PRINCIPLES.md.
