# Audit Logs

[← Documentation](../index.md)

All sessions are logged to `~/.sandbox/logs/<SESSION_ID>/`:

- `session.json` — metadata, domains, timestamps
- `transcript/` — agent conversation transcript (commands run, tool calls, outcomes)
- `files.log` — workspace file changes (Tier 2/3)
- `flows.json` — Hubble network flows

Retention: 90 days (Tier 1/2), 180 days (Tier 3).

## Session events

`session.json` carries an `events` array of structured, timestamped records of
what happened during launch. Each entry has `time` (UTC ISO-8601) and `type`.
Notable types:

- `vetting` — the repo-vetting gate outcome (posture, what verified, what was
  accepted).
- `secret-scan` — the workspace secret-gate outcome (finding counts; whether an
  override was exercised).
- `allowlist-extended` — a `sandbox allow` hot-reload added egress domains.
- `override` — **a safety gate was waived.** One event per waiver, recording:
  - `mechanism` — `flag:--i-accept-<name>` when a CLI flag pre-authorized it
    (e.g. from CI), or `interactive-prompt` when a human answered a y/N.
  - `what` — what was waived (e.g. `2 unmasked secret(s) the agent will read`,
    `3 commit(s) of unattested drift`).
  - `repos` — the affected workspace(s), by basename.

  Every launch-time acceptance is captured: `--i-accept-unmasked-secrets`,
  `--i-accept-unvetted-repo`, `--i-accept-vetting-drift`, and the interactive
  drift / stale-attestation / trusted-endpoint secret prompts. A *declined*
  prompt aborts the launch before `session.json` is written, so the presence of
  an `override` event always corresponds to a session that actually ran with the
  waiver in effect.

  ```json
  {
    "time": "2026-07-21T20:07:04Z",
    "type": "override",
    "mechanism": "flag:--i-accept-unmasked-secrets",
    "what": "2 unmasked secret(s) the agent will read",
    "repos": ["gitea"]
  }
  ```

Image-build version info is appended to `~/.sandbox/logs/image-builds.log` — see
[Rebuilding images](../how-to/rebuilding-images.md).
