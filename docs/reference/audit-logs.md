# Audit Logs

[← Documentation](../index.md)

All sessions are logged to `~/.sandbox/logs/<SESSION_ID>/`:

- `session.json` — metadata, domains, timestamps
- `transcript/` — agent conversation transcript (commands run, tool calls, outcomes)
- `files.log` — workspace file changes (Tier 2/3)
- `flows.json` — Hubble network flows

Retention: 90 days (Tier 1/2), 180 days (Tier 3).

Image-build version info is appended to `~/.sandbox/logs/image-builds.log` — see
[Rebuilding images](../how-to/rebuilding-images.md).
