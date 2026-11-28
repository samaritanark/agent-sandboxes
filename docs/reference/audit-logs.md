# Audit Logs

[← Documentation](../index.md)

A session leaves two kinds of record:

- **The session record**, written by the policy layer in the VM: `session.json`
  (agent, tier, repositories, domains, timestamps, and the launch events below).
  `sandbox logs <SESSION_ID>` shows it.
- **The audit trail**, written in the VM by `sandboxd` and the session's
  gateway, and pulled to your machine into `~/.sandbox/logs/<SESSION_ID>/`:
  - `events.jsonl`: the session's lifecycle and credential events;
  - `flows.jsonl`: every connection the agent and its dependencies made, and
    every request on an intercepted connection;
  - `gaps.jsonl`: written only by the host, when the pull finds records missing.

The host pulls new records after every `sandbox` command it forwards to the VM,
and `sandbox flows` pulls before it prints. The pull is append-only: records
the host already holds are never rewritten, each record carries a sequence
number, and a jump in the sequence is recorded in `gaps.jsonl` as an
`audit_gap`. So a record that reached your machine cannot be changed later from
inside the VM, and records deleted there before the pull show up as a gap.

Retention: nothing expires on its own. `sandbox cleanup` removes session
records in the VM older than 90 days, or `--older-than DAYS`, when you run it.
A team overlay can set a minimum per tier (`log_retention_min_days_tier1`,
`_tier2`, `_tier3`); `cleanup` keeps every session younger than its tier's
minimum, and each session's `session.json` records that minimum as
`retention_days` (null when there is none; v2 recorded 90 or 180 days that
nothing enforced). The copies pulled to `~/.sandbox/logs` are yours to keep or
delete; `cleanup` does not touch them.

v2's `transcript/` and `files.log` are not written in v3: the agent's
conversation is in its history (see [Agents & tiers](agents-and-tiers.md#agent-history)),
and its changes come back through the workspace sync, which records what it
withheld (`sandbox sync review`).

## Launch events (session.json)

`session.json` carries an `events` array of timestamped records of the launch.
Each entry has `time` (UTC ISO-8601) and `type`:

- `vetting`: the repo-vetting gate's outcome (posture, what verified, what was
  accepted).
- `secret-scan`: the workspace secret gate's outcome (finding counts; whether an
  override was used).
- `override`: **a safety gate was waived**, one event per waiver:
  - `mechanism`: `flag:--i-accept-<name>`, or `interactive-prompt` when someone
    answered a y/N prompt;
  - `what`: what was waived (for example `2 unmasked secret(s) the agent will read`);
  - `repos`: the affected workspaces, by basename.

  A declined prompt stops the launch before `session.json` is written, so an
  `override` event always belongs to a session that ran with the waiver.

  ```json
  {
    "time": "2026-07-21T20:07:04Z",
    "type": "override",
    "mechanism": "flag:--i-accept-unmasked-secrets",
    "what": "2 unmasked secret(s) the agent will read",
    "repos": ["gitea"]
  }
  ```

## events.jsonl

One JSON object per line, each with `seq`, `session`, `time`, and `type`:

| Type | Meaning |
|------|---------|
| `session_requested`, `session_running`, `session_end` | the session's lifecycle; `session_end` has the `end_reason` (operator stop, attach lease expired, keep-alive limits, sandboxd restarted, ...) |
| `attached`, `detached` | a terminal attached to the agent, and its exit status |
| `dependency_up` | a dependency microVM (a profile's `services:` or `mcps:`) started |
| `secret_readable` | a secret marked readable was given to the agent as a file |
| `credential_injected` | the gateway put a credential into a request (host, method, path, credential reference; never the value) |
| `credential_reflection` | a response carried an injected value, and the gateway replaced it with the placeholder before the agent saw it |
| `credential_misuse` | a placeholder was sent toward a host it is not bound to; the request was refused |
| `credential_missing` | a request to a bound host carried a credential of its own instead of the placeholder; refused |
| `credential_rate_limited`, `credential_quota_exhausted` | a credential's limits were reached; refused |
| `link_drop` | a packet that tried to leave the session other than through its gateway was dropped |
| `tls_leaves_renewed` | the session's interception certificates were renewed |
| `audit_truncated` | the log reached its size cap; later records were not written |

## flows.jsonl and sandbox flows

`sandbox flows <SESSION_ID>` prints one line per record: time, decision,
destination, and for a request its method, path, status, and the rule that
decided it.

- `flow` records are connections: the destination name (TLS SNI) or the
  dependency, the port, the bytes each way, and the decision (`allowed`,
  `blocked`, `refused`, or `dependency`) with its reason.
- `request` records are HTTP requests on an intercepted connection (a host with
  a credential binding or an L7 rule): method, host, path, status, and the
  deciding rule (`default:forward` when no rule matched). Query strings are not
  logged, and no header values are.

A destination allowed with no binding and no L7 rule is passed through without
interception, so it has `flow` records but no `request` records.

## Other files

- `~/.sandbox/logs/vm-shell.log`: each `sandbox vm shell`, recorded on the host
  before and after it runs.
- `image-builds.log`: each `sandbox rebuild`, with the image's digest. It is
  kept in the VM, under the path `sandbox rebuild` prints (see
  [Rebuilding images](../how-to/rebuilding-images.md)).
