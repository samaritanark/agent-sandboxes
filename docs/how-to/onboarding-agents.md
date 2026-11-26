# Signing agents in

[← Documentation](../index.md)

In v3 an agent never holds its login. `sandbox onboard` seals the login on your
machine and stores it in the credential broker inside the sandbox VM. A session
gets a placeholder where the agent expects its token, and the session's gateway
puts the real token into the agent's requests to its own API hosts, and nowhere
else. Responses that echo the token come back with the placeholder.

Nothing of the login is kept on your machine. Onboard again after you
reinstall the VM.

| Agent | How it signs in | Sent to |
|---|---|---|
| Claude Code | a long-lived token from `claude setup-token` | `api.anthropic.com` |
| Codex | a ChatGPT login of the sandbox's own, refreshed by the broker | `chatgpt.com` |
| OpenCode | `OPENCODE_API_KEY` from your shell at each `run` | your endpoint's host |
| Copilot, Grok | not available in v3 yet | |

Build each agent's image first: `sandbox rebuild --agent <name>` (see
[Rebuilding images](rebuilding-images.md)).

## Claude Code

1. On your machine, with Claude Code installed:

   ```bash
   claude setup-token
   ```

   It signs you in through the browser and prints a token that starts with
   `sk-ant-oat01-`. It is valid for a year.
2. Give it to the sandbox:

   ```bash
   sandbox onboard --agent claude
   ```

   Paste the token when asked (it is not echoed), or export
   `CLAUDE_CODE_OAUTH_TOKEN` before running `onboard`. An API key
   (`sk-ant-api...`) is refused.

`onboard` also copies `~/.claude/settings.json` and `~/.claude/CLAUDE.md` to
`~/.sandbox/agent-config/claude/`, never your credentials file or history.

In the session, Claude Code finds a placeholder in `CLAUDE_CODE_OAUTH_TOKEN`.
Its own updater is turned off; updates come from `sandbox rebuild`.

## Codex

Codex signs in to your ChatGPT account. The sandbox uses a login of its own, so
the Codex you use on your machine stays signed in.

```bash
sandbox onboard --agent codex
```

This runs Codex's device login on your machine (Codex must be installed): open
the link it prints, sign in, and enter the code. `onboard` seals the login into
the broker, records your account's ID, email, and plan (not secrets) in
`~/.sandbox/agent-config/codex/identity.json`, and copies `~/.codex/config.toml`
and `~/.codex/AGENTS.md`.

To import an existing login instead, give its `auth.json`:

```bash
sandbox onboard --agent codex --from-auth-json ~/codex-sandbox/auth.json
```

Use a login nothing else uses: the sandbox refreshes it from then on, which signs
out any other copy. Don't import `~/.codex/auth.json`.

Codex's ChatGPT login has a short-lived access token. Before each Codex launch the
broker renews it in the VM if it would expire within a week, so a session never
outlives it. If the renewal fails (the login was revoked or expired), `run`
stops and tells you to onboard again.

In the session, Codex reads an `auth.json` made for the session: your account's
details and a stand-in access token whose real value only the gateway has.

## OpenCode

OpenCode needs no onboarding. Set its key and endpoint in your shell, as in v2:

```bash
export OPENCODE_API_KEY=...
export OPENCODE_BASE_URL=https://vllm.example.com/v1   # or pass --base-url
sandbox run --agent opencode --tier 2 --repo ~/repos/my-project
```

At each `run` the host fetches the endpoint's model list with your key, builds
OpenCode's configuration from it, and seals the key for that launch, bound to
the endpoint's host. The session gets a placeholder in `OPENAI_API_KEY`. The
endpoint must be `https`: only TLS destinations can carry a brokered key.

## Configuration and history in a session

The files `onboard` copied are given to each session as a fresh, writable copy
(`/home/agent/.claude` or `/home/agent/.codex`), thrown away when the session
ends. Change them on your machine and onboard again to update them.

Conversation history is kept in the VM:

- **Tier 1:** for the session only, deleted when it ends.
- **Tier 2 and 3:** per agent, tier, and set of repositories. A new session at
  the same tier on the same repositories sees it, so Claude's `/resume` and
  Codex's session history work. Sessions at different tiers never share history.

## Checking

`sandbox run` names each credential it brokers, for example:

```
==> claude: credential brokered to api.anthropic.com; configuration re-staged; history kept for this agent, tier, and repository set
```

If the agent is not onboarded, `run` stops and says how. Requests the gateway
refused show in the session's audit records as `credential_missing` or
`credential_misuse`; see [Audit logs](../reference/audit-logs.md) and
`sandbox flows <session>`.
