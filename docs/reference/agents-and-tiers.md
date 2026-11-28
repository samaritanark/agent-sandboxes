# Agents & Tiers

[← Documentation](../index.md)

## Supported agents

| Agent    | Image            | Login (see [Onboarding agents](../how-to/onboarding-agents.md)) | Allowed domains |
|----------|------------------|------------------------------------------------------------------|-----------------|
| claude   | sandbox:claude   | `claude setup-token`, then `sandbox onboard --agent claude`; brokered to `api.anthropic.com` | `claude.ai`, `*.claude.ai`, `claude.com`, `*.claude.com`, `api.anthropic.com`, `console.anthropic.com`, `statsig.anthropic.com`, `sentry.io` |
| codex    | sandbox:codex    | a ChatGPT login: `sandbox onboard --agent codex`; brokered to `chatgpt.com` and refreshed by the broker | `api.openai.com`, `auth.openai.com`, `auth0.openai.com`, `chatgpt.com`, `cdn.openai.com` |
| opencode | sandbox:opencode | `OPENCODE_API_KEY` and `OPENCODE_BASE_URL` in your shell; brokered to the endpoint's host | the host of `OPENCODE_BASE_URL` |
| copilot  | sandbox:copilot  | its own device login in the session; **not brokered**, kept in the VM per tier | `github.com`, `api.github.com`, `*.githubcopilot.com`, `*.individual.githubcopilot.com`, `*.business.githubcopilot.com`, `*.enterprise.githubcopilot.com`, `copilot-proxy.githubusercontent.com`, `origin-tracker.githubusercontent.com`, `copilot-telemetry.githubusercontent.com`, `collector.github.com`, `default.exp-tas.com` |
| grok     | sandbox:grok     | its own device login in the session; **not brokered**, kept in the VM per tier | `api.x.ai`, `accounts.x.ai`, `auth.x.ai`, `grok.com` |

Except for copilot and grok, the agent never holds its real credential. Its token variable or file holds a
placeholder, and the session's gateway replaces it on requests to the agent's
API host. See [Security model](../explanation/security-model.md#credential-brokering).

Build the images once after installing: `sandbox rebuild --agent base`, then
`sandbox rebuild --agent claude` (and `codex`, `opencode`; `--tier3` for the
`-infra` variants). See [Rebuilding images](../how-to/rebuilding-images.md).

Allowlists are mostly exact host names. An entry may be a wildcard such as
`*.claude.ai`, which matches one label. A wildcard whose apex is a registrable
domain also grants the apex (`*.gitea.com` reaches `gitea.com`); one scoped below
the registrable domain does not (`*.aws.amazon.com` does not reach
`aws.amazon.com`). Wildcards over a public suffix (`*.com`) are refused. The
authoritative lists are in `go/internal/agents/agents.go` and
`go/internal/tier/tier.go`.

> **opencode:** set `OPENCODE_API_KEY` in your shell, and give the endpoint with
> `OPENCODE_BASE_URL` or `--base-url` (for example `https://api.openai.com/v1` or
> an internal vLLM proxy). At launch the host fetches the endpoint's model list
> with your key and seals the key for the broker; the agent gets
> `OPENAI_API_KEY` holding a placeholder, `OPENAI_BASE_URL`, and the model
> configuration. The endpoint must be HTTPS for the key to be brokered.

## Tiers

| Tier | Workspace | Extra domains | Requirements | Agent history |
|------|-----------|---------------|--------------|---------------|
| 1 | an empty `/workspace`, or the repos you name | none | none | kept for the session only |
| 2 | your repo(s), synced into the VM | `github.com`, `api.github.com`, `codeload.github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com`, `raw.githubusercontent.com`, `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org`, `registry.terraform.io`, `go.dev`, `dl.google.com`, `proxy.golang.org`, `sum.golang.org` | `--repo` (repeatable; each a git repository) | kept per agent, tier, and repository set |
| 3 | as tier 2 | tier 2, plus the hosts of `--infra-endpoint` and each cluster's gateway name | `--repo`, and `--infra-token` or `--infra-kubeconfig` | as tier 2 |

Tier 3 uses the `sandbox:<agent>-infra` image variant, which adds the infra
tooling, `kubectl` among it.

### Workspaces

The agent works on a copy of each repository inside the VM, not on your
checkout. The host syncs your repository into the VM before the launch and
syncs the agent's changes back while it runs and at the end. Changes to files
that can run code on your machine (`.git/config`, hooks, and the like) are held
back for you to review with `sandbox sync review`. See
[Architecture](../explanation/architecture.md#workspace-sync).

### Agent history

An agent's conversation history (Claude Code's `projects/`, Codex's
`sessions/`) is kept in the VM:

- per agent, per tier, and per set of repositories, so `/resume` in the agent
  finds earlier conversations on the same repositories at the same tier;
- never shared between tiers, so a lower-tier conversation cannot feed an agent
  that holds higher-tier access;
- at tier 1, only for the session.

The agent's configuration (settings, global instructions) is copied fresh into
every session as a writable copy and discarded at the end, so an agent cannot
plant a setting or hook that a later session picks up.
