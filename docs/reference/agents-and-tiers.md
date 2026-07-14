# Agents & Tiers

[← Documentation](../index.md)

## Supported agents

| Agent    | Image            | Auth    | Allowed domains                                                                                  |
|----------|------------------|---------|--------------------------------------------------------------------------------------------------|
| claude   | sandbox:claude   | OAuth   | `claude.ai`, `api.anthropic.com`, `console.anthropic.com`, `statsig.anthropic.com`, `sentry.io`  |
| codex    | sandbox:codex    | OAuth   | `api.openai.com`, `auth.openai.com`, `auth0.openai.com`, `cdn.openai.com`, `chatgpt.com`         |
| opencode | sandbox:opencode | API key | hostname of `OPENCODE_BASE_URL` (any OpenAI-compatible endpoint; operator chooses)               |
| copilot  | sandbox:copilot  | OAuth   | `github.com`, `api.github.com`, `*.githubcopilot.com`, `*.{individual,business,enterprise}.githubcopilot.com`, `copilot-proxy.githubusercontent.com` (+ attribution/telemetry) |
| grok     | sandbox:grok     | OAuth   | `api.x.ai`, `accounts.x.ai`, `auth.x.ai`, `grok.com`                                             |

Allowlists are mostly exact-match FQDNs; an entry may be an explicit wildcard
pattern (e.g. `*.githubcopilot.com`) when a provider fans out across
per-plan subdomains. A Cilium DNS wildcard matches a single label only (it does
not cross a dot), so Copilot's two-label per-plan hosts
(`api.individual.githubcopilot.com`, etc.) each need their own
`*.<plan>.githubcopilot.com` entry — the bare `*.githubcopilot.com` does not
reach them. See `lib/agents.sh` for the authoritative list.

> **opencode users:** `OPENCODE_API_KEY` must be set in the host environment,
> and you must supply an OpenAI-compatible endpoint URL — either via
> `OPENCODE_BASE_URL` in the env, or per-invocation with `--base-url <URL>`
> (`https://api.openai.com/v1`, an internal vLLM/Ollama proxy, etc.). The CLI
> will refuse to start if either is missing. claude, codex, copilot, and grok
> use OAuth and require nothing in the host env in advance (copilot needs an
> active Copilot subscription and signs in via GitHub device flow on first run).

> **copilot users:** Copilot's control plane is `github.com`/`api.github.com` —
> the same hosts a Tier 2 session uses for git — so a Tier 1 copilot sandbox is
> inherently less network-isolated than a Tier 1 claude sandbox. The FQDN
> allowlist still forecloses arbitrary egress. Only the standalone Copilot CLI
> (`@github/copilot`) is supported, not the `gh copilot` extension or the cloud
> coding agent. Behind a corporate proxy or GHES, add your `*.ghe.com` endpoints
> with `--allow-domain`.

> **grok users:** the official xAI Grok CLI signs in via OAuth against
> `auth.x.ai` (`grok login --device-auth` runs a device-code flow inside the
> pod), and the token persists to `~/.grok/auth.json` in the mounted agent-home.
> `GROK_DEPLOYMENT_KEY` is forbidden — it overrides the OAuth token, so it is
> blocked at build, onboard, and launch; `XAI_API_KEY` is unnecessary (OAuth
> outranks it). Grok's built-in web tools are **removed at launch** via
> `--disallowed-tools web_search,x_search,web_fetch`. `web_search` and `x_search`
> run server-side on xAI and return over `api.x.ai`, so the egress allowlist
> cannot see or bound them — dropping the tools from the request is the only
> control (`--disable-web-search` alone is insufficient; it leaves `x_search`
> live). With them gone, the agent fetches web content with `curl`/`wget`, which
> egresses from the pod and **is** bound by the tier allowlist — so a fetch to a
> host outside it is blocked by default-deny, and the allowlist stays the single
> source of truth for web reach. Shell fetches remain human-gated by Grok's
> approval prompts.
>
> `sandbox onboard` also hardens the staged `~/.grok/config.toml` with
> `disable_codebase_upload = true` (plus trace/telemetry off) — grok 0.2.93 was
> found to POST the **entire repository**, secrets included, to xAI's
> `grok-code-session-traces` bucket. The uploads used hosts outside the allowlist
> (so the egress policy already drops them), but `api.x.ai` is a required host
> and not a pure inference channel, so the client-side veto is defense-in-depth.
> These keys are reverse-engineered (not a documented xAI contract) and verified
> against 0.2.93; re-check with `grok inspect` after a version bump. Set the keys
> yourself in your host `~/.grok/config.toml` to override.

## Tiers

| Tier | Workspace     | Extra domains                                                                                                                              | Requirements                                                  |
|------|---------------|--------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| 1    | emptyDir      | none                                                                                                                                       | none                                                          |
| 2    | hostPath repo(s) | `github.com`, `api.github.com`, `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org`, `registry.terraform.io`    | `--repo` (repeatable, each must be a git repo)                |
| 3    | hostPath repo(s) | Tier 2 + URLs from `--infra-endpoint`; API server host/port from `--infra-kubeconfig`                                                      | `--repo` (repeatable) + at least one of `--infra-token` or `--infra-kubeconfig` |

Tier 3 also swaps in the `sandbox:<agent>-infra` image variant, which carries
the infra tooling layer. See `lib/tier.sh` for the authoritative domain list.

On Linux/WSL the tier 2/3 repo is bind-mounted into the pod directly, so the
agent's edits land in your working tree live. On macOS the agent works on a
VM-local copy that syncs back to your repo within a couple of seconds — same
net effect, slightly different mechanism. See [macOS workspace
sync](../explanation/architecture.md#macos-workspace-sync) for why.
