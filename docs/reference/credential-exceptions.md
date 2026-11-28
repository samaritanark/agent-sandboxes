# Credential Exceptions

[← Documentation](../index.md)

Agents whose login the credential broker does not hold (design 5.9.9, OQ-01:
allowed with a warning). Each launch warns, and the session's audit record has an
`unbrokered-credential` event.

| Agent | Login | Where it is kept | Why it is not brokered |
|---|---|---|---|
| copilot | GitHub OAuth (device login in the session) | the VM: `/var/lib/sandbox/agent-home/copilot/tier<N>`, mounted at `~/.copilot` | Not yet researched with a signed-in account: Copilot exchanges the GitHub login for short-lived Copilot tokens, and which requests carry which has to be measured before a placeholder can stand in |
| grok | xAI OAuth (`grok login --device-auth` in the session) | the VM: `/var/lib/sandbox/agent-home/grok/tier<N>`, mounted at `~/.grok` | Not yet researched with a signed-in account |

What the agent can do with it: read the login and use it from any host the
session's allowlist allows (for Copilot that includes `github.com` and
`api.github.com`). Everything else in the session (secrets, infra tokens,
cluster credentials) is still brokered.

See [Onboarding agents](../how-to/onboarding-agents.md#copilot-and-grok-not-brokered).
