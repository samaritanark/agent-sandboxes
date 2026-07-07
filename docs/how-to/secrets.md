# Secret Store

[← Documentation](../index.md)

For credentials that aren't OAuth (Jira PATs, Gitea tokens, internal API
keys), the sandbox keeps a host-side store at `~/.sandbox/secrets/`
(mode 0600 per file) and injects what a profile declares as
session-scoped Kubernetes Secrets. Values **never persist in the
cluster across sessions** — they're created when the session launches
and deleted when it stops (PRINCIPLES.md "Credential isolation" rule 2).

```bash
# Add a secret. Name must match [A-Z_][A-Z0-9_]* — it's the env var
# the agent sees inside the pod.
printf '%s' 'abcd1234' | sandbox secret set JIRA_PAT

# Pull from a host env var with the same name (direnv / 1password-cli /
# .envrc / `export` — anything already in your shell). Defaults the source
# var name to the secret name; pass --from-env=OTHER_VAR to override.
sandbox secret set JIRA_PAT --from-env

# Or from a file on disk
sandbox secret set GITEA_TOKEN --from-file ~/.gitea-token

# Inspect (values are never printed)
sandbox secret list

# Remove
sandbox secret delete JIRA_PAT
```

Then list those names in a profile to inject them at session launch:

```yaml
# ~/.sandbox/profiles/dev-app.yaml
tier: 2
secrets:
  - JIRA_PAT
  - GITEA_TOKEN
```

At `sandbox run --profile dev-app` time, those values are read from the
host store and packed into one Secret (`session-secrets-<id>`); the pod
gets them via `envFrom: secretRef`, so each lands as `$JIRA_PAT` /
`$GITEA_TOKEN` inside the container. If a declared secret is missing
from the host store the launch is aborted before any cluster resources
are created.

## Using a secret inside the session

Each declared secret is a plain environment variable in the agent's
shell, named exactly as you stored it. So once you're in the session you
(or the agent) just reference it like any other env var — no unlock step,
no file to read:

```bash
# Inside the sandbox, the value is already in the environment:
curl -H "Authorization: Bearer $JIRA_PAT" https://jira.example.com/rest/...
git clone https://oauth2:$GITEA_TOKEN@gitea.example.com/team/repo.git
```

When you're driving the agent in natural language, tell it the env var
name rather than the value — e.g. "authenticate with the token in
`$JIRA_PAT`". The agent can use the variable without the secret ever
appearing in the transcript. To confirm what's present without printing
values, run `env | grep -o '^[A-Z_]*=' | sort` inside the session (or
check `printenv JIRA_PAT >/dev/null && echo set`); `sandbox secret list`
on the host shows the same names from the outside.
