# Secret Store

[← Documentation](../index.md)

For credentials that aren't an agent's own login (Jira PATs, Gitea tokens, internal API keys),
the sandbox keeps a store on your machine at `~/.sandbox/secrets/` (one file per secret, mode
0600). The store never leaves your machine. When a session needs a secret, the host seals that one
secret and hands it to the sandbox VM's credential broker for that launch only.

In v3 the agent normally never sees a secret's value. It gets a placeholder (`sbxph_...`) in the
environment variable of the secret's name, and the session's gateway swaps the real value into
requests to the hosts the secret is **bound** to. A secret with no binding is **withheld**: the
session starts without it. You can also mark a secret **readable** when a tool really needs the
value itself.

(Agent logins are not stored here; see [Onboarding agents](onboarding-agents.md).)

## Storing a secret

```bash
# From stdin. The name must match [A-Z_][A-Z0-9_]*: it is also the variable the agent sees.
printf '%s' 'abcd1234' | sandbox secret set JIRA_PAT

# From a variable in your shell (same name by default, or --from-env=OTHER_VAR)
sandbox secret set JIRA_PAT --from-env

# From a file
sandbox secret set GITEA_TOKEN --from-file ~/.gitea-token

# List (names, sizes, times, and bindings; values are never printed)
sandbox secret list

# Remove (its binding goes with it)
sandbox secret delete JIRA_PAT
```

A value can be at most 64 KiB.

## Binding a secret

A binding says where the broker may send the secret and how:

```bash
# Brokered to the Jira host as a bearer token (bearer is the default injection)
sandbox secret bind JIRA_PAT --bind jira.example.com

# Several hosts, and another injection
sandbox secret bind GITEA_TOKEN --bind gitea.example.com,git.example.com --inject header:Authorization

# The binding can be given when storing the value
printf '%s' 'abcd1234' | sandbox secret set JIRA_PAT --bind jira.example.com

# Let the agent read the value itself instead (not brokered)
sandbox secret bind NPM_RC --allow-readable

# Remove the binding (the secret is withheld again)
sandbox secret bind JIRA_PAT --withhold
```

- `--bind HOST[,HOST]...` names exact hosts (no wildcards; at most 16). It can be repeated.
- `--inject KIND` is one of `bearer` (the default), `basic`, `header:NAME`, or `query:NAME`.
  `query:` puts the value in the URL, where more systems log it; prefer a header where the API
  allows it.
- `--allow-readable` and `--bind` are exclusive: a value the agent can read gains nothing from
  the broker.
- `sandbox secret set` without binding options keeps the secret's binding, so rotating a value
  does not lose it.

`sandbox secret list` shows each binding after the name: `-> jira.example.com (bearer)` or
`readable`. The binding is kept beside the value, in `~/.sandbox/secrets/.bindings/`.

## Giving secrets to a session

List the names in a profile:

```yaml
# ~/.sandbox/profiles/dev-app.yaml
tier: 2
secrets:
  - JIRA_PAT
  - GITEA_TOKEN
```

At `sandbox run --profile dev-app`, before the session starts:

1. The VM tells the host which secrets the launch needs. The host refuses any name that neither
   your command line nor your profile files mention, so a compromised VM cannot ask for the rest
   of the store.
2. The host seals each named secret **together with its binding** and stores it in the VM's
   broker. The binding is part of the sealed entry, so nothing in the VM can send the value
   anywhere else or make it readable.
3. A declared secret missing from the store stops the launch with v2's message, as before.

`run` then says what became of each one:

```text
==> Secret JIRA_PAT: brokered to jira.example.com (bearer)
==> Secret NPM_RC: readable by the agent ($NPM_RC)
==> Secret GITEA_TOKEN: withheld (no binding; see 'sandbox secret bind GITEA_TOKEN --bind HOST')
```

A bound host must also be on the session's allowlist (the agent's and tier's domains, your
`--allow-domain` values, and the persistent ones). A binding never widens the allowlist: a host
that is not on it is left out (`withheld (HOST not on this session's allowlist)`). See
[Persistent domains](persistent-domains.md).

Secrets a catalogue dependency declares are bound the same way, toward the dependency's own
egress. A dependency cannot read a secret.

## Using a secret inside the session

A brokered secret is a variable holding a placeholder. Use it where the binding says the value
goes, and the gateway does the rest:

```bash
# Inside the sandbox
curl -H "Authorization: Bearer $JIRA_PAT" https://jira.example.com/rest/api/2/myself
```

The gateway replaces the placeholder with the real value on its way to `jira.example.com`, and
replaces the value with the placeholder again in anything that comes back (an API that echoes the
request, an error page). Each use is in the session's audit log (`credential_injected`, and
`credential_reflection` when a response carried the value).

What the gateway refuses, and records:

- the placeholder sent to any other host (`credential_misuse`);
- a request to the bound host that carries some other credential of its own (an
  `Authorization` or API-key header, a cookie): `credential_missing`. A request with no
  credential at all (a health check) passes as it is.

A readable secret is in a file, `/run/sandbox/secrets/<NAME>` (read-only, the agent's user only),
with `<NAME>_FILE` naming it; an attached command gets `$<NAME>` exported from the file. An image
without a shell gets the file only.

When you drive the agent in natural language, name the variable rather than the value
("authenticate with `$JIRA_PAT`"). To see which variables are set without printing them, run
`env | grep -o '^[A-Z_]*=' | sort` in the session.

## Removing secrets from the VM

The VM's broker keeps the sealed entries the host pushed. A secret deleted from your store is
removed from the VM's broker at the next launch that names it. Removing the VM
(`sandbox uninstall`) removes them all.
