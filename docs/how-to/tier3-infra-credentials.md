# Tier 3 Infra Credentials

[← Documentation](../index.md)

Tier 3 sessions are for infrastructure work. They need at least one credential:
`--infra-token` (available in v3) or `--infra-kubeconfig` (not yet available in v3, see below).

## `--infra-token <[NAME=]PATH>`

A file holding one bearer-style token (Vault, a custom internal API, any service that takes one
opaque secret). The token goes to the hosts of your `--infra-endpoint` URLs, and only there:

```bash
sandbox run --agent claude --tier 3 --repo ~/repos/infra \
  --infra-token api=~/.tokens/internal-api \
  --infra-endpoint https://api.internal.example.com/v1
```

- A bare `PATH` fills `$INFRA_TOKEN`; `NAME=PATH` fills `$INFRA_TOKEN_<NAME>`, so several tokens
  can ride into one session (`--infra-token ~/.vault --infra-token registry=~/.reg-token` gives
  `$INFRA_TOKEN` and `$INFRA_TOKEN_registry`). Names must be a valid variable suffix (letters,
  digits, underscores; not starting with a digit), and each target must be distinct.
- `--infra-endpoint <URL>` (repeatable) adds the URL's host to the session's allowlist and is
  where the tokens may go.

How it works in v3: the token file stays on your machine. At launch the host checks that each
token and each endpoint the VM asks for is one your command line names, reads the file (at most
64 KiB; a trailing line break is dropped, since the value becomes a header), and seals it into the
sandbox VM's credential broker, bound to the `--infra-endpoint` hosts as a bearer token. The agent's
`$INFRA_TOKEN_<NAME>` holds a placeholder; the session's gateway puts the real token into the
`Authorization: Bearer` header of requests to those hosts and refuses the placeholder anywhere
else. `run` says so:

```text
==> Sealing this launch's infra tokens for the sandbox VM: INFRA_TOKEN_api
==> Secret INFRA_TOKEN_api: brokered to api.internal.example.com (bearer)
```

With no `--infra-endpoint`, the token is withheld (`withheld (no --infra-endpoint to bind it
to)`). A relative token path is resolved against your current directory on the host.

Limits of this build:

- The injection is always `Authorization: Bearer`, and every token goes to every endpoint host.
  A service that wants its token in another header (Vault's `X-Vault-Token`) or only on one host:
  store it with `sandbox secret set` and a binding (`--bind vault.example.com --inject
  header:X-Vault-Token`), and name it in a profile's `secrets:`. See [Secret store](secrets.md).
- Only HTTPS endpoints can carry a brokered token (the gateway has to see the request).
  The gateway verifies the endpoint's certificate against the system roots and your extra CAs,
  so an endpoint with a private CA (a cluster's API server) needs that CA in
  `~/.sandbox/extra-ca-certs/` (see [TLS-intercepting proxies](tls-intercept-proxies.md)).
- An endpoint in a network your machine is directly attached to (its LAN, a VPN's subnet) or on
  the machine itself cannot be reached from the sandbox VM yet: the VM's network refuses those
  addresses, and declaring such endpoints (design 5.2.6) is not built.

Credential lifetime is still yours to manage: revoke a token at its issuer when you are done.
`run` reminds you when a session that held one ends.

## `--infra-kubeconfig` (not yet available in v3)

v2 copied a minified kubeconfig into the pod. v3's design keeps the cluster credential in the
gateway instead (bearer tokens brokered, client certificates presented by the gateway itself, so
the agent's kubeconfig holds placeholders only; design 5.9.5). That is not built yet: `sandbox run`
with `--infra-kubeconfig` stops before launching.

Until then, a cluster you can reach over HTTPS from the internet with a ServiceAccount token works
through `--infra-token` and `--infra-endpoint`: point `kubectl` inside the session at the API
server with the token from `$INFRA_TOKEN`, or have the agent use `curl`. A static token is minted
on the cluster as before:

```bash
# On the target cluster, as a human with kubectl access:
kubectl create sa sandbox-agent -n default
kubectl create clusterrolebinding sandbox-agent-edit \
  --clusterrole=edit --serviceaccount=default:sandbox-agent
kubectl create token sandbox-agent --duration=8h > ~/.tokens/dev-cluster
```

Use the lowest role the agent needs (`view`, a namespace-scoped Role, or a custom Role);
`cluster-admin` is never appropriate for an agent session (PRINCIPLES.md, "Credential
isolation").

> **Combining credentials widens the blast radius.** A session handed several tokens can use all
> of them, toward all of their endpoints, and the in-sandbox agent is the adversary in this tool's
> threat model. Brokering keeps the values from being stolen; it does not stop their use. Pair a
> production credential with anything else only when you mean that session to reach production.
