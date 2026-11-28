# Tier 3 Infra Credentials

[← Documentation](../index.md)

Tier 3 sessions are for infrastructure work. They need at least one credential:
`--infra-token` or `--infra-kubeconfig` (both may be given, and each repeated).

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

## `--infra-kubeconfig <PATH>`

A kubeconfig for a cluster the agent may work on. Repeat it for several clusters (at most 16);
`--infra-kube-context <NAME>` picks the context when you give a single kubeconfig, and otherwise
each kubeconfig contributes its current context.

```bash
sandbox rebuild --agent claude --tier3     # once: the claude-infra image, with kubectl
sandbox run --agent claude --tier 3 --repo ~/repos/infra \
  --infra-kubeconfig ~/.kube/dev-cluster.yaml
```

```text
==> Minifying kubeconfig (context: <current-context>)...
==> Sealing this launch's cluster credentials for the sandbox VM: dev
...
==> Checking 1 cluster(s) from --infra-kubeconfig...
  Cluster API: https://203.0.113.10:6443 (context dev)
...
==> Cluster dev: https://203.0.113.10:6443 through the gateway (token brokered; Secrets, TokenRequest, and CSRs refused)
```

Inside the session `kubectl` works as usual (`KUBECONFIG` is set, and `kubectl config
use-context` switches between several clusters under their original context names and
namespaces).

How it works in v3, and how it differs from v2:

- **Your kubeconfig stays on your machine.** The host runs `kubectl config view --minify
  --flatten` on it (as v2 did, so `kubectl` must be installed on your machine), seals the
  credential (a bearer token, or a client certificate and key) into the sandbox VM's credential
  broker bound to that cluster, and passes the VM only the server address, its CA, and the
  context's name and namespace. v2 copied the minified kubeconfig, credential included, into the
  pod.
- **The agent's kubeconfig holds placeholders.** It names each cluster by a gateway name
  (`kube-0.gw.sandbox.internal`, ...) and trusts the session gateway's CA. The gateway puts the
  real token in, or presents the client certificate itself (the agent never sees the key),
  verifies the API server against the CA from your kubeconfig, and keeps a server URL's path
  prefix (a Rancher-style `https://rancher.example.com/k8s/clusters/c-abc`).
- **The gateway refuses some API calls whatever the credential's role allows:** reading or
  changing Secrets, minting ServiceAccount tokens (TokenRequest), and creating or approving
  CertificateSigningRequests. Each would turn the agent's use of the credential into a new
  credential that outlives the session. `kubectl exec`, `logs -f`, `port-forward`, and watches
  work.
- **The checks v2 made still apply:** the API server's host and the address it resolves to are
  checked against the block lists (see [Persistent domains](persistent-domains.md#never-allow-a-personal-block-list)),
  and a server on loopback is refused.

Refused, with what to do instead:

- **Exec credential plugins** (`aws eks get-token`, `gke-gcloud-auth-plugin`, `kubelogin`) are
  not run yet. v2 copied them in, but they failed there too. Mint a static token for the session
  (below), or bake one into a kubeconfig.
- **`auth-provider`** (removed from Kubernetes in 1.26), **basic auth**, and a kubeconfig with no
  credential.
- **`insecure-skip-tls-verify`**: the gateway verifies every API server, so the kubeconfig needs
  the cluster's `certificate-authority-data`. **`proxy-url`** is refused too.
- **A cluster on your own machine or LAN** (k3d, kind, minikube, a VPN-only API server) is not
  reachable from the sandbox VM yet: the VM's network refuses those addresses, and declaring such
  endpoints (design 5.2.6) is not built. A cluster reachable over the internet works.

A static ServiceAccount token, minted on the cluster as before:

```bash
# On the target cluster, as a human with kubectl access:
kubectl create sa sandbox-agent -n default
kubectl create clusterrolebinding sandbox-agent-edit \
  --clusterrole=edit --serviceaccount=default:sandbox-agent
kubectl create token sandbox-agent --duration=8h > ~/.tokens/dev-cluster
kubectl config set-credentials sandbox-agent --token="$(cat ~/.tokens/dev-cluster)" \
  --kubeconfig ~/.kube/dev-cluster.yaml
```

Use the lowest role the agent needs (`view`, a namespace-scoped Role, or a custom Role);
`cluster-admin` is never appropriate for an agent session (PRINCIPLES.md, "Credential
isolation").

> **Combining credentials widens the blast radius.** A session handed several tokens can use all
> of them, toward all of their endpoints, and the in-sandbox agent is the adversary in this tool's
> threat model. Brokering keeps the values from being stolen; it does not stop their use. Pair a
> production credential with anything else only when you mean that session to reach production.
