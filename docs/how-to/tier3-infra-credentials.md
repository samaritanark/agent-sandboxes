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
- An endpoint on your machine itself is reached through a declared endpoint (see [Clusters and
  endpoints on your machine](#clusters-and-endpoints-on-your-machine)). Other machines on your LAN
  or behind your VPN are reached like any other destination.

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

**Exec credential plugins** (`aws eks get-token`, `gke-gcloud-auth-plugin`, `kubelogin`): the
sandbox runs the plugin on your machine, with your own configuration (`~/.aws`, gcloud, a browser
sign-in), once at launch, after asking (`--allow-exec-plugin` skips the question, and is required
when stdin is not a terminal), and brokers the token or client certificate it returns:

```text
WARN: kubeconfig '/home/you/.kube/eks.yaml' gets its credential from the exec plugin 'aws'.
...
  Run it now? [y/N] y
==> Cluster eks: credential from the exec plugin 'aws' (valid until 2026-11-28 15:04 UTC)
```

The credential is not renewed during the session: once it expires (EKS tokens after 15 minutes,
GKE's after about an hour) the session's `kubectl` gets `401 Unauthorized`, and the next launch gets
a new one. For a long session, mint a longer-lived token (below). In v2 the plugin was copied into
the pod without its configuration, so every call failed.

Refused, with what to do instead:

- **`auth-provider`** (removed from Kubernetes in 1.26), **basic auth**, and a kubeconfig with no
  credential.
- **`insecure-skip-tls-verify`**: the gateway verifies every API server, so the kubeconfig needs
  the cluster's `certificate-authority-data`. **`proxy-url`** is refused too.
- **A server on loopback** (`https://127.0.0.1:6443`, as k3d and kind write it): a session's
  127.0.0.1 is its own. Point the kubeconfig at your machine's LAN address instead (below).

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

## Clusters and endpoints on your machine

The sandbox VM cannot reach any address of your machine: its network (`sandbox netd`) refuses
your machine's loopback and LAN addresses, so a session cannot reach services you run locally.
A tier 3 launch whose cluster API server or `--infra-endpoint` is one of your machine's
addresses opens that one address and port, for that session only:

```bash
# k3d writes https://0.0.0.0:<port>; v2's script rewrites it to your machine's LAN address
examples/k3d-podman/bake-kubeconfig.sh sandbox-target
sandbox run --agent claude --tier 3 --repo ~/repos/infra \
  --infra-kubeconfig ~/.kube/sandbox-k3d-sandbox-target.yaml
```

```text
==> Declared host endpoint(s) 192.168.1.178:6443 (this machine) for session ses-20261128-101500-3f2a, until it ends
...
==> Host endpoint 192.168.1.178:6443: an address of your machine, open to this session while it runs
```

- The host decides, by resolving the server's name itself and comparing it with your machine's
  addresses; the VM cannot ask for one.
- The endpoint closes when the session ends: checked after every `sandbox` command (a detached
  `--keep-alive` session's at the next command after it ends), at `sandbox vm stop`, and in any
  case after 7 days and an hour, the longest a session can live. The declarations are in
  `~/.sandbox/vm/vfkit/endpoints` (`vm/qemu/` on Linux); you can also add a line `ADDRESS:PORT` there yourself for an
  endpoint that stays open.
- The cluster's certificate must be valid for the address the kubeconfig names: k3d's is valid for
  your LAN address only if the cluster was created with `--k3s-arg "--tls-san=<address>@server:*"`
  (v2 had the same requirement).
- Only the drivers whose network is `sandbox netd` (vfkit on macOS, qemu on Linux) can open
  endpoints one by one. With `--driver lima` the launch stops and says so.
- The address and port are open to the whole sandbox VM while declared; each other session's
  gateway still refuses it unless that session's allowlist names it.

> **Combining credentials widens the blast radius.** A session handed several tokens can use all
> of them, toward all of their endpoints, and the in-sandbox agent is the adversary in this tool's
> threat model. Brokering keeps the values from being stolen; it does not stop their use. Pair a
> production credential with anything else only when you mean that session to reach production.
