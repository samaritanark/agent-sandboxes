# Credential Brokering

[← Documentation](../index.md)

> **Status:** Draft / Proposed
> **Author:** Jason Hall
> **Date:** 2026-08-27
> **Feature name:** Credential Brokering (a.k.a. brokered credentials)

## Summary

Today every secret handed to a sandbox - infra tokens, `--infra-kubeconfig`,
profile-declared `secrets:`, per-dependency bundles - lands inside the pod in a
form the agent can read directly (an env var, or a mounted `~/.kube/config`).
Under this repo's threat model the in-sandbox agent is **adversarial**, so a
readable credential is an exfiltratable one.

This document proposes **credential brokering**: keeping a credential's real
value *outside* the pod and letting the agent *use* it through a trusted broker
the agent cannot reach, instead of injecting the raw bytes. The agent's config
holds a placeholder; the broker holds the real value and attaches it at the
egress boundary toward a **pinned destination**. A leaked or fully-compromised
sandbox then yields **nothing the agent can exfiltrate or replay once the
session ends** - the placeholder is worthless off-box.

Be precise about what that does *not* buy. Brokering hides the credential's
bytes; it does not shrink the agent's in-session reach. A brokered credential is
*fully usable* while the session lives, so against a high-privilege destination -
the flagship being an infra kubeconfig on a cluster that lacks fine-grained RBAC -
the agent can still spend that capability to mint *new* credentials it then holds
directly (`kubectl get secret -A`, the TokenRequest API, a CSR it approves, a
`hostPath`/privileged pod). Concealment alone does not stop that; the broker must
*also* police what the capability can do at the destination. R1 addresses this
with a minimal deny-list at the apiserver broker (see
[the flagship kubeconfig case](#kubeconfigs-are-the-flagship-case)); the honest
one-line claim is **exfil- and replay-proof, plus no in-session escalation to a
durable exfiltratable credential** - not "yields nothing."

The first release (**R1**) covers credentials that attach to an HTTP request as a
**static header, query parameter, or basic-auth** - kubeconfig bearer tokens,
kubeconfig exec/auth-provider plugins, standalone HTTP bearer tokens, and API
keys. (We believe these cover the bulk of real usage, but that is an empirical
claim about the secret inventory worth measuring before it carries the scoping
argument - see [Coverage boundary](#coverage-boundary).) R1 is **one broker with
two request paths**, not one mechanism: a *reverse proxy* for the kubeconfig case
(the file is rewritten to point at the broker, so there is no TLS interception
and no pod-wide trust anchor) and a *TLS-terminating forward proxy* for ambient
API keys the pod's own SDKs resolve and dial themselves. Signing-based
credentials (AWS SigV4 and friends), and per-protocol brokers (kubeconfig client
certificates, SSH keys and git-over-ssh, database/wire-protocol credentials) are
**described here but scoped to future releases**.

## Background: how secrets reach a sandbox today

All secret paths funnel to one shape. The host-side store lives at
`~/.sandbox/secrets/<NAME>` (mode 0600). At launch the declared names are packed
into a single session-scoped K8s Secret via `--from-literal` and mounted with
`envFrom`, so **the name is the env var the agent sees** (`lib/secrets.sh:188`,
and the comment at `lib/secrets.sh:18` states this explicitly). Infra tokens use
the same mechanism under a different Secret name (`lib/cluster.sh:161`), and
per-dependency bundles mirror it (`create_dependency_secrets`).

Kubeconfigs are a richer case. `--infra-kubeconfig` inputs are minified and
flattened, then mounted as a Secret at `/home/agent/.kube/config`
(`create_kubeconfig_secret`, `lib/cluster.sh:377`). The merge path already
decomposes a kubeconfig into its embedded credential shapes - it reads
`.users[0].user.token`, `client-certificate-data`, and `client-key-data`
(`lib/cluster.sh:290-292`) - and separately detects `user.exec` credential
plugins (`kubeconfig_exec_command`, `lib/cluster.sh:372`), which it currently
refuses or warns on because the plugin binary is absent from the pod
(`bin/sandbox:1045-1065`).

**Net effect today:** the full credential - a bearer token, or a client cert
*and its private key*, or the whole kubeconfig - sits readable inside the pod
for the session's lifetime. The kubeconfig in particular is usually the
highest-privilege secret in the sandbox.

## Threat model

Unchanged from [PRINCIPLES.md](../../PRINCIPLES.md) and
[the security model](../explanation/security-model.md): the **operator is
trusted**, the **in-sandbox agent is adversarial**. The agent controls its own
process space (it can read `/proc/self/environ`, dump mounted files, and trace
its own children), and all pod egress is already forced through a policed path
(Cilium with `policyEnforcementMode: always`, Hubble export).

Two consequences drive the design:

1. **You cannot conceal a secret's value from a process that has it in its own
   address space.** Any "masking" that keeps the real bytes inside the pod -
   obfuscated env vars, wrapper scripts, a `kubectl` shim, file permissions - is
   theater against this agent. Concealment requires the value to never enter the
   pod.
2. **Egress is already brokered - but this hop is a heavier trust anchor.** A
   trusted component (Cilium/Hubble) already sits outside the pod's control on
   the network path, so an out-of-pod mediating hop is architecturally familiar.
   Do not undersell the difference, though: Cilium enforces L3/L4 (optionally L7)
   policy and holds *no* credentials, whereas the broker terminates TLS and holds
   *every* brokered value for the session in memory. It is a genuinely new,
   higher-value component with a different compromise consequence - a single
   place whose loss forfeits the whole session's credential set. That is an
   acceptable trade (it moves the bytes out of the adversary's address space),
   but it is a new trust boundary, and the [Security considerations](#security-considerations)
   treat it as one.

## The reframe: capabilities, not concealment

Stop modeling a secret as *bytes to hand the agent* and model it as *a
capability to use a credential at a known destination*. The store already
separates a secret's **name** from its **value**; brokering adds a per-secret
**binding** - a small policy describing where the credential is used and how it
is attached. The binding is what lets the broker inject the real value at the
egress boundary while the pod holds only a placeholder.

Under this model an infra token stops being special: it is a secret whose
binding is "destination = the API server, attach as `Authorization: Bearer`."
The same machinery covers `OPENAI_API_KEY`, `JIRA_PAT`, `GITHUB_TOKEN`, and the
bearer credential inside a kubeconfig.

### Vocabulary: this is not `sandbox mask`

`sandbox mask` / `masked_paths` hides a host file *from* the agent entirely with
an emptyDir overlay - the agent cannot use it. Brokering is the opposite axis:
the agent *can use* the credential but *cannot read* it. Keep the two distinct
in flags and docs. This feature is **credential brokering**; the credentials it
produces are **brokered** (never "masked").

## Goals and non-goals

**Goals**

- Let the agent use a credential without exposing its real value inside the pod.
- Pin each brokered credential to its intended destination, so a stolen
  placeholder cannot be replayed elsewhere.
- Give operators a truthful view of which secrets are *brokered (unreadable but
  fully usable)* versus *injected (readable)* - and never let the UI imply that
  "unreadable" means "harmless."
- Reuse the existing egress trust boundary and session-scoped credential
  lifecycle rather than inventing a parallel one.
- Provide a per-credential usage audit at a point the agent cannot touch -
  tamper-resistant on the broker, tamper-proof once shipped to an append-only
  off-broker sink.

**Non-goals**

- Concealing credentials whose *use* is an opaque local operation the agent
  drives directly (for example, handing raw key bytes to an arbitrary CLI). See
  [Coverage boundary](#coverage-boundary).
- Replacing the secret gate or the vetting gate. Brokering composes with them; it
  does not subsume them. (Egress policy is different: brokering does not replace
  it either, but it *relocates* part of it - once brokered traffic terminates at
  the broker, per-upstream allowlisting for those destinations has to move into
  the broker. See [Security considerations](#security-considerations).)
- Per-protocol brokers in R1 (see [Scope](#scope-and-phased-delivery)).
- Concealing a credential's *existence* or its *destination* from the agent -
  the agent necessarily learns it can reach service X; it just never holds X's
  key.

## Coverage boundary

A single broker cannot conceal *every* secret, because secrets are used in very
different ways. The governing rule:

> **A credential can be brokered if and only if its use can be expressed as a
> mediated request to a known destination with the credential attached by a rule
> the broker can apply itself** - in R1, a static header, query parameter, or
> basic-auth field.

Everything else can only be **shrunk** (short-lived, tightly scoped), not
hidden. Note the boundary this draws: "HTTP-shaped" is *not* the same as
"header-injectable." Credentials that sign the request (AWS SigV4, GCP
service-account JWT/ADC, OAuth2 client-credentials whose `client_secret` rides a
form body, HMAC-signed webhook/partner APIs) are HTTP but require the broker to
construct a signature over the canonical request and payload, not to staple on a
header - a distinct capability, deferred below. The taxonomy maps credential
shapes onto this rule and onto release phases.

| Credential shape | Example | Brokered how | Release |
|---|---|---|---|
| Kubeconfig - bearer token (`user.token`) | static-token infra kubeconfig | reverse-proxy broker; rewrite `server:`/CA, inject `Authorization: Bearer` | **R1** |
| Kubeconfig - exec plugin | EKS / GKE / AKS (`gke-gcloud-auth-plugin`, `aws eks get-token`, `kubelogin`) | run the plugin **broker-side** from an allowlist; pod never sees even the short-lived token | **R1** |
| Kubeconfig - `auth-provider: oidc` | OIDC kubeconfig | **decompose first**: the stanza carries `client-secret`/`refresh-token`/`id-token`, so extract those broker-side and never write them into the pod | **R1** |
| Standalone HTTP bearer token | `INFRA_TOKEN`, a raw API server token | forward-proxy broker; inject `Authorization: Bearer` for the bound host | **R1** |
| API key (static header, query param, or basic-auth) | `OPENAI_API_KEY`, `JIRA_PAT`, `GITHUB_TOKEN` | forward-proxy broker; inject `X-Api-Key` / custom header / basic-auth for the bound host | **R1** |
| Request-signing credential | AWS SigV4 (incl. Ceph RGW S3), GCP SA JWT, OAuth2 client-credentials, HMAC webhooks | signing broker: canonicalize + sign broker-side (must buffer or stream-hash the body) | **R2+** |
| Kubeconfig - client cert + key | mTLS infra kubeconfig | mTLS re-origination; broker holds the key, re-originates the handshake | **R2+** |
| SSH key / git-over-ssh | deploy key, `git clone git@...` | ssh-agent forwarding; key stays outside the pod | **R2+** |
| DB / wire-protocol password | Postgres, Redis | protocol-aware proxy holds the password | **R3+** |
| Opaque bytes used locally | signing key fed to `gpg --sign` | not concealable as bytes; can only mediate the *operation* | out of scope |

Two taxonomy notes worth stating plainly. First, the old "exec / auth-provider"
grouping no longer holds: the in-tree `gcp` and `azure` auth providers were
removed from client-go/kubectl in Kubernetes 1.26 in favour of exec plugins
(`gke-gcloud-auth-plugin`, `kubelogin`), so for EKS/GKE/AKS the live case is
**exec-only**, and `auth-provider` survives mainly as OIDC - which, unlike an
exec plugin, *does* carry secrets inline. Second, SigV4-against-Ceph-RGW is a
realistic in-scope destination for this platform and is deliberately *not* an R1
target; the honest R1 claim is "credentials attachable as a static header, query
parameter, or basic-auth," not "all HTTP-shaped credentials."

## Architecture (R1: the HTTP credential broker)

R1 is **one broker with two request paths** - a reverse proxy for the kubeconfig
case and a TLS-terminating forward proxy for ambient API keys - applied to every
header/query/basic-auth-attachable credential in the table. Calling it a single
mechanism flattens a real difference in interception and trust anchor (below).

### Components

- **Host-side store (unchanged):** `~/.sandbox/secrets/<NAME>` continues to hold
  real values at rest on the trusted host.
- **Broker:** a small authenticating proxy that holds the real credential(s) for
  the session, attaches each one only for its bound destination, and re-originates
  TLS to the true upstream. It runs **outside the pod** - in the node/VM network
  namespace or in a separate pod the agent has no `exec` into - i.e. the same
  placement as Cilium/Hubble. The agent must have **no network path to an upstream
  that would accept the real credential except through the broker.** Exactly one
  broker instance per session (see [session attribution](#security-considerations)).
- **Placeholder material in the pod:** env vars and/or a rewritten
  `~/.kube/config` carrying an opaque placeholder token and the broker's CA and
  address.

**The two request paths differ in how the pod comes to trust the broker, and
that difference bounds the blast radius of the trust anchor:**

- **Kubeconfig (reverse proxy).** We rewrite `server:` to the broker and
  `certificate-authority-data` to the broker's CA *inside the one kubeconfig
  file*. The broker is a legitimate TLS endpoint the client dials by name; there
  is no interception, and the trust anchor is scoped to that single file. This
  path needs **no pod-wide CA at all**.
- **Ambient API key (forward proxy + interception).** An SDK holding
  `OPENAI_API_KEY` resolves and dials `api.openai.com` itself, so brokering it
  means `HTTPS_PROXY` + `CONNECT` with TLS interception (or transparent 443
  redirection) and a CA the pod's clients trust. This is the path with real
  blast radius, and installing a CA into the pod's *system* store does **not**
  reach many clients: Python `requests`/`httpx` use `certifi`'s bundled roots,
  Node uses its own bundle unless `NODE_EXTRA_CA_CERTS` is set, Go honours
  `SSL_CERT_FILE`/`SSL_CERT_DIR` only on some builds, and cert-pinning clients
  never will. So the pod image needs an explicit **per-runtime trust strategy**
  (`REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_DIR`,
  …) and a **documented list of supported clients**. Combined with fail-closed,
  any client the strategy misses gets a TLS error, not a silent bypass - correct,
  but it caps how much of "the bulk of real usage" this path actually covers
  until the client list is validated.

### Request flow

1. The agent makes a normal request (e.g. `kubectl get pods`, or an HTTPS call
   to `api.openai.com`) using the placeholder credential, routed to the broker.
2. The broker matches on **both** the request's destination **and** the
   placeholder it presents (see [The binding](#the-binding) - keying on
   destination alone would make the capability ambient; keying on the placeholder
   alone would allow cross-destination replay). On a match to a bound destination
   that presents the right placeholder, it swaps the placeholder for the real
   credential (header injection, or the minted plugin token) and re-originates
   TLS to the true upstream.
3. Otherwise the broker **refuses** - not forwards. A request to a bound
   destination with a missing or wrong placeholder is rejected (and is a tamper
   signal); a request to an unbound destination is rejected outright. The broker
   must **not** relay unmatched traffic even without the credential: it sits
   *outside* the pod's Cilium enforcement point, so forwarding would hand the
   agent a general-purpose egress path with the node's network identity that
   bypasses pod egress policy and Hubble's per-destination flow record. Refusal
   is the security decision here, not an implementation detail.
4. The broker records the use in a per-credential audit stream the agent cannot
   reach, shipped off-broker (see [Security considerations](#security-considerations)).

### The binding

Each brokered secret gains a binding: `{ destinations: [host...], placeholder:
<opaque>, inject: <rule> }`, where `<rule>` is one of `Authorization: Bearer {}`,
a named header, a query parameter, or basic-auth. Bindings **must** be
destination-pinned; a wildcard destination turns the broker into a
credential-harvesting oracle (see [Security considerations](#security-considerations)).

**Injection is keyed on destination *and* placeholder together.** A request earns
the real credential only if it targets a bound destination *and* presents that
binding's placeholder; anything else is refused (see the request flow). This is
the difference between a scoped capability and an ambient one - keyed on
destination alone, any code the agent downloads that dials the bound host gets
the credential stapled on for free, placeholder or not.

A **built-in binding library** ships bindings for well-known services
(kubernetes-apiserver, github, openai, anthropic, jira, ...) so the common case
needs no operator configuration. Bindings are policy that decides *where the
agent's secrets get attached*, so - like the vetting trust root - they must be
something the adversarial agent cannot influence; the built-in library and any
custom binding are **signature-anchored to the same trust root as vetting**
(resolving the open question below).

A secret with no binding is **not** silently injected. Under an adversarial-agent
model the failure direction must be toward concealment, not exposure, so an
unbound secret is **withheld by default**; readable raw-env-var injection is
available only when the operator opts in explicitly (per-secret, e.g.
`--allow-readable`, mirroring the existing `--allow-exec-plugin` gate), and is
**labeled readable** in all UI when they do. A binding-name typo therefore fails
closed rather than quietly dropping a live secret into the pod.

### Kubeconfigs are the flagship case

A kubeconfig is not one credential; it is an envelope, and the repo already
takes it apart (`lib/cluster.sh:290-292`, `:372`). Three properties make it the
*easiest* R1 target rather than the hardest:

1. **The binding is self-describing.** The file already carries its destination
   (`clusters[0].cluster.server`, extracted today by `kubeconfig_server_url`,
   `lib/cluster.sh:337`) and its CA. Every other secret makes the operator
   author that metadata; a kubeconfig supplies it for free. Because the launch
   path *already* rewrites and flattens this file before mounting it, brokering
   slots into an existing step: repoint `server:` at the broker, swap in the
   broker's CA, and replace the token with a placeholder.
2. **Exec plugins are the pattern - but "auth-provider" is not secret-free.**
   Distinguish the two. An `exec` kubeconfig genuinely holds no secret in the
   file: it carries instructions to mint a short-lived token from credentials
   that live elsewhere (`~/.aws`, `~/.config/gcloud`, `~/.tsh`). Today the code
   refuses these because the plugin binary is not in the pod
   (`bin/sandbox:1045-1065`). R1 flips that limitation: run the plugin
   **broker-side** from an allowlist, so the pod never holds even the short-lived
   token, and what is currently "broken in the sandbox" becomes how concealment
   works. An `auth-provider: oidc` stanza is **not** secret-free, though - it
   embeds `client-secret`, `refresh-token`, and `id-token` directly, and exec
   `args` routinely embed `--oidc-client-secret=…`. The merge path today
   (`lib/cluster.sh:290-292`) extracts only `token` / `client-certificate-data` /
   `client-key-data` and never looks at these. R1 must **decompose exec and
   auth-provider stanzas for embedded secrets and keep those out of the pod**,
   rather than assuming the stanza is safe to flatten in.

   Running plugins broker-side also *expands the trusted component*, and that has
   to be designed, not assumed: an **allowlist of permitted binaries** (never an
   arbitrary `command:` from the kubeconfig), an ExecCredential response **cache
   with a TTL**, **concurrency control** so a burst of requests triggers one mint
   not many, rejection of **`interactiveMode` plugins** that expect a TTY (they
   will hang), a decision on **`provideClusterInfo`** passthrough, and defined
   behaviour on **plugin failure mid-session**. Note the tension with the
   memory-only rule below: several of these plugins cache tokens to disk by
   default, which the broker must suppress or redirect to memory.
3. **The broker is where the missing authorization can live - and here it is a
   precondition, not a bonus.** The clusters this repo targets lack fine-grained
   RBAC, which is exactly why concealment alone is insufficient for this
   credential (see [Summary](#summary)): a brokered-but-unrestricted apiserver
   capability still lets the agent mint a durable credential it can exfiltrate.
   R1's apiserver broker therefore ships a **minimal deny-list** that blocks the
   known credential-manufacturing paths - reading Secrets (`get`/`list`/`watch`
   across namespaces), the TokenRequest API (`create` on
   `serviceaccounts/token`), CSR creation and approval (`certificates.k8s.io`),
   and creating workloads with `hostPath`, `privileged`, or `hostNetwork`. This
   is deliberately a deny-list of escalation primitives, not a reimplementation
   of RBAC; "how much more coarse allow/deny is worth adding" stays an open
   question, but the deny-list floor is what makes the exfil claim honest for the
   kubeconfig case.

Client-certificate kubeconfigs are the one sub-case R1 does **not** cover: there
is no header to inject, so the broker must hold the client key and re-originate
the mTLS handshake. That is the mTLS re-origination row, deferred to R2 (below).

## Security considerations

- **Injection scoping is the primary hazard.** A binding that matches too
  broadly - a wildcard destination, or following a cross-host redirect - turns
  the broker itself into a credential-harvesting oracle: the agent aims a
  request at an attacker-controlled host and the broker helpfully attaches the
  secret. Bindings must be destination-pinned, and the broker must **refuse
  injection on cross-host redirects** and on any host outside the binding.
- **The adversarial agent controls every byte of the request**, so header and
  protocol handling need explicit rules, not defaults:
  - **Overwrite** the injected header, never append; reject or normalize a
    duplicate `Authorization`.
  - **Strip** agent-supplied hop-by-hop headers and anything named in
    `Connection:` that could strip the injected header downstream.
  - **Do not follow redirects broker-side**; strip the credential from any
    redirected request and refuse cross-host redirect injection.
  - **Guard request smuggling** across the HTTP/1.1 client side and an HTTP/2
    upstream: reject conflicting `Content-Length`/`Transfer-Encoding` and CRLF in
    URLs or headers.
  - **Validate the upstream certificate** against the *bound* hostname, pinned to
    a known CA. The broker must verify upstream TLS - without it, agent-influenced
    DNS resolution reintroduces the harvesting-oracle risk this design otherwise
    closes.
  - **Rate-limit and quota per credential.** Otherwise the agent can burn a
    credential's quota or bill, and use the broker as a request amplifier.
- **The broker is a high-value component.** It terminates TLS and holds every
  brokered value for the session. It is trusted and lives outside the pod, which
  is acceptable, but it must be memory-only, session-scoped, and torn down with
  the session (see [Lifecycle](#lifecycle)). It must **never write real values to
  disk or to its own logs - and that ban extends to request bodies and query
  strings**, which the broker now sees in plaintext and which routinely carry
  other secrets.
- **Egress enforcement relocates; it is not merely composed with.** Once brokered
  traffic terminates at the broker, the pod's only egress destination *is* the
  broker, so Cilium FQDN/CIDR policy for the true upstreams stops being meaningful
  and Hubble records pod-to-broker rather than pod-to-upstream. The broker must
  therefore **reimplement per-destination allowlisting internally, keep it
  consistent with the Cilium policy, and export it into the same audit path** -
  otherwise brokering quietly punches a hole in egress control while appearing to
  preserve it.
- **Session attribution.** If a broker is ever shared across sessions (a
  node-namespace placement, or the Tier 3 same-node topology), source IP plus
  placeholder is a weak identity. R1 mandates **one broker instance per session**
  so attribution is structural; any shared-broker future needs an explicit
  attribution model first.
- **TLS handling differs by path.** The kubeconfig reverse-proxy path is a
  legitimate endpoint with no interception. The ambient-API-key forward-proxy
  path *does* intercept: the pod trusts the broker's CA and the broker sees the
  plaintext of the agent's own traffic (acceptable - that traffic is the agent's).
  Clients that pin certificates, and genuine mTLS upstreams, defeat header
  injection and fall to the per-protocol work.
- **Streaming verbs.** `kubectl exec`/`attach`/`port-forward` (and `kubectl cp`,
  which rides `exec`) use a connection upgrade the broker must proxy, not just
  request/response; `kubectl logs -f` and `watch` are plain long-lived streaming
  responses. As of Kubernetes v1.31 kubectl defaults to the **WebSocket**
  streaming protocol (KEP-4006), which off-the-shelf proxy libraries support far
  better than the deprecated SPDY it replaced - so this is less the "sharpest
  edge" than it once was. The broker must still handle the **SPDY fallback** for
  older or feature-gate-disabled API servers and must **not silently downgrade**.
- **Fail closed.** If the broker is unreachable, or a binding is missing for a
  destination that requires one, the request fails rather than falling back to a
  direct, unbrokered call. An unbound secret is withheld (readable injection is
  opt-in only - see [The binding](#the-binding)), so the failure direction is
  always toward concealment.
- **Audit is tamper-*resistant*, and tamper-*proof* only off-broker.** On-broker
  audit is beyond the agent's reach but not beyond a broker compromise; the
  "tamper-proof" claim holds only once the stream is shipped to an append-only
  sink off the broker. Ship it.
- **Truthful UI.** `sandbox secret list` and session output must distinguish
  `brokered (unreadable, fully usable)` from `injected (readable)`, and
  query-parameter injection - which writes the credential into upstream access
  logs and any intermediary - must be flagged as a **degraded** mode rather than
  presented as equivalent to header injection. The feature must never imply
  concealment, or safety, it is not delivering.

## Benefits beyond privacy

- **Exfil- and replay-proof credentials.** The brokered value itself leaks
  nothing usable even on full sandbox compromise, and cannot be replayed after
  the session - directly serving the adversarial-agent model. (This is about the
  *credential's bytes*; the in-session capability is separately fenced by the
  apiserver deny-list, not by concealment - see [Summary](#summary).)
- **Non-replayable by construction.** Destination pinning means a stolen
  placeholder cannot be pointed at an attacker's host.
- **Tamper-resistant per-credential audit** at a point the agent cannot reach -
  and tamper-*proof* once shipped to an append-only off-broker sink.
- **Rotation and revocation without touching the sandbox** - change the value at
  the broker mid-session.
- **A home for the coarse authorization** the clusters themselves lack - which
  for the apiserver case is load-bearing, not a bonus.

## Scope and phased delivery

### R1 (this release): HTTP credential broker

**In scope**

- Destination-pinned authenticating proxy, running outside the pod, **one
  instance per session**, with the two request paths (reverse proxy for
  kubeconfigs, TLS-terminating forward proxy for ambient keys).
- Kubeconfig **bearer-token** brokering (rewrite `server:`/CA + placeholder).
- Kubeconfig **exec** plugins executed **broker-side** from a binary allowlist,
  and **decomposition of `auth-provider: oidc`** stanzas to keep their embedded
  `client-secret`/`refresh-token`/`id-token` out of the pod.
- **Minimal apiserver deny-list** for the credential-manufacturing verbs (Secret
  reads, TokenRequest, CSR create/approve, `hostPath`/`privileged`/`hostNetwork`
  workloads), so a concealed apiserver capability cannot mint a durable one.
- Standalone **HTTP bearer tokens** (including `INFRA_TOKEN`).
- **API keys** attachable as a static header, query parameter, or basic-auth to a
  bound host (query-param flagged degraded).
- Injection keyed on **destination *and* placeholder**, with request hardening
  (header overwrite, hop-by-hop stripping, no broker-side redirect-follow,
  smuggling guards, upstream-TLS validation, per-credential rate/quota).
- Per-runtime CA-trust strategy in the pod image for the forward-proxy path, with
  a documented list of supported clients.
- Built-in **signature-anchored** binding library for well-known services;
  explicit `--dest`/`--inject` for custom bindings.
- Truthful `brokered` vs `injected` reporting; unbound secrets **withheld by
  default**, readable injection only via explicit per-secret `--allow-readable`.
- WebSocket upgrade handling (K8s ≥ 1.31 default) for kubeconfig streaming verbs,
  with SPDY fallback and no silent downgrade.
- Per-credential audit shipped to an append-only off-broker sink.

**Explicitly out of scope for R1** (deferred, not rejected)

- Any **per-protocol** broker. R1 is HTTP(S)-only.
- Kubeconfig **client-certificate** (mTLS) credentials.
- **SSH keys** and **git-over-ssh**.
- **Database / wire-protocol** credentials.
- Concealing opaque locally-used byte secrets.

### R2 and later (future releases): per-protocol brokers

Per-protocol capabilities are **in scope for the capability overall**, just not
for R1. Anticipated order:

- **R2 - mTLS re-origination and SSH.**
  - Kubeconfig **client-certificate** credentials: the broker holds the client
    key and re-originates the mTLS handshake to the API server; the pod's
    kubeconfig points at the broker over the broker's CA with no client key
    present.
  - **SSH keys and git-over-ssh** via ssh-agent forwarding - the canonical
    "use but not read" precedent. The private key stays outside the pod; the
    agent gets a forwarded agent socket, so `ssh` and `git clone git@...`
    succeed without the key ever entering the sandbox. Scope the forwarded
    agent to session lifetime and, where the SSH implementation allows,
    constrain it (confirmation/destination limits).
- **R3+ - database / wire-protocol credentials.** Protocol-aware proxies (for
  example a Postgres/Redis-fronting hop) that hold the password and speak the
  wire protocol on the agent's behalf. One capability per protocol.

### Fallback for the unbrokerable (any release)

Where a credential cannot be concealed - opaque local use, cert-pinning clients
before their per-protocol support lands - prefer **short-lived, tightly scoped**
credentials where the provider supports them (fine-grained short-lived tokens,
STS/OIDC workload identity). The agent still reads *a* credential, but a leak is
near-worthless. This is blast-radius reduction, not concealment, and the UI must
say so.

## CLI and UX surface (sketch)

```bash
# Store a secret and bind it to a known service (built-in binding).
sandbox secret set OPENAI_API_KEY --bind openai

# Custom binding: pin destination + injection rule explicitly.
sandbox secret set JIRA_PAT --dest jira.example.com --inject 'header:Authorization=Bearer {}'

# Unbound secret is WITHHELD by default (fail-closed). Readable injection is an
# explicit per-secret opt-in, and lands visibly readable in the listing.
sandbox secret set LEGACY_KEY --allow-readable

# Kubeconfig: binding is inferred from the file (server + CA); brokered by default
# for token/exec kubeconfigs. Client-cert kubeconfigs warn "readable until R2".
sandbox run --tier 3 --infra-kubeconfig ~/.kube/prod.yaml ...

# Truthful listing.
sandbox secret list
#   NAME             STATE                              DESTINATION
#   OPENAI_API_KEY   brokered (unreadable, usable)      api.openai.com
#   LEGACY_KEY       injected (readable)                -
#   STALE_KEY        withheld (no binding)              -
```

Exact flag names are provisional; the constraints are that the UI never overstates
concealment (`unreadable` is qualified with `usable`, never bare), that an unbound
secret is *withheld* unless the operator opted it into readable injection, and
that a readable or query-param-degraded secret is visibly labeled as such.

## Lifecycle

Brokered credentials follow the **same session lifecycle** as
`create_session_secrets` / `delete_session_secrets` and the infra-token/
kubeconfig Secrets (`lib/cluster.sh`, `lib/secrets.sh`): established at launch,
owned by the session, and torn down on every termination path. The broker's
in-memory credential set is destroyed with the session, and teardown must verify
the broker is gone alongside the existing Secret-deletion checks.

**The teardown discipline depends on the placement decision that is still open
above, so there are two contracts, not one.** If the broker is a **sibling pod**,
it is a Kubernetes object and reuses the established discipline directly -
owner-reference adoption so it garbage-collects with the session pod object, and
verified deletion across all `cmd_stop` paths, exactly as the credential Secrets
do. If the broker runs in the **node/Lima VM network namespace**, there is no
owner reference and no `cmd_stop` Secret-deletion analogue; it needs its own
explicit process/namespace teardown with the same verified-gone check on every
termination path (including the eviction and signal paths the existing teardown
work already hardened). Resolve placement before writing the contract, or write
both - do not assume the Kubernetes-object shape.

**Broker restart mid-session** also needs a rule the memory-only requirement
forces into the open: a crash means either the session dies, or the broker
rehydrates its credential set from the trusted host store - and rehydration is a
re-authentication path (re-running exec plugins, re-reading `~/.sandbox/secrets`)
that needs its own guardrails rather than happening implicitly.

## Alternatives considered

- **In-pod masking (obfuscated env vars, wrapper scripts, a `kubectl` shim).**
  Rejected: theater against an adversarial agent that controls its own address
  space. Would create a false sense of concealment - worse than honest readable
  injection.
- **Short-lived scoped tokens only.** Kept as the *fallback* tier, not the
  primary design: it reduces blast radius but the agent still reads the token,
  so it does not meet the "use but not read" goal for credentials that can be
  brokered.
- **A bespoke broker per credential type from day one.** Rejected for R1 as
  over-large: header/query/basic-auth injection covers a large share of real
  usage with one broker (two request paths), and per-protocol and signing brokers
  layer on later without reworking it. The share is a claim worth measuring, not
  asserting - see [Coverage boundary](#coverage-boundary).

## Open questions

- **Broker placement:** node/VM network namespace versus a sibling pod - which
  gives the cleanest "agent has no path to it" guarantee across the Linux and
  Lima/macOS topologies? This is now the *gating* question, because the
  [Lifecycle](#lifecycle) contract branches on it.
- **CA distribution (partly settled):** the kubeconfig reverse-proxy path needs
  no pod-wide CA at all - the anchor is scoped to the one rewritten file. The
  open part is only the forward-proxy path: which per-runtime trust mechanism
  (`REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, …) and which
  supported-client list keep the CA from becoming a lever the agent can misuse
  for other destinations.
- **Per-request authorization depth (floor settled):** R1 ships the minimal
  apiserver deny-list of credential-manufacturing primitives. Open is how much
  further coarse allow/deny is worth adding before it becomes a reimplementation
  of RBAC.
- **Signing broker (R2 shape):** how the SigV4/JWT/OAuth signing broker buffers
  or stream-hashes request bodies without violating the no-plaintext-to-disk rule.

Two former open questions are **resolved** in the body above and no longer open:

- **Binding authenticity → yes.** Bindings are policy for where the agent's
  secrets get attached, so they are signature-anchored to the vetting trust root
  (see [The binding](#the-binding)).
- **Placeholder / real-value detection → required.** The broker rejects a request
  to a bound destination that presents no placeholder, the wrong placeholder, or
  the *real* value - the last being a high-signal tamper indicator with no
  false-positive cost (see the [request flow](#request-flow)).

## Related

- [PRINCIPLES.md](../../PRINCIPLES.md) - design intent and threat model.
- [Security model](../explanation/security-model.md) - current controls,
  including the mask and secret gate this feature composes with.
- Multi-infra credentials (`--infra-token` / `--infra-kubeconfig` repeatable;
  `merge_kubeconfigs`) - the credential surface R1 brokers.
