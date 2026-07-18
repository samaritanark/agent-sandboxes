# Persistent Extra Domains & Personal Block List

[← Documentation](../index.md)

## Persistent extras

If your team always needs the same extra domain reachable (an internal Git
host, an artifact registry, etc.), you don't have to type `--allow-domain`
on every invocation. These **operator-side** sources are loaded automatically
on every `sandbox run` and merged with the built-in tier allowlist:

```yaml
# ~/.sandbox/config.yaml — per-user defaults
extra_allowed_domains:
  - git.example.com
  - artifactory.example.com
```

```bash
# Shell env (comma-separated) — convenient for CI / shell-rc
export SANDBOX_EXTRA_ALLOWED_DOMAINS="git.example.com,artifactory.example.com"
```

```yaml
# <overlay>/profiles/<name>.yaml — team overlay profile (reviewed at link time)
extra_allowed_domains:
  - go.private.example.com   # private Go module proxy
  - npm.private.example.com
```

All of these are subject to the same blocked-destinations check as
`--allow-domain`, so an entry that matches `config/blocked-destinations.yaml`
is still rejected.

### A repo's own `.sandbox/config.yaml` is not honored by default

A `<repo>/.sandbox/config.yaml` may also carry an `extra_allowed_domains:`
list, but **the sandbox does not honor it by default**. Widening egress
*loosens* containment, and a repo's tree is writable by the in-sandbox agent
(and by anyone with push access) — so honoring a repo's own list would let the
contained agent grant itself a new exfil destination just by committing a
domain and having you relaunch. Instead, the launch prints a NOTICE listing
what the repo requested and how to allow it deliberately:

```
==> NOTICE: 2 extra egress domain(s) are requested by a repo's
    .sandbox/config.yaml but were NOT granted — a repo config cannot widen egress
    (an in-sandbox agent could otherwise self-add an exfil destination):
      - myapp: go.private.example.com
      - myapp: npm.private.example.com
    To allow one, grant it operator-side: --allow-domain <domain> (this launch),
    extra_allowed_domains: in ~/.sandbox/config.yaml, or an overlay profile; or set
    honor_repo_allowed_domains: true in your team overlay to honor repo lists.
```

This mirrors how the leak scanner treats its own loosening knob
(`leakscan_extra_dep_dirs`): adding to a containment-relaxing list is
**operator authority, confined to the team overlay**. A team that trusts its
repos and wants the check-it-in convenience back can opt in, once, in the
overlay:

```yaml
# <overlay>/config.yaml — team-shipped, operator-controlled
honor_repo_allowed_domains: true
```

With that set, per-repo `extra_allowed_domains:` are honored again (and each
still passes the blocked-destinations check, with a banner at launch). The key
is read **only** from the overlay — a repo or a personal `~/.sandbox/config.yaml`
setting it is ignored, so the decision to trust repo lists cannot itself be made
by an untrusted repo.

## Never-allow: a personal block list

The allow-list isn't purely manual — `--infra-kubeconfig` and `--infra-endpoint`
auto-allowlist their destination as part of spinning up a Tier 3 session. To
stop that convenience from quietly punching a hole in default-deny (say, an
accidentally-supplied **production** kubeconfig), you can keep your own block
list in the same `~/.sandbox/config.yaml`, using the same keys as
`config/blocked-destinations.yaml`:

```yaml
# ~/.sandbox/config.yaml
blocked_domains:
  - "*.prod.internal"        # never let a sandbox reach prod, even if a token says so
blocked_cidrs:
  - 10.0.0.0/8               # …including endpoints given as a bare IP
```

This is **deny-only and additive**: your entries are unioned with the org and
overlay block lists and can never weaken them (a block always beats an allow).
The check runs at `sandbox run` **before any cluster resource is created**, and
covers every egress target — including ones auto-derived from a kubeconfig or
`--infra-endpoint`, and IP-literal endpoints matched against `blocked_cidrs`. So
a kubeconfig whose API server is `https://10.0.3.7:6443` fails fast:

```
ERROR: 10.0.3.7 falls inside blocked CIDR '10.0.0.0/8'.
```

instead of launching and leaving you to discover at runtime that egress is
blocked. (IPv6-literal endpoints are matched only by Cilium's runtime
`egressDeny`, not at create time.)

## Live-updating a running session

If a session hits a domain that's not in its allowlist, you don't have
to stop and restart the pod. `sandbox allow` regenerates the
CiliumNetworkPolicy with extra entries and applies it in place — the
pod isn't restarted and in-flight connections are preserved:

```bash
sandbox allow ses-20260527-...-a7b3 --add-domain go.private.example.com
```

Each `--add-domain` goes through the same blocked-destinations check
as `--allow-domain` at launch. The change is recorded in
`~/.sandbox/logs/<session>/session.json` (both in `allowed_domains` and
as an event). `sandbox allow` is add-only — narrowing a live
allowlist requires `sandbox stop` and a fresh `sandbox run`.
