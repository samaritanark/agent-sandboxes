# Persistent Extra Domains & Personal Block List

[← Documentation](../index.md)

## Persistent extras

If your team always needs the same extra domain reachable (an internal Git
host, an artifact registry, etc.), you don't have to type `--allow-domain`
on every invocation. Three persistent sources are loaded automatically on
every `sandbox run` and merged with the built-in tier allowlist:

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
# <repo>/.sandbox/config.yaml — per-repo defaults, checked in alongside code
extra_allowed_domains:
  - go.private.example.com   # private Go module proxy
  - npm.private.example.com
```

The per-repo source lets a project ship its own allow-list additions
(private package indexes, internal mirrors, etc.) without every
contributor having to add them to their personal config. **Because anyone
with push access to the repo can edit it, every session start prints a
banner listing what each repo's `.sandbox/config.yaml` contributed** —
that keeps slipped-in additions visible to the operator launching the
session.

All three sources are subject to the same blocked-destinations check as
`--allow-domain`, so an entry that matches `config/blocked-destinations.yaml`
is still rejected.

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
