# Egress L7 Rules

[← Documentation](../index.md)

The allowlist decides which hosts a session may reach. L7 rules decide what it may do there:
which methods and paths. They are new in v3, enforced by each session's gateway in the sandbox
VM.

## Interception

A session's connection to an allowlisted host normally passes through the gateway untouched
(TLS end to end; the gateway sees only the host name). A host is **intercepted** instead when it
has an L7 rule or a credential binding (see [Secret store](secrets.md)): the gateway terminates
TLS with a certificate from the session's own certificate authority, applies the rules, and opens
its own TLS connection upstream, verified against the system and your extra CAs. The session
trusts that authority through `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `PIP_CERT`,
`GIT_SSL_CAINFO`, and `NODE_EXTRA_CA_CERTS`, and the bundle under `/etc/ssl/sandbox/`.

Intercepted requests are logged by method, host, path (never the query), status, and the rule that
decided: `sandbox flows <SESSION_ID>`.

## The org baseline

Every intercepted host gets the baseline that ships in the appliance image
(`config/egress-baseline.yaml`). It holds deny rules only, and nothing removes them:

- git smart-HTTP push (`POST …/git-receive-pack` and its advertisement), on every host;
- `TRACE` and `TRACK`, on every host;
- container registry pushes (the OCI distribution API's upload and manifest writes), on every
  host;
- publishing to npm (`registry.npmjs.org`, `registry.yarnpkg.com`), PyPI (`upload.pypi.org`,
  `test.pypi.org`, and any host's `/legacy/`), crates.io, and RubyGems.

A host that is allowlisted with no rule and no binding is not intercepted, so the baseline does not
apply there. It also carries no brokered credential to push or publish with. Add a rule for a host
to put the baseline on it.

## Your rules and the overlay's

Rules come from two files, in the baseline's format:

- the overlay's `egress-rules.yaml` (the team's), and
- `~/.sandbox/egress-rules.yaml` (yours; the host pushes it to the VM with the rest of your
  operator state).

```yaml
# ~/.sandbox/egress-rules.yaml
rules:
  # GitHub's API read-only for this machine's sessions: only GETs under /repos
  - {"host": "api.github.com", "methods": ["GET"], "path_patterns": ["/repos/**"], "action": "allow"}
  # never delete anything on any intercepted host
  - {"host": "*", "methods": ["DELETE"], "action": "deny"}
  # a self-hosted npm registry is read-only
  - {"host": "npm.corp.example.com", "methods": ["PUT", "DELETE", "PATCH"], "action": "deny"}
```

Each rule is one line, a JSON object (also valid YAML), under `rules:`:

- `host`: one exact name, `*.example.com` (one label under it), or `*` (every intercepted host;
  deny rules only).
- `methods`: the methods it covers (none: every method).
- `path_patterns`: globs over the path. `*` matches within one segment, `**` (a whole segment)
  any number of segments, and everything else itself. A pattern may end in a query part,
  `?name` or `?name=value` (`*` within a value), but only on a deny rule. None: every path.
- `action`: `deny` or `allow`.

Rules are deny first: any matching deny refuses the request. A host with allow rules is limited to
what they allow; one with only deny rules allows the rest. The baseline always comes first, so an
allow rule cannot reopen a baseline deny.

`sandbox run` reports the rules it applied:

```text
==> L7 rules (overlay): 3
==> L7 rules (operator): 2; left out for hosts not on this session's allowlist: npm.corp.example.com
```

A rule never widens the allowlist: one for a host the session cannot reach is left out and named.
A file that does not parse stops the run (a rule you wrote is never dropped quietly).

## The registry warning

A session's intercepted host whose name looks like a package or image registry (`registry`,
`npm`, `pypi`, `artifactory`, `nexus`, and the like) but has no deny rule of its own covering
`PUT` gets a warning at launch, with the rule to add:

```text
WARNING: npm.pkg.example.com looks like a package or image registry, but no rule refuses writes to it (a publish with a credential would pass).
         Add one to ~/.sandbox/egress-rules.yaml or the overlay, e.g.: {"host": "npm.pkg.example.com", "methods": ["PUT", "DELETE", "PATCH"], "action": "deny"}
```

The baseline already covers the public registries it names.

## Not yet

- The design lets an overlay relax the baseline's git push deny for named hosts (OQ-02); there is
  no way to do that yet.
- Rules apply to the agent's microVM. A catalogue dependency's egress is its catalogue list.
