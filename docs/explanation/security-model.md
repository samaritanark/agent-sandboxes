# Security Model

[← Documentation](../index.md)

For the design intent and threat model behind these controls, read
[PRINCIPLES.md](../../PRINCIPLES.md).

- **Kernel isolation**: gVisor (runsc) for all pods
- **Network**: Cilium with `policyEnforcementMode: always`;
  per-session CiliumNetworkPolicy
- **Filesystem**: `.env`, `.npmrc`, `clouds.yaml`, and any `kubeconfig`/`.kube/`
  in the workspace are masked with emptyDir overlays. The only kubeconfig that
  ever enters the pod is one explicitly passed via `--infra-kubeconfig`, which
  is minified to a single context, mounted as a K8s Secret at
  `/home/agent/.kube/config`, and deleted on teardown.
- **Secret gate**: before every Tier 2/3 launch each `--repo` is scanned
  with [betterleaks](https://github.com/betterleaks/betterleaks). A secret
  found in a file the mask would **not** hide aborts the launch — the agent
  never sees a workspace secret you forgot about. The error names the
  offending path and gives a `sandbox mask add` command to hide it (see
  [Extending the mask](#extending-the-mask) below). betterleaks is required for
  Tier 2/3; if it is missing, the launch fails closed. `sandbox setup` installs
  the pinned version (`setup/versions.sh`) when it is absent or older, so you
  normally never have to install it by hand. The scan covers your tracked and
  untracked files but skips gitignored dependency trees (`node_modules`,
  `.venv`, `vendor`, ...) — upstream-managed code that holds none of your
  secrets (see [Dependency-tree exclusion](#dependency-tree-exclusion)).
  `--i-accept-unmasked-secrets` on `sandbox run` prints the findings and
  launches anyway. Values that are **encrypted at rest** are exempt — a hit
  inside a Bitnami SealedSecret's `spec.encryptedData` or a Mozilla SOPS
  `ENC[...]` envelope is ciphertext the agent can read harmlessly, so it does
  not gate (see [Encrypted-at-rest exemption](#encrypted-at-rest-exemption)). A
  genuine false positive can instead be recorded per-finding as an exception
  that the gate honors only once the repo is vetted (see
  [Accepting a reviewed false positive](#accepting-a-reviewed-false-positive)).
- **Credentials**: claude/codex use OAuth (no API key injection);
  opencode key via K8s Secret; tier 3 infra creds via per-session Secrets
  (`--infra-token` → `$INFRA_TOKEN`; `--infra-kubeconfig` → mounted file)
- **Pod security**: non-root UID 1000, all capabilities dropped,
  no privilege escalation
- **Service account**: `automountServiceAccountToken: false`,
  no RBAC bindings

## Extending the mask

The built-in mask covers a fixed root-level set (`.env`, `.env.local`,
`.npmrc`, `clouds.yaml`, `kubeconfig`, `.kube/`, `*-openrc.sh`). To hide
additional files — including nested ones — add them per-repo:

```bash
# Hide a nested config the secret gate flagged
sandbox mask add --repo ~/repos/app config/prod/secrets.yaml

# See the effective mask (built-in + configured) for a repo
sandbox mask list --repo ~/repos/app
```

`mask add` records each path under `masked_paths:` in
`<repo>/.sandbox/config.yaml`; at launch those paths are mounted as empty
overlays exactly like the built-in set (and excluded from the macOS
workspace sync). Re-running `sandbox run` then passes the gate.

## Encrypted-at-rest exemption

Some committed files legitimately contain secret-shaped values that are
already encrypted — the whole point is that they're safe to store in git.
The gate recognises two such shapes and does **not** block on them, because
the agent reads only ciphertext it cannot decrypt:

- **Bitnami SealedSecret** — a hit inside a `kind: SealedSecret`
  (`apiVersion: *bitnami.com*`) document's `spec.encryptedData:` block.
- **Mozilla SOPS** — a flagged value whose column span sits *inside* a SOPS
  `ENC[AES256_GCM,...]` envelope. Containment is required: merely sharing a
  line with an envelope is not enough.

This is *not* a mask: the file stays fully readable to the agent (unlike a
`masked_paths` entry, which hides it). The exemption is scoped tightly on
purpose. It applies only to the `encryptedData` block / the value inside the
`ENC[...]` envelope itself, so a plaintext secret smuggled into the same file
still blocks the launch — a sibling `kind: Secret` document in a multi-doc
manifest, a plaintext value under the SealedSecret's `spec.template`, an
unencrypted key left beside SOPS-encrypted ones, or a plaintext value that
only shares a line with an `ENC[...]` string (e.g. in a trailing comment).
The gate cannot verify the value actually decrypts (it holds no key); `kind` +
`apiVersion` + `encryptedData` scoping (SealedSecret) and envelope containment
(SOPS) are the check.

## Accepting a reviewed false positive

Masking hides a whole file; the encrypted-at-rest exemption is automatic. Between
them sits the case of a finding that is a genuine false positive — a documented
example key, a dummy token in a fixture — where the agent still needs to read the
file. For that, a reviewer can record a per-finding **exception** instead of
masking the file or accepting every secret at launch:

```bash
sandbox exceptions add --repo ~/repos/app deploy/values.yaml:generic-api-key:155 \
    --reason "documented example key"
```

Each entry is a native betterleaks fingerprint (`relpath:rule:line`) in a
`.betterleaksignore` at the repo root — the same file, in the same format, that
the team's CI and pre-commit betterleaks runs read, so a finding cleared once is
cleared everywhere. Two properties keep this from being a workspace-authored
bypass — the thing the gate otherwise refuses to allow:

- **The sandbox counts it only on a vetted repo.** A committed ignore file
  carries no weight to the gate on its own (a plain `betterleaks` run in CI
  honors it, which is fine for a linter but not a security boundary); the
  [vetting](../how-to/vetting.md) signature over the tree — including the file —
  is its authority at launch, so accepting a finding is a reviewer's
  cryptographic sign-off, not the say-so of an untrusted workspace. `sandbox vet`
  surfaces the exceptions and requires the signer to acknowledge them.
- **The value binding rides on the signature, and only tracked content counts.**
  A native fingerprint names a location, not a value; the binding comes from
  vetting — change the value on that line and the tree is dirty (or a new HEAD),
  the repo un-vets, and re-vetting re-surfaces the exception to acknowledge. Only
  a git-tracked file (the signed content) can be excepted, so a
  gitignored/untracked local secret is never accepted even if a fingerprint for
  it is listed. A non-relative (absolute) fingerprint — which betterleaks' own
  root-file read would honor outside the gate's control — fails the scan closed.

Full workflow, hand-authoring, and how this compares to an operator-wide
`.betterleaksignore` baseline: [Accepting secret-gate false positives](../how-to/secret-exceptions.md).

A reviewed false positive is one lever; a real secret plus a **trusted internal
model** is the other. Everything the agent reads flows to its model endpoint, so
that endpoint is the system's most sensitive egress destination — an internal
model keeps the data in-boundary while an external one exports it. When a
session's endpoint is on the overlay's `trusted_inference_endpoints:` list, the
gate still scans and still shows every finding, but a would-be block becomes a
single interactive confirmation (and fails closed with no TTY, since there is no
one to ask). The confirmation is deliberate because a trusted endpoint closes
only the model channel — the agent can still act on a secret or leak it via shell
egress — so a human decides rather than the launch passing silently. See
[Trusted internal model endpoints](../how-to/secret-exceptions.md#trusted-internal-model-endpoints-a-different-lever).

## Dependency-tree exclusion

On large, deep repositories the workspace scan can spend most of its time
walking dependency trees a package manager installed locally — `node_modules`,
`.venv`, `site-packages`, `vendor`, and so on. That code is managed upstream and
holds none of *your* secrets, so the gate skips it and only pays for the files
that are yours.

The skip is **gitignore-gated**, which is the safety property: a directory is
excluded only when it is both a recognised dependency-tree name **and** actually
gitignored (a locally-installed copy). Two consequences follow:

- A directory that merely shares one of those names but is **tracked** in the
  repo — first-party code you committed — is scanned normally, because a secret
  committed there is your responsibility.
- Only dependency-tree *names* are ever skipped. An ordinary gitignored file
  like `.env`, `*.key`, or a `secrets/` directory is **never** skipped — those
  are exactly what the gate exists to catch.

A short, separate list of **known-safe artifact filenames** is skipped
*unconditionally* — whether tracked or gitignored — because their contents are
audited or derived rather than live secrets. Today that is `.secrets.baseline`, a
[detect-secrets](https://github.com/Yelp/detect-secrets) baseline: it records
SHA-1 *hashes* of already-reviewed findings for CI to diff against, so scanning
it only produces hash-shaped false positives. This list is deliberately narrow —
matching it hides a file from the gate, so it holds specific well-known artifact
names, never broad patterns — and lives in `LEAKSCAN_SKIP_PATHS` in
`lib/filesystem.sh`, changed only through source review.

### Owning betterleaks' allowlist inputs

The gate also owns the inputs betterleaks would otherwise take from the
workspace, so an untrusted repo cannot quietly allowlist its own secrets away —
with two documented exceptions: inline allow comments (honored by default,
below) and the root ignore file (noted at the end of this section). Three
channels are covered:

- **Config.** betterleaks runs under the gate's own generated config, which
  takes precedence over any `.gitleaks.toml` / `.betterleaks.toml` a workspace
  ships. The full default ruleset always applies; a repo config can only *add*
  rules, never remove them.
- **Inline comments.** `# gitleaks:allow` / `# betterleaks:allow` annotations
  are **honored by default** — a line the team has reviewed and annotated is
  suppressed, matching how the team's own CI and pre-commit betterleaks runs
  treat the same comment. This is the one workspace-authored input the gate
  trusts by default, a deliberate product choice for parity with the team's
  other tooling. The cost is a self-annotation bypass: a repo can exempt a line
  just by commenting next to the secret. An org that does not accept that sets
  `leakscan_inline_allow: off` in the overlay, which restores
  `--ignore-gitleaks-allow` and makes the gate ignore the comments. Like the
  other loosening knobs the setting is overlay-only (it only ever tightens, so
  a repo or user config cannot change it). A stricter middle ground — honoring
  inline comments only when the repo is *vetted*, exactly as the repo-root
  `.betterleaksignore` accept-list is gated (below) — was considered and
  deferred; the overlay switch is the current lever. **One place never honors
  inline comments, regardless of the knob: the explicit `.git/config` scan.**
  Honoring exists for parity with the team's own betterleaks runs, and those
  never scan `.git/config` (betterleaks excludes `.git` from directory walks);
  a `.git/config` is also not reviewed, committed, or vetting-signed content,
  and it is the one *unmaskable* finding class. So an inline `# gitleaks:allow`
  next to a credential in `.git/config` is only ever an untrusted
  self-suppression and is always ignored.
- **Fingerprint ignore file.** betterleaks' `-i` ignore path is pointed at an
  operator-owned baseline — a `.betterleaksignore` (or `.gitleaksignore`) shipped
  at the root of the **team overlay** — rather than the process working
  directory. This is the sanctioned way to accept a reviewed finding, and like
  `leakscan_extra_dep_dirs` it is operator-only, because suppressing a finding
  loosens the scan.

One gap remains, and it is worth stating plainly: betterleaks *also* always
reads a `.gitleaksignore` / `.betterleaksignore` at the root of the tree it
scans, and offers no flag to turn that off, so a workspace that commits one at
its repo root can still suppress its own findings' fingerprints. The operator
`-i` baseline is additive and cannot override it. Only the repo root is read
this way — nested ignore files are not — so a committed root ignore file is
exactly the kind of change `sandbox vet` review is meant to catch. Closing the
gap in the scanner itself (relocating or refusing such a file) is tracked as a
follow-up.

### Customising the skip list

The built-in list lives in tracked source (`LEAKSCAN_DEP_DIRS` in
`lib/filesystem.sh`), so changing it flows through code review and, where you
use it, the `sandbox vet` signing gate. Two config knobs adjust it at runtime,
split by the direction of risk — mirroring the vetting posture's "only tighten
locally" rule:

| Change | Direction | Where it's honored |
|--------|-----------|--------------------|
| **Add** dependency names (`leakscan_extra_dep_dirs:`) | looser (skips more) | **team overlay only** |
| **Disable** exclusions (`leakscan_dep_exclusions: off`) | stricter (scans everything) | any repo or user config |

Adding a name to the skip list loosens the scan — it is a way to hide a file
from the gate — so that authority is confined to the operator trust level, the
same place the vetting trust root lives. A per-repo or per-user config that sets
`leakscan_extra_dep_dirs` is **ignored**; there is no local way to make the scan
skip more. Turning exclusions off only ever makes the scan stricter, so any repo
or user may do it (`leakscan_dep_exclusions: off`, also `false`/`no`), at the
cost of walking every dependency tree and known-safe artifact. betterleaks' own
built-in `node_modules` skip is independent of all of this and always applies.

```yaml
# <overlay>/config.yaml — team-shipped, operator-controlled
leakscan_extra_dep_dirs:
  - my-vendored-libs      # a gitignored install tree specific to your stack

# <repo>/.sandbox/config.yaml or ~/.sandbox/config.yaml — local, stricter-only
leakscan_dep_exclusions: off
```

### Widening egress follows the same rule

The egress allowlist is a containment boundary, so *widening* it is the same
class of decision as loosening the leak scan: operator authority, never the
workspace's. A `<repo>/.sandbox/config.yaml` may carry an `extra_allowed_domains:`
list, but the sandbox does **not** honor it — a repo's tree is writable by the
in-sandbox agent (the party egress is meant to contain), so honoring it would let
the agent grant itself a fresh exfil destination just by committing a domain and
having the operator relaunch. The launch surfaces what the repo requested (so an
operator can grant it deliberately) but adds nothing to the allowlist. The
operator-side sources — `--allow-domain`, `~/.sandbox/config.yaml`
`extra_allowed_domains:`, and overlay profiles — are honored as before, and a
team that wants per-repo lists honored opts in with `honor_repo_allowed_domains:
true` in the overlay (overlay-only, exactly like `leakscan_extra_dep_dirs`; a repo
or user config setting it is ignored). Everything still passes the
blocked-destinations check.

The opt-in stops short of trusting the writable working tree. When it is on, the
sandbox honors only the repo's **vetted committed** list: the `extra_allowed_domains:`
in its signed `HEAD`, and only while an `agent-vetted/<sha>` attestation verifies —
read from the committed blob, never the working tree, exactly as the secret-gate
exceptions are (see "The sandbox counts it only on a vetted repo" above). The
attestation is the authority for both loosening controls. So an agent that edits
the config self-widens nothing: its edit dirties the tree (the repo goes unvetted)
or lands in a new commit the tag no longer covers, and nothing is honored until a
human re-vets — which re-surfaces the change for acknowledgment. The result gives
a team the check-it-in convenience and repo-scoped lists without handing the
contained party a lever on its own containment.
