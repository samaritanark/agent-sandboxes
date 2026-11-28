# Security Model

[← Documentation](../index.md)

For the design intent and threat model behind these controls, read
[PRINCIPLES.md](../../PRINCIPLES.md); the full v3 design and its threat model
by escape depth are in [docs/design/v3-architecture.md](../design/v3-architecture.md).

v3 defends against an agent that is rogue, mistaken, prompt-injected, or
jailbroken. It does not defend against a malicious operator, a compromised
machine, a compromised model provider, or a compromise of this tool's own
supply chain.

## Boundaries

From the agent outward:

- **The agent's microVM.** Each session's agent runs in a Kata microVM (Cloud
  Hypervisor, its own guest kernel) as uid 1000 with no capabilities, no
  privilege escalation, and guest seccomp on. Each dependency runs in a
  microVM of its own. A session started with `--runtime gvisor` (or with
  `runtime: gvisor` in your `config.yaml`) runs each of them in a gVisor
  sandbox instead, with the same user, capabilities, seccomp profile, mounts,
  and network; see [Choosing a runtime](#choosing-a-runtime).
- **The session's gateway.** The microVM's only network link goes to the
  session's gateway, in a network namespace of its own, running as an
  unprivileged user that differs per session. Every name the agent resolves and
  every connection it opens goes through it: names not on the allowlist get no
  answer, destinations on the block lists or off the allowlist are refused, and
  a packet that tries any other way is dropped and recorded (`link_drop`). An
  attacker who exploits a gateway gets that session's bindings and nothing else.
- **The appliance VM.** Sessions, `sandboxd`, the policy layer, and the
  workspace copies live in a Linux VM. Nothing of your machine is mounted into
  it. On the default drivers (vfkit, qemu) its only network is `sandbox netd`
  on your machine, which refuses everything addressed to your machine
  (loopback, LAN address, broadcast) and fails closed when it stops.
- **Your machine.** The host binary talks to the VM over SSH with a pinned host
  key, and treats everything that comes back as untrusted: audit records are
  validated and appended, never rewritten; workspace changes pass the sync gate.

## Choosing a runtime

Sessions run under Kata unless you choose gVisor, per session
(`sandbox run --runtime gvisor`) or as your default (`runtime: gvisor` in
`~/.sandbox/config.yaml`). A repository's own `.sandbox/config.yaml` cannot
choose it, and a session never falls back from one to the other. The banner and
the audit trail (`session_requested`) record which one a session used.

| | Kata (default) | gVisor |
|---|---|---|
| Between the agent and the appliance VM's kernel | a hardware-virtualized guest with its own Linux kernel | gVisor's user-space kernel (the sentry), itself confined by seccomp to a limited set of the VM kernel's system calls |
| Between two sessions | separate VMs | separate gVisor sandboxes on the same kernel |
| An escape to the appliance VM needs | a guest kernel exploit, then a Cloud Hypervisor (or KVM) escape | a sentry exploit, then an exploit of the VM kernel through the calls the sentry may make |

Everything else is the same under both: the agent runs as uid 1000 with no
capabilities and no privilege escalation, the default seccomp profile applies to
it (gVisor enforces it in the sentry), its only network link goes to the
session's gateway (gVisor's own network stack sends its packets over the same
link, and the gateway enforces egress the same way), and the appliance VM,
`sandbox netd`, the credential broker, and the sync gate stand behind it either
way. v2 ran every session under gVisor, without the appliance VM's boundary.

Neither runtime is recommended over the other. [Kata or gVisor](../how-to/runtimes.md)
covers why one might choose each, and what changes in use.

## Credential brokering

The agent never holds a real credential. A session's credentials (the agent's
login, profile secrets with a binding, `--infra-token`, opencode's key) are
**bindings**: the agent's variable or file holds a placeholder, and the session's
gateway puts the real value into requests to the hosts the binding names, in the
way it names (a bearer token, basic auth, a header, a query parameter).

- A placeholder sent anywhere else is refused (`credential_misuse`).
- A request to a bound host that carries a credential of its own instead of the
  placeholder is refused (`credential_missing`). A request that carries no
  credential at all is relayed as it is (clients make unauthenticated calls to
  the same hosts).
- Responses are scanned for the real value, in its common encodings, and it is
  replaced by the placeholder before the agent sees it
  (`credential_reflection`).
- `TRACE` and `TRACK` are refused on every intercepted host, as are git pushes
  and package-registry writes by the [org baseline](../how-to/egress-rules.md).
- Per-credential rate limits and quotas apply.

Credentials are stored in the VM's broker store, each sealed (AES-256-GCM) with a
key that is made on your machine, kept in its keychain (or a 0600 file on
Linux), and given to the VM only in memory. Each secret's binding is sealed with
its value, so the VM can use a value only as it was bound on your machine. Values
are decrypted only by short-lived helper processes, straight into the gateway.

The host pushes a launch's secrets only after checking that your command line
or profiles name them. A secret with no binding is withheld; one marked
`--allow-readable` is given to the agent as a file and recorded
(`secret_readable`). See [Secrets](../how-to/secrets.md) and
[Onboarding agents](../how-to/onboarding-agents.md).

Brokering stops credential **theft**, not credential **use**: the agent can still
act with a bound credential toward its bound hosts, within the L7 rules. Tiers,
bindings, and L7 rules bound what that use can do.

## Agent history and configuration

An agent's configuration is copied into each session as a writable copy and
discarded at the end, so an agent cannot plant a setting or hook that a later
session runs. Its conversation history is kept per agent, tier, and repository
set, and never crosses tiers. Sessions of the same agent on the same repositories
at the same tier share that history and are one trust domain for it: a
conversation can carry an injected instruction from one session to the next,
which is the cost of the agent's own `/resume`.

## The sync gate

The agent edits a copy of your repository in the VM. Its changes reach your
checkout only through the sync gate on your machine, which holds back anything
that could run code there or change how git behaves (git config and hooks,
filters, submodules, executable bits on such files, and the like) for you to
review with `sandbox sync review`. The agent never writes your checkout
directly; the host applies what passes the gate. See [Architecture](architecture.md#workspace-sync).

## Teardown

A session ends when you stop it, when its terminal has been detached for two
minutes, or, for `--keep-alive`, after 24 hours idle or 7 days. Its microVMs,
gateway, credentials in memory, readable-secret files, and configuration copy go
with it. `sandboxd` journals each resource before it creates it, so a crash or
reboot of the VM ends every session it cannot vouch for at the next start.

## Accepted risks

- **Root in the appliance VM** (a microVM escape that also escapes Kata, or a
  gVisor escape for a session that runs under gVisor) can
  read the broker store and the brokers' memory: every onboarded agent login,
  the secrets pushed for running sessions, and the other sessions' workspace
  copies. It cannot reach your machine's files, processes, or network services
  beyond the SSH channel and the sync, and it cannot plant credentials on your
  machine: nothing flows from the VM into your keychain or secret store.
- **Audit integrity against VM root is not claimed.** Sequence numbers make
  records deleted before the pull show up as a gap; they cannot stop an
  attacker who already holds VM root from writing false records.
- **Passthrough destinations are not inspected.** A host you allow with no
  binding and no L7 rule is passed through after the name check; it carries no
  brokered credential, but the agent can send it what it reads.
- **The working tree is shared.** Sessions on the same repository, and you, read
  what an agent writes there; the sync gate protects your machine, not your
  review of the content.

## Workspace gates

- **Filesystem masks:** `.env`, `.npmrc`, `clouds.yaml`, and any
  `kubeconfig`/`.kube/` in a workspace are covered in the agent's view, and
  `.git/hooks`, `.vscode`, `.idea`, and `.devcontainer` are read-only to it.
  Read-only *files* (`.git/config`, `.gitmodules`) are not yet enforced inside
  the microVM; the sync gate holds back any change to them either way.
- **Secret gate:** before every tier 2 and 3 launch each `--repo` is scanned
  with [betterleaks](https://github.com/betterleaks/betterleaks), which ships
  in the appliance image. A secret found in a file the mask would **not** hide
  aborts the launch; the error names the path and gives a `sandbox mask add`
  command to hide it (see [Extending the mask](#extending-the-mask)). The scan
  covers your tracked and untracked files but skips gitignored dependency trees
  (`node_modules`, `.venv`, `vendor`, ...; see
  [Dependency-tree exclusion](#dependency-tree-exclusion)).
  `--i-accept-unmasked-secrets` prints the findings and launches anyway. Values
  **encrypted at rest** are exempt (a hit inside a Bitnami SealedSecret's
  `spec.encryptedData` or a Mozilla SOPS `ENC[...]` envelope; see
  [Encrypted-at-rest exemption](#encrypted-at-rest-exemption)). A genuine false
  positive can be recorded as an exception the gate honors only once the repo
  is vetted (see [Accepting a reviewed false positive](#accepting-a-reviewed-false-positive)).
- **Vetting:** see [Vetting](../how-to/vetting.md).

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

**A mask hides the working copy, not git history.** The overlay covers the
working-tree path only, and the repo is mounted into the sandbox *including*
`.git`. So if a masked path was ever committed, the content still lives in the
object store, and the agent — which the model treats as adversarial — can
recover it (`git show <rev>:<path>`, `git cat-file`, or a `git worktree` / fresh
checkout elsewhere in the writable workspace, none of which the overlay covers).
`mask add` warns when the target is in git — tracked, or committed and since
removed, or living only on another branch — for exactly this reason. Masking
is the right tool for **untracked** working-copy secrets — a local `.env`, a
`kubeconfig`, `.kube/`, an `*-openrc.sh` you never committed. For a secret that
is already committed, masking is not a containment boundary: rotate it, or scrub
it from history, and treat the exposure as real.

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

- **The sandbox counts it only on a vetted repo.** An ignore file carries no
  weight to the gate on its own (a plain `betterleaks` run in CI honors it, which
  is fine for a linter but not a security boundary); a [vetting](../how-to/vetting.md)
  attestation on the repo is its authority at launch, so accepting a finding rests
  on a reviewer's cryptographic sign-off, not the say-so of an untrusted workspace.
  `sandbox vet` surfaces the exceptions and requires the signer to acknowledge them.
  By default the gate reads the honored list from the **working-copy** ignore file
  (parity with the team's CI/pre-commit runs); an operator who wants every honored
  entry to be one the signature literally covers — so drift can introduce nothing —
  sets `vetting_exceptions_from_commit: true`, and the gate then reads only the
  attested commit's blob. Either way an *unvetted* repo's list is ignored outright
  — unless an operator launches it with `--i-accept-unvetted-repo`, which accepts
  everything about the repo (its working-copy exceptions included), exactly as
  accepting drift does on a vetted repo. That override is audited and per-launch,
  and an org can disable it entirely with `vetting_forbid_unvetted_override: true`,
  which also removes this way of honoring an unvetted repo's list.
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
read from the committed blob, never the working tree. (Egress widening is
committed-only with no working-copy option, unlike the secret-gate exceptions
above, whose default source is the working copy — self-granting an exfil host is
a sharper lever than clearing a reviewed false-positive, so it stays anchored to
the signature.) The attestation is the authority for both loosening controls. So an agent that edits
the config self-widens nothing: its edit dirties the tree (the repo goes unvetted)
or lands in a new commit the tag no longer covers, and nothing is honored until a
human re-vets — which re-surfaces the change for acknowledgment. The result gives
a team the check-it-in convenience and repo-scoped lists without handing the
contained party a lever on its own containment.
