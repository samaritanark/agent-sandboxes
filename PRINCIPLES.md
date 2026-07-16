# Principles

This document explains the design intent behind the Agent Sandbox: what
it defends against, how it expects to be used, and what it deliberately
will not do for you. It is not an organizational policy — adopters of
this tool are expected to write their own policy that references these
principles and adds whatever procedural detail their environment needs
(rotation schedules, approval flows, audit retention, incident response,
onboarding requirements). The goal here is to capture the assumptions
the tool is built on so those policies can be informed.

If you operate this sandbox for others, read this end-to-end before your
first session. If you only use it for yourself, at least skim
"Accountability" and "Never permitted" — the rest will make more sense
the first time something surprises you.

## Accountability

**You are responsible for everything an agent does on your behalf.** An
AI agent acts with the access you give it and runs under your identity.
If an agent commits code, modifies infrastructure, deletes files, or
leaks credentials, the responsibility is yours — not the agent's, not
the LLM provider's, not this sandboxing tool's.

**Treat every agent as a junior developer or junior operator.** Agents
can be fast and productive, but they lack the context, judgment, and
institutional knowledge that come from experience on your specific
systems. They make confident mistakes. They produce plausible-looking
code that is subtly wrong. They take the most literal interpretation of
a request and miss the intent. You would not merge a junior's pull
request without carefully reviewing every change — apply the same
standard to agent-produced work.

Sandboxing, network controls, and filesystem masking reduce risk. They
do not eliminate it. They are not a substitute for understanding what
you are asking the agent to do and reviewing what it produces.

Before every session, ask yourself:

- Do I understand what I'm giving this agent access to?
- Am I prepared to review its output before it goes anywhere?
- If something goes wrong, can I explain what happened and the choices
  I made?

If the answer to any of these is no, stop and ask for help.

## Core principles

1. **Agents are untrusted by default.** Every session runs inside a
   gVisor-isolated pod with a default-deny egress policy. The tool does
   not rely on agent-side configuration or cooperative behavior for any
   security property.

2. **Least privilege.** A session receives only the access required for
   its tier. Access is not granted preemptively in case it might be
   needed.

3. **Humans approve, agents execute.** Agents may propose changes; a
   human reviews and approves before anything is pushed, applied, or
   deployed. Fully autonomous operation is out of scope for this tool.

4. **Isolation is mandatory.** This tool exists because running an
   agent directly on a host machine is the wrong default. There is no
   "skip the sandbox just this once" mode.

5. **Production is out of scope by design.** The tier model and
   defaults assume non-production use. Pointing the sandbox at
   production systems is an operator decision; if you do it, you accept
   that the tier abstraction was not designed to protect production and
   you are responsible for whatever additional controls you put around
   it.

## Threat model

**Defends against:**

- A rogue agent action triggered by a model mistake, hallucination, or
  prompt injection — destructive shell commands, exfiltration attempts
  to arbitrary domains, attempts to read host credentials.
- A jailbreak that makes the agent ignore its system prompt — the
  sandbox enforces controls at the kernel, network, and filesystem
  layer, so agent-side persuasion cannot weaken them.
- A subtly wrong agent suggestion that an inattentive operator might
  accept — making the blast radius of a mistake one pod, not one host.
- Workspace-resident secrets the operator forgot about — masked file
  paths hide `.env`, `.npmrc`, kubeconfigs, OpenStack RC files, etc.

**Does not defend against:**

- An operator with malicious intent who has shell access to the host —
  the sandbox runs as your user; you can stop it, dump its state, or
  not use it.
- Compromise of the host machine itself — if your laptop is owned, so
  are your sandbox sessions.
- Compromise of the LLM provider or the model weights — the sandbox
  cannot tell a "good" instruction stream from a poisoned one.
- Supply-chain compromise of this tool, its container images, gVisor,
  or Cilium — keep your install current and source from a trusted
  upstream.
- An operator who deliberately weakens the configuration ("just add
  the production cluster to the allowlist for this one task") — the
  tool will not stop you, but you accept the consequences.

The tier model and credential rules below are calibrated against the
first list, not the second.

## Tier model

Three tiers, lowest-privilege by default:

- **Tier 1 — ephemeral.** Disposable workspace (`emptyDir`), agent
  domains only. For exploratory work, learning a tool, throwaway
  experiments. Use when no real codebase is involved.

- **Tier 2 — project.** A host repo (or several) mounted read-write,
  plus package-registry and GitHub egress. For real development work
  against your own code. No cloud or infrastructure access.

- **Tier 3 — infrastructure.** Tier 2 plus operator-supplied,
  session-scoped credentials for a specific non-production cluster or
  cloud project. Never `cluster-admin`, never an unscoped cloud
  account, never production. `apply` / `deploy` operations are out of
  scope from inside the sandbox — the agent plans, you execute
  outside.

When in doubt, start at the lower tier. Escalation is a deliberate
operator decision, not a default. See the README for the concrete
allowlist contents and CLI flags per tier.

## Credential isolation

Five rules govern what credentials can enter the sandbox:

1. **Agents never hold long-lived API keys directly.** Provider
   credentials (LLM keys, cloud tokens) are injected at runtime via
   Kubernetes Secrets keyed to the session, not baked into images,
   config files, or shell rcs that the agent could read.

2. **Infrastructure credentials are session-scoped or absent.** If a
   Tier 3 session needs cluster or cloud access, the credentials are
   provisioned for that session, scoped to the minimum required role
   for a specific non-production target, and revoked when the session
   ends.

   The same rule applies to user-managed secrets (Jira PATs, Gitea
   tokens, internal API keys). They live in the host-side store at
   `~/.sandbox/secrets/` (mode 0600) and only enter the cluster as a
   session-scoped Secret when a profile declares them — created at
   launch, deleted at teardown. See `sandbox secret --help` and
   `docs/how-to/secrets.md`.

3. **Auth-provider sessions never enter the sandbox.** If your
   organization uses Teleport, Okta, AWS SSO, GCP IAM exec plugins,
   Azure CLI auth, kubelogin, or any similar interactive auth tool,
   none of them should be runnable inside the sandbox. Their host-side
   state (`~/.tsh/`, `~/.aws/`, exec credential plugins, etc.) is
   never mounted or forwarded. If a Tier 3 session needs API access,
   produce a static kubeconfig or scoped token on the host first and
   pass it in via `--infra-kubeconfig` / `--infra-token`; see
   `examples/teleport/` for one such recipe.

4. **SSH keys, SSH agent sockets, and Git credential helpers stay on
   the host.** `~/.ssh/`, `SSH_AUTH_SOCK`, and host credential helpers
   are never forwarded. `~/.gitconfig` is mounted read-only so the
   agent can produce commits with your identity but cannot rewrite it.

5. **Git host CLI auth is ephemeral.** If you `gh auth login` or the
   equivalent inside a session, the credentials live and die with that
   session — they are not persisted across sessions.

## Default-deny egress

Every session starts with all outbound network access denied. Cilium
FQDN policy then opens exactly the domains required by the agent and
tier, plus any explicit additions:

- Per-tier allowlists are defined in `lib/tier.sh` and `lib/agents.sh`
  and shipped as conservative defaults.
- Per-invocation additions: `--allow-domain <DOMAIN>` (repeatable).
- Persistent operator-supplied extras: `~/.sandbox/config.yaml`,
  `SANDBOX_EXTRA_ALLOWED_DOMAINS`, or `<repo>/.sandbox/config.yaml`
  (loaded for each `--repo`). See `docs/how-to/persistent-domains.md`.
  The per-repo source's additions are banner-printed on every
  session start so a slipped-in domain stays visible to the operator
  launching the session.

Every addition — flag-based, env-based, or file-based — passes through
the blocked-destinations check (`config/blocked-destinations.yaml`). If
an overlay is configured (`$SANDBOX_OVERLAY` or the `overlay:` key in
`~/.sandbox/config.yaml`), the overlay's
`blocked-destinations.yaml` is unioned with the org file at check time.
**Overlays are additive only on the safety side** — they can extend the
block list and narrow profile allow-lists, but nothing in an overlay
can remove an org-level block or weaken the tier model.
Operators should populate that file with hosts that must never be
reachable from a sandbox: production environment hostnames, internal
SSO / identity-provider endpoints, communication platforms, email
relays. The defaults that ship cover the obvious universal cases
(email, Slack, Teams, paste sites); your organization adds the rest.

## Filesystem isolation

The sandbox enforces three filesystem rules:

1. **The workspace is the only writable host path** the agent sees.
   Tier 1 gets an `emptyDir`; Tier 2/3 mount your repository
   read-write at `/workspace` (or `/workspace/<basename>` for
   multi-repo). Nothing else from the host is writable from inside the
   pod. (On macOS the agent writes a VM-local copy that syncs back to
   your repo, rather than the repo directly — same guarantee, see
   "macOS workspace sync" in the README. The agent still sees exactly
   one writable workspace and nothing else of the host; the sync runs
   outside the pod.)

2. **Sensitive paths in the workspace are masked**, even though the
   workspace itself is mounted from the host. The following are
   replaced with empty overlays before the agent can read them:

   | Path                           | Treatment                                       |
   | ------------------------------ | ----------------------------------------------- |
   | `.env`, `.env.*`               | Hidden (empty file overlay)                     |
   | `.npmrc`                       | Hidden (empty file overlay)                     |
   | `*-openrc.sh`, `clouds.yaml`   | Hidden (empty file overlay)                     |
   | `kubeconfig`, `.kube/`         | Hidden (empty file / emptyDir)                  |
   | `.git/config`                  | Read-only                                       |
   | `.gitmodules`                  | Read-only                                       |
   | `.vscode/`, `.idea/`           | Read-only                                       |
   | `.devcontainer/`               | Read-only                                       |

   The built-in set is extensible per-repo: `sandbox mask add --repo
   <PATH> <RELPATH>` records additional paths (including nested ones)
   under `masked_paths:` in `<repo>/.sandbox/config.yaml`, and they are
   masked at launch exactly like the built-in set.

   The masking is defense in depth — operators should also confirm
   their workspace does not contain real secrets before launch. The
   `sandbox check` command surfaces what would be masked. As a backstop,
   every Tier 2/3 launch is **gated** on a betterleaks scan of each
   `--repo`: a secret in a file the mask would not hide refuses the
   launch (fail closed; betterleaks is required), naming the path and the
   `sandbox mask add` command to hide it. The operator can override with
   `--i-accept-unmasked-secrets`, which prints the findings and proceeds —
   an explicit, audited acceptance of the risk.

3. **Nothing else on the host is visible.** Other repositories, your
   home directory, system directories, the container runtime socket,
   and other sandbox sessions are not reachable from inside the pod.

## Repo vetting

Some organizations require that an agent only touch a repository that has
been through an approval workflow. The sandbox provides the hook for that
policy — an optional launch gate that checks each Tier 2/3 `--repo` for a
signed attestation that a trusted reviewer cleared its current `HEAD` for
agent use. This is the kind of "approval flow" the introduction says
adopters layer on top; the tool supplies the mechanism, your policy decides
whether and how to require it.

Three things keep it honest:

1. **The trust decision lives with the operator, not the repo.** The repo
   carries only the artifact — a signed git tag. Whether vetting is
   *required*, and *whose* signatures count, are operator-side settings
   (`vetting:` and signer trust roots — the operator's own in
   `~/.sandbox/config.yaml`, and/or a reviewer list shipped by a team overlay
   the operator links and pins). Nothing
   a workspace author can commit weakens the gate, because a repo-resident
   flag would be a cooperative-behavior control, and no security property
   here depends on that (see Core principle 1). Verification runs host-side,
   before the pod starts, against the operator's signer list.

2. **An overlay may only tighten it.** A team overlay can raise the posture
   (`advisory → required`) but never relax it — the same "additive on the
   safety side" rule the block list follows.

3. **Vetted is not a substitute for the sandbox.** Vetting addresses a
   different axis — repo-borne prompt-injection payloads, org compliance —
   than isolation. It is additive to gVisor, default-deny egress, and
   masking, never a replacement. A vetted repo is not thereby cleared to run
   an agent outside a session; isolation is still mandatory (Core principle
   4). Read a "vetted" marker as "reviewed," not as "trusted enough to skip
   the controls."

See `docs/how-to/vetting.md` for setup and the `sandbox vet` workflow.

## Agent behavior expectations

The sandbox enforces what it can at the kernel, network, and
filesystem layers. Beyond that, agent behavior is shaped by the
guardrails file the operator provides to the agent (e.g. `AGENTS.md`
or `CLAUDE.md` in the workspace) and by the agent's per-session
approval prompts. The principles below are what those guardrails
should encode regardless of agent or model:

**Agents must not** — without per-invocation human approval:

- Push to remote repositories, force-push, or rewrite published
  history.
- Create, close, or comment on issues or pull requests on external
  platforms.
- Execute destructive commands (`rm -rf`, `DROP TABLE`, formatting,
  partitioning, `kill -9` on long-running services).
- Install packages from sources outside the configured allowlist.
- Modify their own guardrails, sandbox configuration, or permission
  settings.
- Spawn additional agent sessions or sub-processes that bypass
  sandbox controls.

**Agents may** — without per-invocation approval:

- Read and write within the mounted workspace.
- Run common, idempotent development tooling: linters, formatters,
  test runners, type checkers, language-specific package managers in
  their query / install / cache modes (not their publish modes).
- Create local commits on a feature branch (never `main` / `master`
  directly).
- Propose changes for human review.

**Never pre-approved**, regardless of tier:

- Push operations to any remote.
- Arbitrary network access (`curl`, `wget` to non-allowlisted hosts).
- Remote access tooling (`ssh`, `scp`, `rsync` to anywhere).
- Auth-provider clients inside the sandbox (`tsh`, exec credential
  plugins, etc. — see "Credential isolation").
- Cloud / infrastructure CLIs except in a Tier 3 session with scoped
  credentials.
- Container or runtime operations (`docker`, `podman`, `kubectl` apply
  / delete / exec).
- Terraform / Pulumi / Ansible apply equivalents.
- Anything piping arbitrary content to `sh`, `bash`, `eval`, or
  `exec`.

## Commit hygiene and review

- **Agent-produced commits must be marked.** Use a co-author trailer
  identifying the agent and model (`Co-Authored-By: Claude Code
  <noreply@anthropic.com>` or equivalent). Reviewers must be able to
  tell which commits were agent-produced. This is not optional.

- **Agents never commit directly to `main` / `master`.** All
  agent-produced work lives on a feature branch and goes through the
  same review process human-produced work does.

- **Agent-produced code gets the same review rigor as human-produced
  code, plus a few extra checks:**
  - Hallucinated imports or dependencies — packages that don't exist
    or aren't in the project's manifest.
  - Subtle logic errors hiding behind plausible-looking code.
  - Security issues — injection vulnerabilities, hardcoded values,
    overly permissive error handling.
  - Scope creep — unrequested refactoring, drive-by comment edits,
    speculative "improvements."
  - License compliance — agents can reproduce code from training data
    with incompatible licenses.

## Never permitted regardless of tier

Independent of any policy your organization layers on top, the tool's
design assumes none of the following happen. If you do them anyway,
the sandbox cannot protect you and most of this document does not
apply:

1. **Running agents against production data, systems, or
   environments.** The tier model does not distinguish prod from
   non-prod — that's your operator decision and your responsibility.
2. **Running an agent outside the sandbox** (directly on a host
   machine, in a tmux on a bastion, etc.) when the goal is anything
   other than the most trivial throwaway query.
3. **Granting an agent access to a credential store, secret manager,
   or password vault.**
4. **Mounting or forwarding interactive auth-provider state**
   (Teleport `~/.tsh/`, exec-plugin kubeconfigs as-is, SSH agent
   sockets, raw cloud-CLI session files) into the sandbox.
5. **Using an agent to interact with external parties** — sending
   emails, posting to chat platforms, opening public issues — outside
   workflows you've explicitly designed for that.
6. **Handling regulated data** (PII, PHI, etc.) inside a sandbox
   session without separate legal / compliance review.
7. **Sharing a session between people.** One operator, one session.
   Audit trails depend on it.
8. **Disabling, bypassing, or weakening sandbox controls** to make an
   agent "work better." If you find yourself doing this, the right
   move is to ask whether the task belongs in a sandbox at all.

## Audit logs

Every session produces an audit log under `~/.sandbox/logs/<session>/`
containing start/stop times, allowed-domain list, the resolved tier
and credentials path, and (for agents that support it) a copy of the
conversation transcript. Retention is the operator's responsibility;
the tool does not auto-prune.

If you observe unexpected agent behavior during a session, the
recommended sequence is: stop the session (`sandbox stop <id>`), do
not push any changes from it, preserve the audit log, and review what
happened before deciding whether any of the work is salvageable.
