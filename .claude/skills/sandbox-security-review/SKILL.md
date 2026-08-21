---
name: sandbox-security-review
description: >
  Security-review the current branch's changes for THIS repo (agent-sandboxes),
  using its real threat model — operator trusted, in-sandbox agent adversarial —
  instead of a generic web-app vuln checklist. Use in place of the built-in
  /security-review whenever reviewing changes to bin/sandbox, lib/, setup/,
  lima/, docker/, manifests/, the security-bearing docs (PRINCIPLES.md,
  SECURITY.md, docs/explanation/security-model.md), or the review harness itself
  (.claude/skills/ and the .gitignore/masks that govern it). Checks containment,
  egress-evasion, audit/forensic integrity, credential lifecycle across ALL
  termination paths, gate integrity, and the truthfulness of security claims —
  and verifies platform behavior, not just the diff text.
---

# Sandbox security review

You are a senior security engineer reviewing changes to **agent-sandboxes**, a
tool that runs an AI agent inside a contained pod and audits what it does. The
product's security *is* its containment, egress, credential-isolation, and audit
model — not a request/response attack surface. Review accordingly.

## Why this exists (read once)

The built-in `/security-review` is a generic web-app scanner: it hunts SQLi /
XSS / SSRF / deserialization, and it is explicitly told to **skip documentation
files, skip anything DoS-adjacent, and skip "lack of audit logs."** For this
repo those exclusions delete the real finding classes. A recent external review
raised a HIGH that lived entirely in `PRINCIPLES.md` (a false credential-
revocation claim), plus MEDIUMs about audit evidence being lost on eviction and
eviction blast-radius — none of which the generic harness could ever surface.
This skill exists to review the surface that actually matters here, and to catch
those classes before an external reviewer does.

## The threat model (do not re-derive it — load it)

Read, don't restate: **`PRINCIPLES.md` (§ Threat model, § Tier model, §
Credential isolation, § Default-deny egress, § Filesystem isolation, § Never
permitted regardless of tier)**, **`SECURITY.md` (§ Scope)**, and
**`docs/explanation/security-model.md`**. In one line:

> The operator running the CLI is **trusted**. The adversary is the **AI agent
> running inside the sandbox pod** (driven by a model mistake, prompt injection,
> or jailbreak). The tool's job is to contain that agent, gate what reaches it,
> and produce a trustworthy record of what it did.

Consequences for weighting findings:
- **Env vars, CLI flags, and operator config are TRUSTED inputs**, not attack
  vectors. A finding that depends on the operator supplying a hostile flag is
  out of scope (see PRINCIPLES.md § "Never permitted"). Do not report it.
- **The in-sandbox agent controls:** the contents of the workspace/repo mount
  and the agent-home mount (both writable), its own memory/CPU/disk usage, the
  syscalls it attempts, the network connections it attempts, and anything it can
  write to a file the host later reads. Weight a finding by what *this* party can
  do — escape, exfiltrate, evade egress, or defeat/forge the audit — not by what
  a careless operator could do.
- **Out of scope** (same as `SECURITY.md`): host-root attacks, third-party CVEs
  (gVisor/Cilium/k3s/agent binaries), and operator self-sabotage.

## The security invariants — check the diff against every relevant one

For each invariant, ask: *does this diff weaken it, rely on a false assumption
about it, or add a path that bypasses it?* These are the properties an external
reviewer will test.

**1. Containment / isolation.** Pods run gVisor, non-root uid, all caps dropped,
no privilege escalation, `automountServiceAccountToken: false`. Any new mount,
hostPath, securityContext change, volume, or symlink-reachable write must not
give the agent a path onto the host or into another pod. Check mount *paths* and
`readOnly`, not just that a mount exists.

**2. Egress cannot be evaded or self-widened.** Default-deny via Cilium
`policyEnforcementMode: always` + per-session policy. The allowlist is a
containment boundary, so **widening it is operator authority only** — never
honored from the agent-writable working tree (see security-model.md § "Widening
egress follows the same rule"). Any new allowlist input, DNS path, or policy
change: can the contained agent grant itself a destination? Does everything
still pass the blocked-destinations check?

**3. The audit / egress-log channel is tamper-evident and un-silenceable.** The
Hubble flow export is the network audit record; the session audit log records
what happened. The agent must not be able to **silence, starve, evict, OOM, or
forge** either one. Specifically:
   - Any component on the audit path (hubble-relay, cilium, the export step)
     must not be the first eviction/OOM victim the agent can trigger — check QoS
     class and resource requests on **both the memory and the ephemeral-storage
     axes** (they rank differently; QoS does not rank disk).
   - Any forensic/state artifact written to an **agent-writable location**
     (workspace, agent-home) is **not evidence** — the agent can forge or delete
     it. A trustworthy signal must derive from **operator-side state the agent
     cannot reach** (e.g. `session.json` fields, host-side files). Flag any code
     or doc that treats an agent-writable artifact as authoritative.

**4. Credentials are isolated on entry AND revoked on EVERY exit path.**
   - *Entry:* creds reach the pod only as intended (OAuth, or session-scoped K8s
     Secrets); no host credential, kubeconfig, or token leaks in that
     `--infra-*` didn't explicitly pass. The mask hides workspace secrets.
   - *Exit:* infra tokens / kubeconfigs / API-key Secrets must be revoked or
     deleted on **normal stop, crash, timeout, OOM, node-pressure eviction, and
     operator kill** — enumerate the paths and check each. **Kubernetes
     ownerReference GC fires on DELETION of the owner pod, NOT on the pod
     terminating or being evicted** — an Evicted pod object lingers, so GC does
     not cascade. Do not accept "owned by the pod, so it's cleaned up" without
     tracing which paths actually *delete* the pod.

**5. Gate integrity (secret gate, vetting gate).** Both must **fail closed** if
their tooling is missing. Neither may honor a **workspace-authored** bypass: the
in-sandbox agent writes the repo tree, so anything that loosens a control
(allowlist entries, leak-scan skips, accepted-secret exceptions, inline allow
comments) must rest on **operator/overlay authority or a vetting signature**,
read from committed/attested content — never from the working copy in a way the
contained agent could self-serve. See security-model.md §§ "Owning betterleaks'
allowlist inputs" and "Customising the skip list."

   *The review harness is itself a workspace-authored surface.* `.claude/skills/`
   is tracked in the repo and is **not** masked (`lib/filesystem.sh`
   `MASKED_FILE_PATHS`/`MASKED_DIR_PATH` omit `.claude`), so on tier 2/3 the
   in-sandbox agent has read-write access to `.claude/skills/**` — including this
   file. Its content loads as **instructions into the operator's host-side agent
   session**, outside the sandbox, so it attacks the review process rather than
   having to survive containment. Human PR review is the control, but treat any
   change under `.claude/skills/**` (and the `.gitignore` rules that ship it) as
   security-bearing and review it with the same lens as `lib/`. Consider whether
   it should be masked. Note also that `.claude/skills/**` is now *tracked*
   (the `.gitignore` re-includes it), so a file the in-sandbox agent plants there
   is swept into a `git add -A` — the review harness can be **propagated to other
   operators' host sessions via an accidental commit**, not just read in the
   current one. The residual control is human PR review plus, optionally, a
   pre-commit guard that rejects `.claude/skills/**` changes not authored
   host-side.

**6. Security claims must be TRUE.** Every assertion in a doc, code comment, or
operator-facing message that tells the operator a control holds — "credentials
are revoked," "the pod owns the Secret," "the breadcrumb records the eviction,"
"this makes it no longer the first victim" — is in scope, **including in Markdown
files.** A false assurance is worse than a silent gap because the operator relies
on it. Verify the claim against actual platform behavior. If you cannot verify
it, flag the claim as unverified rather than passing it.

**7. Lifecycle / eviction edge cases don't silently drop 1–5.** Image pinning,
eviction thresholds, GC settings, preStop hooks, termination grace, resume/
recreate paths — trace what happens to containment, credential revocation, and
the audit record when the path is abnormal. Blast-radius and eviction *tuning*
are in scope here (they are NOT mere DoS) **when getting them wrong disables a
security control or widens which sessions are affected.** Size eviction/GC
settings against **k3s's compiled-in defaults, not vanilla kubelet's** — they
differ: k3s overrides `EvictionHard` (to `imagefs.available<5%,nodefs.available<5%`,
dropping the vanilla `memory.available<100Mi` threshold entirely) and sets a 10%
`EvictionMinimumReclaim` (vanilla defaults to 0). The 5-minute
`evictionPressureTransitionPeriod`, by contrast, is the **vanilla upstream
default**, not a k3s override — don't cite it as a k3s difference. Confirm each
against the kubelet args on a real node at the pinned tag; a misattributed
mechanism is itself an invariant-6 claim.

## What to report vs. skip (this repo's rules, overriding the generic ones)

**DO report** (the generic skill wrongly suppresses these):
- Security-assurance falsehoods in **any** file, Markdown included (invariant 6).
- **Audit / anti-forensics** gaps the in-sandbox agent can trigger — silencing,
  starving, evicting, or forging the flow log or audit record (invariant 3).
- **Eviction / lifecycle blast-radius** that defeats containment, revocation, or
  the audit record, or widens the set of affected sessions (invariant 7).
- Credential survival across an abnormal termination path (invariant 4).
- Any workspace-authored bypass of a gate or the egress boundary (invariants 2, 5).

**Still skip** (genuinely out of scope): pure availability DoS with **no**
control-defeat; third-party/upstream CVEs; hardening nitpicks and style; findings
that require host root or a hostile operator flag; resource-leak/FD nits;
log-spoofing; theoretical races. Match the generic skill's exclusions *only* for
these — not for the DO-report classes above.

## Method — verify behavior, not just diff text

Most findings here are "the code does X but the platform behaves Y," invisible in
a static read. So:
- **Render the real artifact.** For manifest/policy changes, render the actual
  pod/CNP YAML (source `lib/manifest.sh`, stub the env-sensitive helpers as
  `tests/test-resume.sh` does) and inspect mount paths, `readOnly`, resource
  requests/limits, securityContext, and any lifecycle hook's real destination.
- **Reason from platform semantics.** k8s GC/eviction/QoS, Cilium policy
  identity, gVisor's syscall surface. When a claim rides on a compiled-in default,
  check it at the **pinned version** (`setup/versions.sh`).
- **Trace every exit path**, not the happy path — that is where revocation and
  audit gaps live.
- **Follow claims and prescribed remediations into UNCHANGED code — do not stop
  at the diff.** The two findings this skill missed on its first run both lived
  outside the diff: a "teardown runs" claim whose *other* trigger paths (a killed
  CLI with no signal trap) were never traced, and a "run `sandbox stop`"
  remediation whose target (`cmd_stop`) was never opened to check it records the
  eviction. When a change adds/corrects a claim or tells the operator to run a
  command, `grep` for the mechanism (the trap, the GC owner-delete, the mask) and
  **open the command it names** before you believe it. Prove absences by searching
  the whole tree, not the hunk.
- **Never "clear" an invariant from the changed lines alone.** "The diff's new
  code looks fine" is not "the invariant holds across every path an operator now
  travels." Verify the steady state the change produces, not just the delta.
- **Re-audit the RESIDUAL claims and the tests that guard them.** A change that is
  a genuine improvement can still leave a neighbouring assertion false (transcript
  "persists regardless"), or ship a test that asserts a weaker property than the
  bug needs (a breadcrumb under *any* mount, when `/tmp` is an `emptyDir` mount).
  Read the guarding test as adversarially as the code.
- **Review the harness's own introduction.** When the diff adds or edits
  `.claude/skills/**`, this file, the `.gitignore` rules that ship it, or the
  masks in `lib/filesystem.sh`, turn every invariant on *those* changes too.
- **Consult the past-finding library** below and check the diff for analogues.

**Severity calibration.** A security assurance that is false in a state the
operator can actually occupy **without having opted into the risk** is not LOW —
weight it by whether the operator consented to the exposure, not by how narrow the
trigger looks. (A `--keep-alive` gap is an accepted trade-off; a plain session
orphaning its credentials because the terminal closed is not.)

## Past findings — check every diff for a recurrence of these

These have actually been raised on this repo. The *classes* recur; hunt the next
instance.
- **False "credentials revoked on eviction" claim** — ownerReference GC doesn't
  fire on eviction; the doc/comment said it did. (Invariants 4, 6.)
- **Audit breadcrumb written to an ephemeral or agent-writable path** — lost on
  pod death, and forgeable by the agent, so it isn't evidence. (Invariant 3.)
- **Audit channel as first eviction/OOM victim** — hubble-relay BestEffort (no
  resource requests) let the agent starve the egress log; disk-axis ranking is
  separate from memory-axis. (Invariant 3.)
- **Eviction tuning sized against vanilla kubelet, not k3s** — wrong thresholds /
  minimum-reclaim widened the blast radius across sessions. (Invariant 7.)
- **Teardown swallowing revocation reminders / asserting false success** — a
  failure path that hides the "revoke this token" warning or claims a clean
  teardown that didn't happen. (Invariants 4, 6.)
- **Workspace-authored control loosening** — repo-tree `extra_allowed_domains`,
  leak-scan skips, or inline allow comments honored without operator/vetting
  authority. (Invariants 2, 5.)
- **Sudo/PATH and cross-platform gaps** — a control that silently no-ops on one
  platform (macOS/lima vs Linux/WSL) or under a restricted `sudo secure_path`.
- **Credential survival via a killed CLI, not just eviction** — teardown that runs
  only on normal exit / pod-eviction leaves a non-`--keep-alive` session's pod and
  Secrets live when the `sandbox` process itself is signalled or killed (closed
  terminal, dropped ssh, suspend, `kill`). Prove the trap exists — `grep` the
  whole CLI — don't assume "the connection falls through to teardown." (Invariants 4, 6.)
- **Prescribed remediation leaves no durable record** — a doc says "run `sandbox
  stop`" to fix an abnormal ending, but `cmd_stop` stamps `end_time` at stop time
  and records no reason, so the remediated `session.json` is indistinguishable
  from a clean teardown and `sandbox status`/`list` can't surface it. Trace the
  remediation, not just the claim. (Invariants 3, 4, 6.)
- **Test asserts a weaker property than the bug requires** — e.g. a breadcrumb
  under *any* `mountPath` passes even for `/tmp` (`emptyDir`, ephemeral); the test
  must assert the backing volume kind (`hostPath`). Read guarding tests
  adversarially. (Invariants 3, 7.)
- **The review harness as an attack surface** — `.claude/skills/**` is tracked and
  agent-writable on tier 2/3 and loads host-side as instructions; a change under
  it (or the `.gitignore`/masks that govern it) is security-bearing. (Invariant 5.)

## Execution

Prefer a fan-out, one worker per invariant group, each carrying the threat model
and the verify-behavior method, then adversarially verify each candidate before
reporting (a workflow or parallel sub-agents). For a small diff a single careful
pass is fine. Either way:
1. Read the threat-model docs above and the full branch diff (code **and**
   security-bearing docs/comments).
2. For each invariant relevant to the changed files, look for weakening,
   false-assumption, or bypass — rendering artifacts and reasoning from platform
   behavior, not just reading the diff.
3. Adversarially verify each candidate: can the *in-sandbox agent* actually
   trigger it? Is the platform claim actually true at the pinned version? Drop
   anything you cannot stand behind at ≥80% confidence.

## Output

Markdown report. For each finding: `file:line`, severity (HIGH / MEDIUM / LOW),
the invariant number it violates, a one-line description, a concrete exploit or
failure scenario **from the in-sandbox agent's position** (or, for invariant 6,
the false claim and the true behavior), and a fix recommendation. Rank most
severe first. If nothing survives verification, say so plainly — but only after
checking the invariants and the past-finding library, not by default.
