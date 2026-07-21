# Accepting Secret-Gate False Positives

[← Documentation](../index.md)

Before every Tier 2/3 launch the [secret gate](../explanation/security-model.md)
scans each `--repo` with betterleaks and refuses to start if a secret lives in a
file the mask would not hide. Most of the time that is exactly what you want. But
some findings are false positives — a documented example key, a dummy token in a
test fixture, a secret shape the encrypted-at-rest exemption doesn't recognise —
and blocking on them is friction with no safety payoff.

You have three ways to get past a finding, and they are not equal:

| Approach | Effect | When it fits |
| --- | --- | --- |
| `sandbox mask add` | Hides the whole **file** from the agent (empty overlay) | The agent doesn't need to read that file at all |
| `--i-accept-unmasked-secrets` | Accepts **every** finding for one launch | Never a good habit — it's the blunt instrument this feature exists to replace |
| `sandbox exceptions add` | Accepts **one specific finding**, reviewed, and only on a vetted repo | The finding is a genuine false positive and the agent still needs the file |

This page is about the third one.

## What an exception is

An exception records a single finding as a reviewed false positive. Each entry
is a betterleaks **fingerprint**:

```
<relpath>:<rule>:<line>
deploy/values.yaml:generic-api-key:155
```

— the finding's path, its betterleaks rule, and its line. Entries live in a
`.betterleaksignore` file at the **repo root**, one fingerprint per line, with
optional `#` comments. This is betterleaks' own native ignore format, which is
the whole point: **one committed file is the single source of truth for every
scanner the team runs.** Your pre-commit hook, your CI pipeline, and the sandbox
launch gate all read the same list, so a finding a reviewer clears once stops
nagging everywhere at once instead of being re-accepted in three different
places. (If a repo already carries a `.gitleaksignore`, betterleaks reads that
too, and `sandbox exceptions` appends to it rather than starting a second file.)

Two properties keep this safe rather than a backdoor:

- **The sandbox honors it only on a vetted repo.** An ignore file means nothing
  to the *sandbox* on its own — anyone who can push to the repo (including a
  prompt-injected agent) could add a line, and a plain `betterleaks` run in CI
  honors it unconditionally, which is fine for a linting tool but not for a
  security boundary. What gives it authority *at launch* is a [vetting](vetting.md)
  attestation on the repo: accepting a finding rests on a human's cryptographic
  sign-off, and `sandbox vet` surfaces the exceptions for the signer to
  acknowledge first. By default the gate reads the list from your **working copy**
  (tracked or not), the same file your CI and pre-commit runs read — so the file
  you edit is the file that counts. An operator who wants every honored entry to
  be one the signature literally covers sets `vetting_exceptions_from_commit: true`,
  and the gate then reads only the **attested commit's** blob (an uncommitted or
  drift-added entry is not honored until a signer re-vets). Either way, on an
  unvetted repo the sandbox ignores the list and the gate blocks exactly as
  before. (More on this in
  [Integration with vetting](#integration-with-vetting-and-team-overlays).)
- **The value binding rides on the signature, not a hash.** Older exceptions
  carried a SHA-256 of the matched value so a rotated token re-blocked. A native
  betterleaks fingerprint has no hash — it names a location — so the binding
  moves to the vetting anchor instead. Change the value on that line and the tree
  is dirty (or a new HEAD): the repo stops being vetted, and re-vetting
  re-surfaces every currently-matching exception for the signer to acknowledge
  again. Accepting a line never silently blesses whatever lands there later; a
  human re-confirms.

One more boundary: the sandbox honors an exception **only for a git-tracked
file**. The vetting signature covers committed content, so a finding in a
gitignored or untracked local file (a `.env` you never committed, say) is not
part of the signed tree and is never accepted — even if a fingerprint for it
appears in the list. Those stay gated, which is correct: no one signed for them.

> **Repo-relative fingerprints only.** Entries must be repo-relative
> (`deploy/values.yaml:github-pat:1`), which is what `sandbox exceptions add`
> and `betterleaks dir .` both produce. An *absolute*-path fingerprint would be
> honored by betterleaks' unconditional root-file read but sits outside the
> gate's control, so the gate **refuses to launch** while the ignore file
> carries one — remove it and use the relative form.

## The workflow

> The vetting gate runs before the secret gate at launch, so on an unvetted
> repo under `vetting: required` you'll meet the
> [inline attest offer](vetting.md#attest-at-launch-authorized-signers) before
> the output below. That ordering is what lets steps 4-5 collapse into a single
> `sandbox run` for an authorized signer.

### 1. The gate flags a finding

```
$ sandbox run --tier 2 --repo ~/repos/app --agent claude
...
ERROR: betterleaks found secret(s) the sandbox mask will NOT hide. The
       agent would be able to read them, so the launch is refused:

    deploy/values.yaml:generic-api-key:155
        match: REDACTED

  Resolve this in one of these ways:
    - Remove or relocate the secret(s) above, or
    - Mask the file(s) ...
        sandbox mask add --repo ~/repos/app deploy/values.yaml

    - Or, if a finding is a reviewed false positive, record it as an
      exception (honored once a reviewer vets the repo — 'sandbox vet'):

        sandbox exceptions add --repo ~/repos/app deploy/values.yaml:generic-api-key:155
```

The gate hands you the exact `sandbox exceptions add` command, so the common
path is copy-paste.

### 2. Review, then record it

Look at the finding and satisfy yourself it really is a false positive. Then:

```bash
sandbox exceptions add --repo ~/repos/app \
    deploy/values.yaml:generic-api-key:155 \
    --reason "documented example key from upstream docs"
```

`add` re-scans to confirm the finding actually exists in the current tree (you
cannot pre-accept something the scanner doesn't flag). The `--reason` is optional
and is written as a `#` comment above the entry — betterleaks treats a trailing
inline comment as part of the fingerprint, so the reason goes on its own line.
The result:

```
# ~/repos/app/.betterleaksignore
# documented example key from upstream docs
deploy/values.yaml:generic-api-key:155
```

Review what's recorded any time:

```bash
sandbox exceptions list --repo ~/repos/app
```

> **One value, sometimes several rules.** A single token can trip more than one
> betterleaks rule on the same line (e.g. `github-pat` *and* `generic-api-key`).
> The gate prints each; accept each. `exceptions add` takes several specs at
> once: `sandbox exceptions add --repo ~/repos/app f.yaml:github-pat:1 f.yaml:generic-api-key:1`.

### 3. Commit it

`.betterleaksignore` is checked in like any other repo file. That's the point —
it's visible in code review, a junior developer inherits the judgment of whoever
reviewed it rather than re-litigating each finding, and the team's pre-commit and
CI betterleaks runs pick up the same clearance the moment it merges (they scan
from the repo root with `betterleaks dir .`, so the relative fingerprints match).

```bash
git -C ~/repos/app add .betterleaksignore
git -C ~/repos/app commit -m "Accept reviewed secret-gate false positive in values.yaml"
```

### 4. A reviewer vets the repo

The list only takes effect once the tree is [vetted](vetting.md). When a reviewer
signs, `sandbox vet` surfaces exactly what they're signing off on and asks them
to acknowledge it — so a signature can never silently launder a real secret
someone recorded as an "exception":

```
$ sandbox vet --repo ~/repos/app

  This repo records 1 secret exception(s). Signing this attestation
  vouches that they are reviewed false positives — the agent WILL be able to
  read these values once the repo is vetted:
      deploy/values.yaml:generic-api-key:155

  Acknowledge and sign? [y/N] y
  ~/repos/app: created signed attestation tag agent-vetted/1ff36c4...
```

In CI or any non-interactive context, pass `--yes` to acknowledge explicitly;
without it (and without a terminal to prompt on) `vet` refuses rather than sign
off unattended.

An authorized signer doesn't need the separate `vet` step on an interactive
launch: `sandbox run` offers the same attestation
[inline](vetting.md#attest-at-launch-authorized-signers) when a required-but-
unvetted repo would otherwise refuse — same signed tag, same acknowledgment
prompt shown above — and, because vetting runs before the secret gate, the
freshly blessed exceptions list is honored in that same launch.

### 5. The launch passes

```
$ sandbox run --tier 2 --repo ~/repos/app --agent claude
...
  Scanning workspace(s) for secrets with betterleaks...
  1 secret finding(s) accepted via the vetted exceptions list (reviewed false positives; the agent WILL read these).
  betterleaks: no unmasked secrets.
```

`sandbox check <workspace>` previews the same, so you can confirm before a real
run.

## Authoring or auditing an entry by hand

The subcommand is only a convenience — `.betterleaksignore` is plain text in a
format the whole team already understands, so a reviewer can add or check an
entry with an editor. Each line is exactly what the gate prints: `RELPATH:RULE:LINE`,
repo-relative. A `#` line is a comment. There is no hash to compute and nothing
tool-specific about the format, which is why the same file serves CI and
pre-commit unchanged. `sandbox exceptions add` is still the easy path — it
confirms the finding exists before recording it, so you can't accept a typo.

## Migrating from `accepted_secrets:`

Repos vetted before this change recorded exceptions under `accepted_secrets:` in
`<repo>/.sandbox/config.yaml`, with a value hash on each entry. **That list is no
longer honored.** One command converts a repo:

```bash
sandbox exceptions migrate --repo ~/repos/app
```

It rewrites each `relpath:rule:line:hash` entry as the native `relpath:rule:line`
in `.betterleaksignore` (carrying any `# reason` comment across), removes the
`accepted_secrets:` block from `.sandbox/config.yaml`, and leaves every other key
in that file alone. Review the diff, commit **both** files, and re-vet so the
gate honors the new list. Until you do, `sandbox run`, `sandbox check`, and
`sandbox vet` all print a one-line nudge when they notice a leftover
`accepted_secrets:` list, and the findings it used to cover block again.

## Integration with vetting and team overlays

Exceptions and [vetting](vetting.md) are one mechanism seen from two ends. A few
consequences are worth making explicit:

- **A trust root is required for exceptions to ever count.** "Vetted" means a
  signed `agent-vetted/<sha>` tag verifies against an operator-side
  [trust root](vetting.md#set-up-a-trust-root) — your own file, or the reviewer
  list a linked team overlay ships (they are a union; either verifying counts).
  With no trust root available at all, no repo is vetted, so no exception is
  ever honored.
- **Posture and honoring are separate.** The `vetting:` posture
  (`off`/`advisory`/`required`) controls whether an *unvetted* repo may launch at
  all. Honoring a *vetted* repo's exceptions does not depend on posture — a valid
  signature is a valid signature. So even under `vetting: off`, a repo that
  carries a verifying tag has its exceptions honored; a repo without one simply
  has its list ignored.
- **The overlay is where the authority is configured.** Teams typically ship the
  `vetting:` posture and the reviewer list itself (`vetting_trust_root:
  allowed_signers`, a relative path resolved against the overlay root) in a
  [team overlay](profiles-and-overlays.md) (delivered via `sandbox link` or
  `SANDBOX_OVERLAY`). That is what decides whose signatures make a repo's
  exceptions count — set once for everyone, not per-developer.

### Per-repo exceptions vs. an operator baseline

Both stores now use betterleaks' native fingerprint format; what differs is
*where the file lives* and *what makes the sandbox trust it*. Use the one that
matches where the judgment lives:

| | Repo `.betterleaksignore` (this page) | Overlay `.betterleaksignore` |
| --- | --- | --- |
| Lives in | the **repo root** (committed) | the **team overlay** |
| Authored by | anyone who can commit; blessed by the vetting signer | the operator who ships the overlay |
| Authority at launch | the repo's vetting attestation | trust in the overlay itself (org-wide) |
| Scope | that one repo | every repo the overlay applies to |
| Also read by | the team's own CI / pre-commit betterleaks | operator-side only |
| Best for | a false positive specific to one repo | a finding that recurs across many repos |

The [operator baseline](../explanation/security-model.md#owning-betterleaks-allowlist-inputs)
is the right tool when the same false positive shows up everywhere and a single
operator owns the call. Per-repo exceptions are the right tool for the ordinary
case: a specific finding, in a specific repo, that a reviewer vouches for as part
of vetting that repo — and, because the file is the repo's own
`.betterleaksignore`, the same clearance the developers' local scans already use.

## Trusted internal model endpoints (a different lever)

Exceptions above are for findings that are **not really secrets** — reviewed
false positives, honored on any endpoint. A separate lever handles the opposite
case: a finding that **is** a real secret, where the model reading it is one you
trust.

Everything an agent reads flows to its model endpoint, which makes that endpoint
the most sensitive egress destination in the system. An **internal** model (a
vLLM/Ollama box, an in-cluster proxy) keeps that data inside your trust boundary;
an **external** one exports it. So a secret is tolerable to an internal model but
not an external one — which is exactly the distinction this lever draws.

When a session's inference endpoint is on the team overlay's
`trusted_inference_endpoints:` list, a would-be-blocking finding is **downgraded
from a hard refusal to a single interactive confirmation** for the whole run:

- The gate **still scans** and **still shows** every finding — nothing is skipped
  or silenced.
- Instead of refusing, it prints the findings and asks once: *start the sandbox
  anyway? [y/N]*. Answer `n` and nothing launches.
- With **no interactive terminal** (CI, headless), there is no one to ask, so the
  gate **fails closed** and refuses — use `--i-accept-unmasked-secrets` to consent
  non-interactively there.

The confirmation is deliberate rather than automatic because a trusted endpoint
closes only the **model** channel. The agent still reads the secret and could act
on it, or leak it via shell egress to an allowed domain — so a human makes the
call with eyes open, rather than the launch passing silently.

Configuration lives in the [team overlay](profiles-and-overlays.md)'s
`config.yaml` — an operator-side input, selected via `SANDBOX_OVERLAY` or your
`~/.sandbox/config.yaml`, and **not** read from a repo-local
`<repo>/.sandbox/config.yaml`. That is the boundary that matters: the repo and
the in-sandbox agent — the party the secret gate exists to contain — cannot add a
trusted endpoint or point the agent at one, because they can write neither the
operator's overlay/config nor the launch environment. It does **not** restrict
the launching operator, who selects the overlay and sets `OPENCODE_BASE_URL`;
that operator already controls the gate outright (`--i-accept-unmasked-secrets`,
or an overlay `.betterleaksignore` baseline), so for them the list only records
intent rather than granting new power. (Unlike the repo exceptions above, the
trust list is unsigned operator config, not bound to a vetting signature.) Match
is on the exact bare host (no wildcards, no port). Today only the `opencode`
agent has a caller-chosen endpoint (`OPENCODE_BASE_URL`); the other agents always
use their vendor API and are never on the list.

```yaml
# <overlay>/config.yaml
trusted_inference_endpoints:
  - vllm.internal.example.org
  - llm.corp.example.org
```

| | `.betterleaksignore` (exceptions) | `trusted_inference_endpoints:` |
| --- | --- | --- |
| The finding is | a reviewed **false positive** | a **real secret** |
| Effect | finding is not counted at all | block → one interactive confirm |
| Keyed on | the repo (via its vetting signature) | the session's model endpoint |
| Depends on a TTY | no | yes (else fails closed) |

## See also

- [Vetting repos for agent use](vetting.md) — the signature that gives an
  exceptions list its authority.
- [Security model → the secret gate](../explanation/security-model.md) — what
  the gate scans, the mask, and the encrypted-at-rest exemption (which handles
  SealedSecret / SOPS values without needing an exception at all).
- [Configuration reference](../reference/configuration.md) — the repo-root
  `.betterleaksignore` and the per-repo config file beside it.
