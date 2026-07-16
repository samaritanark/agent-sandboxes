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
is a **fingerprint**:

```
<relpath>:<rule>:<line>:<hash>
deploy/values.yaml:generic-api-key:155:3cd3c4be828647be
```

— the finding's path, its betterleaks rule, its line, and a short SHA-256 of the
**matched value**. Entries live under `accepted_secrets:` in the repo's own
`<repo>/.sandbox/config.yaml`, right beside `masked_paths:`.

Two properties make this safe rather than a backdoor:

- **It only counts on a vetted repo, and only when committed.** A committed
  accept-list means nothing on its own — anyone who can push to the repo
  (including a prompt-injected agent) could add one. What gives it authority is
  the [vetting](vetting.md) signature: a reviewer signs the whole tree,
  *including* this list, so accepting a finding carries a human's cryptographic
  sign-off. The gate reads the list from the **signed commit** (`HEAD`), not your
  working copy, so an entry that is uncommitted — or hidden by `.gitignore` —
  is never honored; you must commit it and (re-)vet. On an unvetted repo the list
  is ignored and the gate blocks exactly as before. (More on this in
  [Integration with vetting](#integration-with-vetting-and-team-overlays).)
- **It's bound to the value.** The hash is of the secret value the scanner
  matched. Replace that value — rotate the token, or slip a *real* secret onto
  the same line — and the hash no longer matches, so the finding blocks again.
  Accepting a line never blesses whatever lands there later.

One more boundary: an exception is honored **only for a git-tracked file**. The
vetting signature covers committed content, so a finding in a gitignored or
untracked local file (a `.env` you never committed, say) is not part of the
signed tree and is never accepted — even if a fingerprint for it appears in the
list. Those stay gated, which is correct: no one signed for them.

## The workflow

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

`add` re-scans to resolve the value hash, so a matching finding must actually
exist in the current tree (you cannot pre-accept something the scanner doesn't
flag). The `--reason` is optional and is stored as a comment for the next person
reading the file. The result:

```yaml
# ~/repos/app/.sandbox/config.yaml
accepted_secrets:
  - "deploy/values.yaml:generic-api-key:155:3cd3c4be828647be"  # documented example key from upstream docs
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

`accepted_secrets:` is checked in like any other repo config. That's the point —
it's visible in code review, and a junior developer inherits the judgment of
whoever reviewed it rather than re-litigating each finding.

```bash
git -C ~/repos/app add .sandbox/config.yaml
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

The subcommand is only a convenience — the file is plain text, so a reviewer can
add or check an entry with an editor and standard tools. The hash is a 16-hex
prefix of the SHA-256 of the exact bytes betterleaks matched:

```bash
printf '%s' 'the-matched-value' | sha256sum | cut -c1-16
```

The one subtlety is "exact bytes": the hash covers precisely the span the
scanner flagged (surrounding quotes or trailing whitespace matter), so hand-
computing it is best used to *audit* an entry the tool produced rather than to
author from scratch. When in doubt, let `exceptions add` compute it.

## Integration with vetting and team overlays

Exceptions and [vetting](vetting.md) are one mechanism seen from two ends. A few
consequences are worth making explicit:

- **A trust root is required for exceptions to ever count.** "Vetted" means a
  signed `agent-vetted/<sha>` tag verifies against your operator
  [trust root](vetting.md#set-up-a-trust-root-one-time). With no trust root
  configured, no repo is vetted, so no exception is ever honored.
- **Posture and honoring are separate.** The `vetting:` posture
  (`off`/`advisory`/`required`) controls whether an *unvetted* repo may launch at
  all. Honoring a *vetted* repo's exceptions does not depend on posture — a valid
  signature is a valid signature. So even under `vetting: off`, a repo that
  carries a verifying tag has its exceptions honored; a repo without one simply
  has its list ignored.
- **The overlay is where the authority is configured.** Teams typically ship the
  `vetting:` posture and `vetting_trust_root:` in a
  [team overlay](profiles-and-overlays.md) (delivered via `sandbox link` or
  `SANDBOX_OVERLAY`). That is what decides whose signatures make a repo's
  exceptions count — set once for everyone, not per-developer.

### Per-repo exceptions vs. an operator baseline

There are two ways to tell the gate "accept this finding," with different trust
models. Use the one that matches where the judgment lives:

| | `accepted_secrets:` (this page) | Overlay `.betterleaksignore` |
| --- | --- | --- |
| Lives in | the **repo** (`.sandbox/config.yaml`) | the **team overlay** |
| Authored by | anyone who can commit; blessed by the vetting signer | the operator who ships the overlay |
| Authority | the repo's vetting attestation | trust in the overlay itself (org-wide) |
| Scope | that one repo | every repo the overlay applies to |
| Fingerprint | value-bound (`…:hash`); a changed value re-blocks | betterleaks' own path/rule fingerprint |
| Best for | a false positive specific to one repo | a finding that recurs across many repos |

The [operator baseline](../explanation/security-model.md#owning-betterleaks-allowlist-inputs)
is the right tool when the same false positive shows up everywhere and a single
operator owns the call. Per-repo exceptions are the right tool for the ordinary
case: a specific finding, in a specific repo, that a reviewer vouches for as part
of vetting that repo.

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
intent rather than granting new power. (Unlike `accepted_secrets:` above, the
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

| | `accepted_secrets:` (exceptions) | `trusted_inference_endpoints:` |
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
- [Configuration reference](../reference/configuration.md) — the
  `accepted_secrets:` key.
