# Vetting Repos for Agent Use

[← Documentation](../index.md)

Some teams want a gate on *which* repositories an agent may touch: not "does
this repo leak a secret?" (that's the [secret gate](../explanation/security-model.md))
but "has a trusted human reviewed this exact tree and cleared it for agent use?" The
vetting gate answers that question at launch. A reviewer signs a git tag at a
repo's `HEAD`; `sandbox run` verifies that signature against an operator-held
trust root before it will start a Tier 2/3 session.

This is a compliance / prompt-injection control, and it is **orthogonal to
isolation** — a vetted repo is not thereby safe to run outside a sandbox. Every
session still runs gVisor-isolated with default-deny egress and workspace
masking. Vetting decides *whether to load a repo*, not whether the sandbox's
other guarantees apply. See PRINCIPLES.md ("Repo vetting").

## The trust model, in one paragraph

The repo carries only the *artifact* — a signed tag named `agent-vetted/<sha>`.
The *requirement* (is vetting enforced?) and the *trust roots* (whose signatures
count?) live operator-side, so nothing a workspace author can commit weakens the
decision. Verification runs on the host, before the pod starts, against signer
lists you control — never the ambient keyring. The tag need not point at the
current `HEAD`: a verified tag that is an **ancestor** of `HEAD` counts, and the
gate reports how many commits behind `HEAD` it is. The commits in between are
trusted because nothing reaches the branch without code review — so the drift is
reviewed changes layered on a vetted base. A tag on a divergent line (not an
ancestor of `HEAD`) does not count, and a dirty working tree is always refused,
because uncommitted edits are unreviewed and would ride along unattested.

## Set up a trust root

Two places can hold the reviewer list, and they are a **union** — a signature
verifying against either one counts:

**The team overlay (recommended).** An overlay can ship its reviewer list as a
plain `allowed_signers` file in its own tree and point at it with a relative
path in its `config.yaml`:

```yaml
# <overlay>/config.yaml — a relative path resolves against the overlay root
vetting_trust_root: allowed_signers
```

Everyone who runs `sandbox link` gets the list — and stays current with it,
because `sandbox run` syncs a linked overlay to its pinned ref before every
launch (`sandbox link sync` is the same step run deliberately, showing the
diff). There is no per-operator setup at all. Enrollment is a change to one committed file, and
[`examples/overlay-template/gen-allowed-signers.sh`](../../examples/overlay-template/gen-allowed-signers.sh)
can regenerate it from your git forge's `/<username>.keys` endpoints.

**Your own file.** The operator-local root is an SSH `allowed_signers` file at
`~/.sandbox/vetting/allowed_signers` (or wherever `vetting_trust_root:` in
`~/.sandbox/config.yaml` points). It *adds to* an overlay-shipped list — useful
for signers the team list doesn't carry, or when there is no overlay at all:

```bash
mkdir -p ~/.sandbox/vetting
# "<principal> <keytype> <key>", e.g. from a reviewer's ~/.ssh/id_ed25519.pub
echo "reviewer@example.com ssh-ed25519 AAAAC3NzaC1lZDI1..." \
  >> ~/.sandbox/vetting/allowed_signers
```

Both are operator-side inputs: the overlay is something you chose to link,
pinned to a ref your team controls and advanced only to that ref's tip — a
workspace author can write to neither. Prefer GnuPG? Set `vetting_trust_format: gpg` and point
`vetting_trust_root:` at a GnuPG home directory that holds the reviewers'
public keys.

## Choose a posture

Set `vetting:` in `~/.sandbox/config.yaml`:

```yaml
vetting: required          # off | advisory | required
vetting_trust_root: ~/.sandbox/vetting/allowed_signers   # optional; this is the default
vetting_trust_format: ssh  # optional; ssh (default) or gpg
```

| Posture | Behavior at launch |
| --- | --- |
| `off` | No gate, no output. |
| `advisory` | Prints each `--repo`'s vetting status — including how many commits behind `HEAD` the attestation is — and proceeds. The default. |
| `required` | Refuses the launch unless every `--repo` carries a verified attestation reachable from `HEAD`. Drift behind `HEAD` is accepted per the [drift rules](#when-the-attestation-is-behind-head) below. |

A team [overlay](profiles-and-overlays.md) can ship its own `config.yaml` with a
`vetting:` key. An overlay may only **ratchet the posture up** (`advisory →
required`), never relax it — the same "additive on the safety side" rule the
overlay's block list follows. So an organization can make vetting mandatory for
everyone who uses its overlay, and an individual operator can opt themselves into
`required` even when the overlay does not.

### When the attestation is behind `HEAD`

A single attestation clears a repo, and it keeps clearing it as work lands on
top — because the intervening commits went through code review, the gate treats
them as reviewed changes on a vetted base rather than forcing a re-attestation
every commit. This is the whole point of the compromise: a developer who is
**not** an approved signer can still launch on a repo their team vetted earlier,
without waiting for someone to re-sign `HEAD`.

Under `required`, when the freshest verified attestation is *N* commits behind
`HEAD`:

- **With a drift cap set** (`vetting_max_commits_behind:`, below) and *N* within
  it — the launch **proceeds automatically**, and the "*N* commits behind" shows
  up in the launch output and the audit log. The organization has already
  decided that much drift is acceptable, so there is no per-session prompt.
- **With no cap set** — the launch **prompts** you to accept the *N* commits of
  unattested drift. In a non-interactive context (CI, no terminal), pass
  `--i-accept-vetting-drift` to accept it, or the launch refuses.
- **Over the cap** — the launch refuses. Re-attest `HEAD` (`sandbox vet`), raise
  the cap, or use `--i-accept-unvetted-repo` to override for this launch (audited).

### Cap how far behind an attestation may be

An overlay (or your own config) can bound the drift with an integer:

```yaml
# <overlay>/config.yaml — or ~/.sandbox/config.yaml
vetting_max_commits_behind: 20   # attestations may be at most 20 commits behind HEAD
```

Both configs are read and the **most restrictive** (smallest) value wins, so an
overlay can only tighten the bound and a user can only tighten it further —
neither can loosen the other's, the same safety-additive rule the posture
follows. A cap of `0` means the attestation must sit exactly at `HEAD` — the
strict, re-attest-every-commit behavior. With no cap set, drift is unbounded but
each session requires the interactive acceptance (or `--i-accept-vetting-drift`)
described above.

## Attest a repo

A reviewer, after reading the tree, signs the current `HEAD`:

```bash
sandbox vet --repo ~/repos/app
# → creates signed tag agent-vetted/<sha>, then tells you how to push it:
git -C ~/repos/app push origin agent-vetted/$(git -C ~/repos/app rev-parse HEAD)
```

Pushing the tag lets other operators verify the same attestation. `sandbox vet`
uses your own git signing configuration (`user.signingkey`, `gpg.format`); your
public key must be in a trust root for the resulting tag to verify. If signing
isn't configured yet, `vet` offers to set it up with your existing SSH key and
prints the `allowed_signers` line a trust-root maintainer needs to enroll you —
nothing private moves; enrollment is public keys only.

**GPG-sign your commits?** Keep doing that. Attestations must be SSH-signed to
verify against an `allowed_signers` trust root, and a GPG key id in
`user.signingkey` would make SSH signing fail (`Couldn't load public key
<id>`). Instead of touching git config, set an attestation-only key:

```yaml
# ~/.sandbox/config.yaml — used by `sandbox vet` and the launch-time attest,
# never by git commit/tag signing outside the sandbox CLI
vetting_signing_key: ~/.ssh/id_ed25519.pub
```

`vet` detects the OpenPGP case and offers to write this for you. The key is
personal, so it lives in the user config only — an overlay cannot choose whose
key an operator signs with.

Check a repo's state without signing anything:

```bash
sandbox vet --status --repo ~/repos/app
# vetted:   /home/you/repos/app
#   HEAD:   1ff36c4...
#   tag:    agent-vetted/1ff36c4...
#   signer: reviewer@example.com
#   behind: 0 (attestation is at HEAD)
```

New commits move `HEAD` past the tag, and `--status` reports the growing
distance (`behind: 3 commit(s) — the attestation is an ancestor of HEAD`). The
repo stays vetted through that drift; whether a launch accepts it depends on the
[drift rules](#when-the-attestation-is-behind-head) and any cap. Re-vetting
`HEAD` resets the distance to zero and is always available to a signer.

## Acknowledging secret exceptions

Vetting is also what gives a repo's
[secret-gate exceptions](secret-exceptions.md) their authority. If the repo
records any in its root `.betterleaksignore`, signing the tree vouches for them —
so before it signs, `sandbox vet` lists the finding(s) that file would let the
agent read and asks you to acknowledge them:

```
$ sandbox vet --repo ~/repos/app

  This repo records 1 secret exception(s). Signing this attestation
  vouches that they are reviewed false positives — the agent WILL be able to
  read these values once the repo is vetted:
      deploy/values.yaml:generic-api-key:155

  Acknowledge and sign? [y/N] y
```

This keeps a signature from silently laundering a real secret a contributor
recorded as an "exception". Pass `--yes` to acknowledge non-interactively (e.g.
in CI); without it, and with no terminal to prompt on, `vet` refuses rather than
sign off unattended. A repo with no exceptions signs with no extra prompt.

### Exceptions and drift

The acknowledgment above binds an exception to the *signed* commit. But an
attestation clears a repo while it is [behind `HEAD`](#when-the-attestation-is-behind-head),
and drift is reviewed code layered on a vetted base — whereas an
`accepted_secrets:` entry is not code, it is a standing permission for the agent
to read a plaintext value. A commit added on top of the vetted base can record a
brand-new exception that **no signer ever acknowledged**, so honoring `HEAD`'s
list under drift trusts whoever can land a reviewed commit not to weaponize it.

Two settings, both operator-controlled:

| `vetting_exceptions_require_head:` | Behavior |
| --- | --- |
| *omitted* / `false` (**default**) | Exceptions are honored whenever the repo is vetted, drift included. The frictionless default — the same "reviewed changes ride along" bargain the rest of drift makes, extended to the exception list. |
| `true` | Exceptions are honored **only** when the attestation sits exactly at `HEAD` (`behind: 0`), where the signature genuinely covers the list. Under any drift the list is ignored and those findings block the launch again; re-attest `HEAD` to restore them. |

```yaml
# <overlay>/config.yaml — or ~/.sandbox/config.yaml
vetting_exceptions_require_head: true
```

Read from both the overlay and your own config, this is **tightening-only**:
`true` wins if either sets it, so an overlay can ratchet exception-handling up
and a user can opt in further, but neither can relax the other's — the same
safety-additive rule the [posture](#choose-a-posture) and the
[drift cap](#cap-how-far-behind-an-attestation-may-be) follow. The knob is
independent of posture: it decides only *which* exceptions count, not whether
vetting is enforced.

## Attest at launch (authorized signers)

Sometimes you'd rather sign than accept drift — or the repo is unvetted, or the
drift is over the cap. So when `required` would refuse an interactive launch and
your signing identity is available, the gate offers the attestation inline
instead of sending you away to run `sandbox vet` and retry:

```
  /home/you/repos/app is not vetted at HEAD 1ff36c4...
  Your git signing key can attest it right now — the same signed sign-off
  as 'sandbox vet', honored only if your key is in the trust root. Attest
  only if you have reviewed what is at this HEAD.
  Attest HEAD 1ff36c4... continue? [y/N]
```

Answering `y` is the full `sandbox vet` sign-off, not a shortcut past it: the
same signed tag, the same [secret-exceptions acknowledgment](#acknowledging-secret-exceptions),
and the signature is re-verified against the trust roots before the launch
proceeds — if your key isn't enrolled, the tag is removed again and the launch
is refused with enrollment guidance. Declining refuses the launch exactly as
before. The offer only appears on an interactive terminal (CI keeps the hard
refusal), for a cleanly unvetted repo or one blocked on drift — in both cases
attesting `HEAD` is the fix — but never for a dirty tree (commit first) and never
touching an existing tag someone else created. Unlike `--i-accept-unvetted-repo`,
saying `y` leaves a portable, signed attestation — accountability travels with
the repo instead of a line in a local log.

## When a launch is refused

Under `vetting: required`, a `--repo` with no accepted, verified attestation
stops the launch (after the inline offer, if one was available, was declined or
unavailable) — whether it is wholly unvetted or vetted but too far behind `HEAD`:

```
ERROR: vetting is required, but the following workspace(s) have no accepted,
       verified agent-vetting attestation at HEAD, so the launch is refused:

    /home/you/repos/app: no verified attestation (HEAD 1ff36c4...; no reachable agent-vetted/* tag)
    /home/you/repos/api: vetted but 34 commit(s) behind HEAD (over the cap, or drift not accepted) (HEAD 9ac21be...)

  A trusted reviewer must attest the current HEAD:
        sandbox vet --repo <PATH>
  Or, for a repo that is vetted but behind HEAD, accept the reviewed drift:
        re-run with --i-accept-vetting-drift, or raise
        vetting_max_commits_behind: in your config/overlay.
  Override (audited), accepting the risk for this launch:
        re-run with --i-accept-unvetted-repo
```

`--i-accept-vetting-drift` accepts a verified-but-behind attestation
non-interactively (within any cap); `--i-accept-unvetted-repo` proceeds
regardless and records the acceptance (which repos, and that the override was
used) in the session's audit log. A **missing
trust root** under `required` is treated as an operator misconfiguration and
fails closed regardless of the override — fix the trust root rather than
overriding past it.
