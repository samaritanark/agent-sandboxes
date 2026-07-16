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
lists you control — never the ambient keyring. Freshness is strict: the tag must
point at the current `HEAD`, and a dirty working tree is refused, because an
attestation describes a specific commit rather than whatever is checked out.

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

Everyone who runs `sandbox link` gets the list; `sandbox link sync` — the
deliberate, diff-showing step — is the only thing that updates it. There is no
per-operator setup at all. Enrollment is a change to one committed file, and
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
pinned to a commit, and moved only by `link sync` — a workspace author can
write to neither. Prefer GnuPG? Set `vetting_trust_format: gpg` and point
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
| `advisory` | Prints each `--repo`'s vetting status and proceeds. The default. |
| `required` | Refuses the launch unless every `--repo` carries a current, verified attestation at `HEAD`. |

A team [overlay](profiles-and-overlays.md) can ship its own `config.yaml` with a
`vetting:` key. An overlay may only **ratchet the posture up** (`advisory →
required`), never relax it — the same "additive on the safety side" rule the
overlay's block list follows. So an organization can make vetting mandatory for
everyone who uses its overlay, and an individual operator can opt themselves into
`required` even when the overlay does not.

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
```

Any new commit moves `HEAD` past the tag, so the attestation goes stale and the
repo must be re-vetted — which is the point: a review covers the code that was
reviewed, not whatever lands on top of it.

## Acknowledging secret exceptions

Vetting is also what gives a repo's
[secret-gate exceptions](secret-exceptions.md) their authority. If the repo
records any under `accepted_secrets:`, signing the tree vouches for them — so
before it signs, `sandbox vet` lists the finding(s) that list would let the agent
read and asks you to acknowledge them:

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

## Attest at launch (authorized signers)

Repos don't hold still: every new commit — including one the agent itself made
last session — stales the attestation. So when `required` would refuse an
interactive launch and your signing identity is available, the gate offers the
attestation inline instead of sending you away to run `sandbox vet` and retry:

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
refusal), only for a cleanly unvetted repo (a dirty tree must be committed
first), and never touches an existing tag someone else created. Unlike
`--i-accept-unvetted-repo`, saying `y` leaves a portable, signed attestation —
accountability travels with the repo instead of a line in a local log.

## When a launch is refused

Under `vetting: required`, an unvetted `--repo` stops the launch (after the
inline offer, if one was available, was declined or unavailable):

```
ERROR: vetting is required, but the following workspace(s) have no current,
       verified agent-vetting attestation, so the launch is refused:

    /home/you/repos/app: no verified attestation (HEAD 1ff36c4...; no agent-vetted/* tag at HEAD)

  A trusted reviewer must attest the current HEAD:
        sandbox vet --repo <PATH>
  Override (audited), accepting the risk for this launch:
        re-run with --i-accept-unvetted-repo
```

`--i-accept-unvetted-repo` proceeds anyway and records the acceptance (which
repos, and that the override was used) in the session's audit log. A **missing
trust root** under `required` is treated as an operator misconfiguration and
fails closed regardless of the override — fix the trust root rather than
overriding past it.
