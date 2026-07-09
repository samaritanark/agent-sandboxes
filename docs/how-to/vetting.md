# Vetting Repos for Agent Use

[← Documentation](../index.md)

Some teams want a gate on *which* repositories an agent may touch: not "does
this repo leak a secret?" (that's the [secret gate](secrets.md)) but "has a
trusted human reviewed this exact tree and cleared it for agent use?" The
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
The *requirement* (is vetting enforced?) and the *trust root* (whose signatures
count?) live operator-side, so nothing a workspace author can commit weakens the
decision. Verification runs on the host, before the pod starts, against a signer
list you control — never the ambient keyring. Freshness is strict: the tag must
point at the current `HEAD`, and a dirty working tree is refused, because an
attestation describes a specific commit rather than whatever is checked out.

## Set up a trust root (one time)

The default trust root is an SSH `allowed_signers` file at
`~/.sandbox/vetting/allowed_signers`. Add one line per authorized reviewer —
their principal (the email they tag with) and their public signing key:

```bash
mkdir -p ~/.sandbox/vetting
# "<principal> <keytype> <key>", e.g. from a reviewer's ~/.ssh/id_ed25519.pub
echo "reviewer@example.com ssh-ed25519 AAAAC3NzaC1lZDI1..." \
  >> ~/.sandbox/vetting/allowed_signers
```

Prefer GnuPG? Set `vetting_trust_format: gpg` and point `vetting_trust_root:` at
a GnuPG home directory that holds the reviewers' public keys.

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
public key must be in the trust root for the resulting tag to verify.

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

## When a launch is refused

Under `vetting: required`, an unvetted `--repo` stops the launch:

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
