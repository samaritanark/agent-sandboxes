# Troubleshooting

[← Documentation](../index.md)

Start with `sandbox doctor`. It checks the VM driver, `sandbox netd`, that the
VM answers and its image version, `/dev/kvm` inside the VM (which Kata needs),
and that the VM cannot reach your machine. `sandbox vm status` shows the VM's
state and image version.

## The VM

**`the sandbox VM has not been created. Run: sandbox install`** or **`the
sandbox VM is stopped. Start it with: sandbox vm start`.** As it says. The VM
does not start on its own after your machine reboots.

**A command hangs, then fails with `cannot reach the sandbox VM`, or `doctor`
reports netd as not running.** On the vfkit and qemu drivers, `sandbox netd` on
your machine is the VM's only network; if it stopped, the VM has none. `sandbox
vm start` restarts it (and the VM if needed). This also happens after your
machine sleeps for a long time.

**`the sandbox VM image ... speaks control API N, older (or newer) than this
sandbox binary supports`.** The host binary and the image are from different
builds. The message suggests `sandbox upgrade`, which is not available in v3 yet.
Instead, run `sandbox uninstall` (answer `n` to keep each kind of state) and
install an image built from the same version (see
[Installing](../how-to/installing.md)).

**`/dev/kvm in the VM (nested virtualization)` fails in `doctor`.** The agent's
microVMs need nested virtualization. On macOS it needs an Apple silicon Mac with
macOS 15 or later (M3 or newer for vfkit's nested support); on Linux, KVM with
nested virtualization enabled for your CPU's KVM module.

**`WARNING: could not give the credential broker its key`** at `install` or
`vm start`. Sessions that use any credential (an agent login, a bound secret) are
refused until it succeeds. Run `sandbox vm start` again; if the warning stays,
`sandbox doctor` shows what is wrong. On macOS the key is in your login keychain
(`agent-sandboxes broker key`); a locked keychain stops it.

**`could not push the operator state to the sandbox VM`**, or a warning that a
file was `not pushed to the VM`. Before each command the host copies your
settings (`config.yaml`, `profiles/`, and the like) into the VM. It skips files
it will not copy (links, unusual names, very large files) and names them; move or
rename them.

## Launching a session

**`<agent> is not onboarded in this sandbox VM`.** Sign the agent in:
[Onboarding agents](../how-to/onboarding-agents.md). Logins live in the VM, so
reinstalling the VM means onboarding again.

**`codex's login could not be renewed ... Onboard it again on the host`.** The
broker refreshes Codex's ChatGPT login before a launch when it is about to
expire; the token endpoint refused (the login was signed out, revoked, or
unused for too long). Run `sandbox onboard --agent codex` again.

**`'run' with copilot (grok) is not yet available in v3`.** Their broker
adapters are not built; use claude, codex, or opencode.

**`No runnable image for agent '<agent>'`.** The agent's image has not been built
in this VM: `sandbox rebuild --agent base`, then `sandbox rebuild --agent <agent>`
(add `--tier3` for tier 3). See [Rebuilding images](../how-to/rebuilding-images.md).

**`not enough memory: the session needs N MiB ...`.** Sessions do not
overcommit memory. Stop another session (`sandbox list`, `sandbox stop`), or
reinstall the VM with more memory (`--vm-memory`). On the minimum 8 GiB VM one
session fits.

**`betterleaks is required to scan workspaces for secrets`.** The appliance image
ships betterleaks; an image built before it did cannot launch tier 2 or 3.
Install a current image.

**`==> Secret NAME: withheld (no binding; ...)`.** In v3 a profile's secret
reaches the agent only through a binding. Bind it to the hosts it is for:
`sandbox secret bind NAME --bind api.example.com`, or let the agent read it with
`--allow-readable`. See [Secrets](../how-to/secrets.md).

**`==> Secret NAME: withheld (HOST not on this session's allowlist)`.** A
binding never widens the allowlist. Add the host with `--allow-domain`, a
profile, or `extra_allowed_domains`.

**`the sandbox VM asked for secret 'NAME', which neither this command line nor
your profiles ... name`.** The host refuses to give the VM a secret you did not
ask for, and pushes nothing. If you did not change anything that explains it,
treat the VM as suspect: `sandbox doctor`, and consider reinstalling it.

**`WARNING: HOST looks like a package or image registry, but no rule refuses
writes to it`.** A session can reach a registry with a credential and no rule
stops a publish there. Add the deny rule the warning prints to
`~/.sandbox/egress-rules.yaml` or the overlay. See [Egress rules](../how-to/egress-rules.md).

**A gate refuses the launch** (unmasked secrets, unvetted repo, vetting drift).
These work as in v2: see [Security model](security-model.md#workspace-gates),
[Vetting](../how-to/vetting.md), and [Accepting secret-gate false
positives](../how-to/secret-exceptions.md).

## Inside a session

**The agent cannot reach a host.** `sandbox flows <SESSION_ID>` lists every
connection and request with its decision. A name not on the allowlist gets no
DNS answer; a blocked or unlisted destination shows `refused` or `blocked`. Add
the host with `--allow-domain` on the next launch (`sandbox allow` on a running
session is not available in v3 yet).

**A request gets `403` and the session's events show `credential_misuse` or
`credential_missing`.** The agent sent a placeholder to a host it is not bound
to, or sent a credential of its own to a host where the broker injects one.
Check the binding's hosts (`sandbox secret list`); for an agent login, see
[Onboarding agents](../how-to/onboarding-agents.md).

**A request gets refused by an L7 rule** (a git push, a package publish, `TRACE`,
or one of your rules). `sandbox flows` names the rule. The org baseline's rules
cannot be removed; your own are in `~/.sandbox/egress-rules.yaml`.

## Your files

**The agent's change to `.git/config`, a hook, `.gitattributes`, or a similar
file did not appear in your checkout.** The sync gate holds such changes back:
`sandbox sync review` shows each with its diff, and `--apply <ID>` or
`--discard <ID>` settles it.

**`WARNING: the last sync of REPO failed`** after a session. The agent's last
changes are still in the VM's copy; `sandbox sync once --repo REPO` brings them
over.

**A file you changed and the agent changed at the same time** is a conflict and
is held for `sandbox sync review` too.

## Leftovers

**`sandbox list` shows a session you thought ended.** A `--keep-alive` session
stays until `sandbox stop`, 24 hours detached, or 7 days. Any other session ends
two minutes after its terminal goes away.

**After a crash or a reboot of the VM**, `sandboxd` ends every session it did not
see finish, removes their microVMs and networks, and records `sandboxd
restarted` as the end reason.
