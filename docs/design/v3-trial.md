# Trying v3 on a Mac

A working guide for the owner's trial of the v3 rewrite before the v3 pull request. It is not
user documentation. State as of 2026-11-27; S8.md "Start here" says what changed since.

## What works

- `sandbox install` (vfkit VM, netd networking), `vm start|stop|status`, `doctor`, `uninstall`.
- `sandbox rebuild` builds the agent images in the VM (v2's Dockerfiles).
- `sandbox onboard --agent claude` and `--agent codex`: the agents' logins through the credential
  broker (Codex's ChatGPT login is refreshed by the broker in the VM).
- `sandbox run` with Claude Code or Codex (`--agent codex`): tiers 1 to 3, the workspace gates (vetting, the secret scan with
  betterleaks), your repositories synced into the VM and back (changes the gate withholds wait in
  `sandbox sync review`), profile secrets brokered or readable (`sandbox secret set ... --bind` or
  `--allow-readable`), `--infra-token`, MCP dependencies, your L7 rules in
  `~/.sandbox/egress-rules.yaml`, `--keep-alive`, `list`, `stop`, `resume`.
- opencode with `OPENCODE_API_KEY` and `OPENCODE_BASE_URL` set (not yet run against a real
  endpoint).
- `--runtime gvisor` (or `runtime: gvisor` in `~/.sandbox/config.yaml`): the session runs under
  gVisor instead of Kata. On a Mac this is the fast option: Claude Code shows its first screen
  about a second after launch and echoes keys in 15-30 ms, against 6-7 s and 50-80 ms under Kata
  (4-CPU test VM). The differences are in docs/how-to/runtimes.md.

## What does not work yet

- copilot and grok (their broker adapters are not built); `--infra-kubeconfig`.
- Resuming a stopped tier 3 or opencode session, or one whose profile binds secrets (other stopped
  sessions are recreated).
- `sandbox upgrade`, prebuilt agent images in the appliance (you build them once with
  `sandbox rebuild`), Windows and Linux hosts (Linux uses qemu; not part of this trial).
- Files over 64 MiB reach the VM, but the agent's changes to them do not come back (the sync gate's
  per-file limit; the sync notes each one). v2 synced them both ways.
- The catalogue's `everything-mcp` exits a few seconds after it starts if nothing connects to it;
  sandboxd restarts it (10 s, doubling to 5 min), so it comes and goes until the agent connects.

## Beside v2

v3 reads and writes the same `~/.sandbox` as v2: your profiles, secrets, `config.yaml`, overlays,
and logs are shared and keep their formats. v3 adds `~/.sandbox/vm`, `sync`, `quarantine`,
`agent-config`, and `egress-rules.yaml`. v2's Lima VM is untouched. Name the v3 binary
`sandbox3` so v2's `sandbox` keeps working, and give the two VMs memory to share (or stop v2's).

**Never run `sandbox3 uninstall --purge`**: it removes the shared state, v2's secrets, agent
homes, logs, and profiles included. Plain `sandbox3 uninstall` asks about each kind of state;
answer `n` to keep it.

## Setting up

1. vfkit: `brew install vfkit`.
2. The host binary (Go 1.27):
   `cd go && go build -o ~/bin/sandbox3 ./cmd/sandbox`
3. The appliance image, built in the `v3-spike` Lima VM (about 15 minutes):
   `image/build-in-lima.sh v3-spike 3.0.0-dev.trial ~/sandbox-appliance.raw`
4. Install (8 GiB is the minimum; more memory gives sessions more):
   `sandbox3 install --dev-image ~/sandbox-appliance.raw --vm-memory 12 --vm-cpus 4`
   The credential broker's key is kept in your login keychain (`agent-sandboxes broker key`).
5. The agent images, once (about 10 minutes, from the network, in the VM):
   `sandbox3 rebuild --agent base && sandbox3 rebuild --agent claude`
   (add `--tier3` for tier 3's `claude-infra`). For the other agents of the trial:
   `sandbox3 rebuild --agent codex` and `sandbox3 rebuild --agent opencode`.
6. Claude Code's login: in a terminal on the Mac, `claude setup-token` (it signs in through the
   browser and prints a token, `sk-ant-oat01-...`), then `sandbox3 onboard --agent claude` and
   paste it. The token goes only into the VM's broker; sessions see a placeholder. Onboard again
   after reinstalling the VM.
7. Codex's login: `sandbox3 onboard --agent codex` runs Codex's device login (Codex must be
   installed on the Mac): open the link it prints and enter the code. This is a login of the
   sandbox's own, so your Codex on the Mac stays signed in; the broker in the VM refreshes it.
8. opencode: run it with `OPENCODE_API_KEY` and `OPENCODE_BASE_URL` set in your shell
   (`sandbox3 run --agent opencode ...`); the key is sealed for that launch and brokered to the
   endpoint's host, and the model list is fetched on the Mac.

## Updating an existing install

The VM's image cannot be upgraded in place yet, so an update is a reinstall that keeps your state:

1. Rebuild the host binary from the branch: `cd go && go build -o ~/bin/sandbox3 ./cmd/sandbox`.
2. Build the image as in step 3 above (or use one already built for you).
3. `sandbox3 uninstall` and answer `n` to every question (keeps profiles, secrets, logs, sync
   state); never `--purge`.
4. `sandbox3 install --dev-image <image> ...` with your memory and CPU settings, then steps 5 and
   6 again: the agent images and the logins live in the VM, so rebuild and onboard again.
5. For gVisor by default: add `runtime: gvisor` to `~/.sandbox/config.yaml` (pass
   `--runtime kata` for a session that should still get a microVM).

## Using it

- `sandbox3 run --repo ~/code/some-repo` (tier 1: history kept for the session only), or
  `--tier 2` to keep Claude's conversation history for that repository (`/resume` in Claude).
- The agent works in the VM's copy of the repository; its changes come back to the repository on
  the Mac while it runs and at the end. Changes to executable config (`.git/config`, hooks, and the
  like) are withheld: `sandbox3 sync review`.
- `sandbox3 list`, `sandbox3 stop ID`, `sandbox3 run --keep-alive ...` then `sandbox3 resume ID`.
- `sandbox3 run --runtime gvisor ...` for one session under gVisor; the banner's `Runtime` line
  says which one a session got.
- Session logs and audit records: `~/.sandbox/logs/<session>/`.

## What to note during the trial

Anything that differs from v2 unexpectedly, every error message that did not tell you what to do,
and in particular:

- Whether Claude Code works for a whole day on the placeholder (the first run with a real token;
  S2 has only seen it with a fake one), and any request the gateway refused
  (`~/.sandbox/logs/<session>/` events `credential_missing` or `credential_misuse`, flows with a
  `denied` decision).
- Whether the files you expect come back to the Mac, and anything `sync review` holds.
- Memory and CPU on the Mac while a session runs.
