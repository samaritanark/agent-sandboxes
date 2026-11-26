# CLI Reference

[← Documentation](../index.md)

In v3, `sandbox` is a single binary on your machine (the host). Some commands run
on the host itself; the rest are forwarded over SSH to the policy layer inside
the sandbox VM, which runs them and streams the output back. You type every
command the same way; the split only matters when you read an error message.

Every command takes `--help`.

## Host commands

These run on your machine. They manage the VM, your secrets, agent logins, and
the files that sync between your repositories and the VM.

```text
sandbox install --dev-image <PATH> [OPTIONS]
  --dev-image <PATH>        appliance image (raw; qcow2 for --driver lima).
                            Development builds only: the signature is not checked
  --vm-cpus <N>             default: host CPUs less 2, at least 4
  --vm-memory <GiB>         default: host memory less 6 GiB, at least 8
  --vm-disk <GiB>           state disk, default 60
  --driver <vfkit|qemu|lima>
                            vfkit (macOS) and qemu (Linux) are the defaults;
                            their only network is sandbox netd, which keeps the
                            VM from reaching this machine. lima cannot block
                            your LAN address
  --vfkit <PATH> | --qemu <PATH> | --limactl <PATH>
                            the hypervisor binary to use (default: on PATH)
  --skip-v2-migration       do not look for a v2 install to carry over
sandbox setup ...           alias of install

sandbox uninstall [--keep-vm] [--purge]
  Deletes the VM and its SSH keys. On a terminal it then asks, kind by kind,
  whether to delete your state in ~/.sandbox (secrets, withheld changes and
  sync state, logs, settings and profiles). Without a terminal it keeps them.
  --purge deletes all of them without asking. ~/.sandbox is shared with a v2
  install: --purge deletes v2's secrets, agent homes, logs, and profiles too.

sandbox migrate [--remove-v2] [--yes]
  Carries a v2 install over (install runs this when it finds one). See
  Upgrading from v2.

sandbox vm start | stop | status | shell
  shell opens a root shell in the VM for debugging; it is recorded on the host
  in ~/.sandbox/logs/vm-shell.log.
sandbox status              same as: sandbox vm status
sandbox doctor              checks the driver, netd, the VM's reachability and
                            version, /dev/kvm in the VM, and that the VM cannot
                            reach this machine

sandbox onboard [--agent claude|codex] [--dry-run] [--from-auth-json FILE]
  Seals an agent's login into the VM's credential broker. See
  Onboarding agents.

sandbox secret set <NAME> [--from-file PATH | --from-env[=VAR]]
                   [--bind HOST[,HOST]... [--inject KIND] | --allow-readable]
sandbox secret bind <NAME> (--bind HOST [--inject KIND] | --allow-readable | --withhold)
sandbox secret list
sandbox secret delete <NAME>
  KIND is bearer (default), basic, header:NAME, or query:NAME. See Secrets.

sandbox sync review [--apply <ID> | --discard <ID>]
sandbox sync once --repo <PATH>
  review lists the workspace changes the sync gate withheld from your
  checkouts, with a diff, and applies or discards one. once runs one sync pass.

sandbox flows <SESSION_ID>  the session's gateway records (see Audit logs)

sandbox setup-proxy-cert [...]
  Finds a corporate TLS-intercept proxy's root CA in this machine's trust
  store and writes it to ~/.sandbox/extra-ca-certs/proxy-ca.crt. It applies
  from the next session; nothing is rebuilt.
```

## Commands run in the VM

```text
sandbox run [OPTIONS]
  --agent <claude|codex|opencode>   default: claude
  --tier <1|2|3>                    default: 1
  --profile <NAME>                  numeric 1|2|3 aliases --tier; a name resolves
                                    ~/.sandbox/profiles/<name>.yaml or the
                                    overlay's profiles/<name>.yaml
  --repo <PATH>                     required for tier 2 and 3; repeatable. One repo
                                    is mounted at /workspace; several at
                                    /workspace/<basename>
  --allow-domain <DOMAIN>           repeatable; the block list still applies
  --base-url <URL>                  opencode's endpoint (overrides OPENCODE_BASE_URL)
  --infra-token <[NAME=]PATH>       tier 3; brokered to the --infra-endpoint hosts
                                    as $INFRA_TOKEN or $INFRA_TOKEN_<NAME>
  --infra-endpoint <URL>            tier 3, repeatable
  --name <NAME>                     a label for the session
  --keep-alive                      keep the session after you detach
  --dry-run                         print the session spec and start nothing
  --i-accept-unmasked-secrets       see Vetting and secret exceptions
  --i-accept-unvetted-repo
  --i-accept-vetting-drift

sandbox resume <SESSION_ID> [--keep-alive]
sandbox list
sandbox stop <SESSION_ID>
sandbox logs <SESSION_ID>
sandbox cleanup [--older-than DAYS]       default: 90
sandbox check <WORKSPACE_PATH>
sandbox rebuild [--agent NAME] [--tier3] [--no-cache]
                [--codex-version VER] [--opencode-version VER]
sandbox profile save | list | show | delete ...
sandbox mask add --repo <PATH> <RELPATH>...
sandbox mask list --repo <PATH>
sandbox exceptions add | list | migrate --repo <PATH> ...
sandbox vet --status --repo <PATH>
sandbox link ...
sandbox version
```

The flags, messages, and exit codes of these commands are v2's, except where
this page says otherwise.

### What changed from v2

- **`run`** starts a session as Kata microVMs in the VM instead of a pod. The
  repositories you name are synced into the VM before the launch and back while
  the agent runs; see [Architecture](../explanation/architecture.md#workspace-sync).
  The agent's login comes from the credential broker (`sandbox onboard`), not
  from a directory the agent can read. A profile's `secrets:` are brokered,
  readable, or withheld according to each secret's binding, and `run` prints
  which. `--dry-run` prints the session spec (JSON) instead of v2's manifests.
- **`--infra-token`** is brokered: the agent's variable holds a placeholder, and
  the gateway puts the token into requests to the `--infra-endpoint` hosts as a
  bearer token.
- **`resume`** syncs the session's repositories before it reattaches.
- **`flows`** reads the gateway's records, not Hubble.
- **`status`** reports the VM; there is no cluster to report.
- **`rebuild`** builds the agent images inside the VM. Each image is recorded by
  digest, and `image-builds.log` records the digest rather than the agent's
  version.
- **`onboard`** puts a login into the broker; it no longer copies files into
  `~/.sandbox/agent-home`.

### Removed

- `configure-network`: the VM follows your machine's networking.
- `install` and `uninstall` no longer take v2's cluster flags (`--pod-cidr`,
  `--service-cidr`, `--apiserver-port`, `--dns`, `--keep-*`).
- `run --homedir` is still accepted but has no effect: there is no agent home
  to point at.

### Not available yet

- `upgrade` (reinstall with a newer image for now) and `ca`.
- `allow` (adding domains to a running session).
- Resuming a session that has stopped. A `--keep-alive` session that is still
  running resumes.
- `run --infra-kubeconfig`, `--infra-kube-context`, and `--allow-exec-plugin`.
- The copilot and grok agents.
- Signing an attestation with `vet --repo` (`vet --status` works).

## Session naming

- Tier 1: `<agent>`, for example `claude`
- Tier 2 or 3, one repo: `<repo-basename>/<agent>`, for example `my-project/claude`
- Tier 2 or 3, several repos: `multi/<agent>`

`--name` sets your own label. The name appears in the launch banner and in
`sandbox list`.

## Session ID format

`ses-<YYYYMMDD>-<HHMMSS>-<4hex>`, for example `ses-20260401-143022-a7b3`.

## Related

- [Installing](../how-to/installing.md) and [Upgrading from v2](../how-to/upgrading-from-v2.md)
- [Onboarding agents](../how-to/onboarding-agents.md)
- [Secrets](../how-to/secrets.md) and [Egress rules](../how-to/egress-rules.md)
- [Configuration](configuration.md)
