# Uninstalling

[← Documentation](../index.md)

```bash
sandbox uninstall              # delete the VM; ask about each kind of state
sandbox uninstall --keep-vm    # keep the VM; ask about the state
sandbox uninstall --purge      # delete the VM and all the state below, without asking
```

`uninstall` stops and deletes the sandbox VM, with everything in it (workspace
copies, agent history, the credential broker's store), and its SSH keys in
`~/.sandbox/vm/`. Then, on a terminal, it asks about each kind of state in
`~/.sandbox`; without a terminal it keeps them all:

| Asked about | Paths in `~/.sandbox` |
|---|---|
| secrets and agent tokens | `secrets/`, `agent-home/` |
| withheld workspace changes and sync state | `quarantine/`, `sync/` |
| logs | `logs/` |
| settings and profiles | `config.yaml`, `profiles/`, `vetting/`, `extra-ca-certs/`, `overlays/`, `egress-rules.yaml`, `agent-config/` |

> **If v2 is still installed, don't use `--purge`.** v2 uses the same
> `~/.sandbox`: its secrets, agent homes, logs, and profiles would go with it.
> Answer `n` to each question instead. See [Upgrading from v2](upgrading-from-v2.md).

Review withheld workspace changes (`sandbox sync review`) before you remove
`quarantine/`: they exist nowhere else.

`uninstall` does not remove the host binary, vfkit or qemu, this repository, or
the broker's key (the keychain item `agent-sandboxes broker key` on macOS,
`~/.sandbox/broker.key` on Linux; the latter goes if you remove `~/.sandbox`
yourself). v2's flags `--keep-lima` and `--keep-kubetools` are gone; use
`--keep-vm`.

To remove v2 after upgrading, use `sandbox migrate --remove-v2`
([Upgrading from v2](upgrading-from-v2.md#removing-v2)).
