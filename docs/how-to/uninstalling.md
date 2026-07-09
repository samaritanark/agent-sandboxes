# Uninstalling

[← Documentation](../index.md)

```bash
sandbox uninstall              # Interactive — prompts before each destructive step
sandbox uninstall --yes        # Non-interactive (skip all prompts)
sandbox uninstall --keep-logs  # Remove everything except ~/.sandbox/logs/
```

`sandbox uninstall` is a thin wrapper over `./uninstall.sh` (same flags);
running `./uninstall.sh` directly continues to work, which is handy in scripts
or if the CLI isn't on your PATH.

| Option             | Effect                                          |
|--------------------|-------------------------------------------------|
| `--yes` / `-y`     | Skip all confirmation prompts                   |
| `--keep-logs`      | Preserve `~/.sandbox/logs/` (audit records)     |
| `--keep-images`    | Skip sandbox container image removal            |
| `--keep-lima`      | macOS: delete the Lima VM but leave Lima        |
| `--keep-kubetools` | Leave Helm (and kubectl on Linux) in place      |

The uninstaller removes, in order:

1. Active pods, CiliumNetworkPolicies, and secrets from the cluster
2. The `sandbox` namespace, ServiceAccount, and `gvisor` RuntimeClass
3. Container images (`sandbox:*`) from k3s containerd / Docker or Podman
4. **Linux**: k3s (and Cilium), gVisor binaries, runsc config,
   `sandbox-masquerade.service`
5. **macOS**: Lima VM `sandbox-vm` (and optionally Lima itself)
6. `~/.sandbox/` — config, kubeconfig, and session logs
7. Helm from `/usr/local/bin/helm` if setup.sh installed it (optional)

The uninstaller does **not** remove this repository directory,
Homebrew, or other Lima VMs.
