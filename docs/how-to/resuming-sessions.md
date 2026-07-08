# Resuming Sessions

[← Documentation](../index.md)

By default, disconnecting from a session (Ctrl-D, `exit`, or losing the
terminal) tears the pod down to free cluster resources. Conversation
history is preserved on the host at `~/.sandbox/agent-home/<agent>/`
and survives pod deletion, so a fresh `sandbox run` followed by the
agent's own `/resume` command (Claude Code, Codex, OpenCode) restores
prior conversations.

To keep the pod alive across disconnects — e.g. while a long-running
build is in flight — pass `--keep-alive` to `run` or `resume`. With
the pod still running, reconnect via `kubectl exec`-style attach:

```bash
sandbox run --agent claude --tier 2 --repo ~/repos/foo --keep-alive
sandbox resume <SESSION_ID> [--keep-alive]
```

Sessions use `restartPolicy: Always` — the pod's `sleep infinity`
container automatically restarts after a node reboot, so a kept-alive
session survives reboots too. (The agent itself is launched via
`kubectl exec`, not as PID 1; the container just waits.)

A systemd service (`sandbox-masquerade.service`) re-applies the pod
egress MASQUERADE iptables rule on every boot so network access is
restored alongside the pod. The rule is scoped to the pod CIDR
(default `100.64.0.0/10`) so pods can reach hosts on the host's own
network (including corporate `10.x.x.x` ranges). Use `--pod-cidr`
at setup time if your network overlaps with the default.
