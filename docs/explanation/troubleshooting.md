# Troubleshooting

[← Documentation](../index.md)

Diagnose with `sandbox status` first — it surfaces most install-level
issues. For runtime failures, the patterns below cover the common
cases. See [Diagnostic subcommands](../reference/cli.md#diagnostic-subcommands)
for the full toolkit.

**Agent CLI can't reach `api.anthropic.com` / `api.openai.com`**
(`ECONNREFUSED` or `ETIMEDOUT` shortly after the agent banner appears).
First time you ran the agent? Step through OAuth — the agent prints a
URL; open it in a browser, log in, paste the code back. Already
OAuth'd? Check the cluster is healthy:

```bash
kubectl --kubeconfig ~/.sandbox/kubeconfig -n kube-system \
  get pods -l k8s-app=cilium     # all Running, 1/1 Ready?
sandbox status
```

If you switched networks or reconnected a VPN while a sandbox was
already running, that pod's networking can go stale — `sandbox run`
re-checks interfaces for *new* sessions, but a live pod won't pick up
the change. Run `sandbox configure-network` to re-apply and restart
Cilium.

**`kubectl` inside the pod times out reaching the API server.** Almost
always a route or DNS problem, not auth. From the **host**:
`getent hosts <api-server-host>` must return an IP, and
`ip route get <that-ip>` must show a real interface. If the IP routes
via your VPN's `tun0`/`wg0`, run `sandbox configure-network` so the
pod's egress packets get SNAT'd to the VPN interface IP. See
[Reaching Clusters Behind a Corporate VPN](../how-to/corporate-vpn.md) for
the full story.

**`kubectl` inside the pod fails with `ECONNREFUSED` or
`exec: ... no such file or directory`.** Your kubeconfig has an
`exec:` credential plugin (tsh / aws / gcloud / kubelogin) that the
sandbox image doesn't carry. Bake static credentials before mounting
— see the ServiceAccount-token recipe in [Tier 3 Infra
Credentials](../how-to/tier3-infra-credentials.md) or
`examples/teleport/bake-kubeconfig.sh` for Teleport.

**Pod stuck in `Pending` after `sandbox run`.** Usually one of:

- *Image not present in k3s containerd.* `kubectl --kubeconfig
  ~/.sandbox/kubeconfig -n sandbox describe pod <pod-name>` will say
  "ErrImageNeverPull". Fix with `sandbox rebuild --agent <name>`
  (and `--tier3` if you were launching Tier 3).
- *gVisor RuntimeClass missing.* `sandbox status` will say so; re-run
  `./setup.sh`.
- *Out of cluster resources.* Single-node k3s is small; check
  `kubectl describe pod` for Insufficient CPU/memory and stop other
  sessions with `sandbox stop`.

**New sandboxes stuck in `ContainerCreating` after a reboot or network
change.** `kubectl --kubeconfig ~/.sandbox/kubeconfig -n sandbox
describe pod <pod-name>` shows `failed to setup network ... plugin
type="cilium-cni"` errors (`429`, `timeout exceeded`, or `EOF`), and
`kubectl -n kube-system logs -l k8s-app=cilium` repeats `IPv4 direct
routing device IP not found`. Cilium's pinned device list points at an
interface that is now down — typically a wifi/ethernet/dock switch or
an unplugged USB adapter. `sandbox run` auto-corrects this on its next
launch; to fix it immediately run `sandbox configure-network`. See
[Reaching Clusters Behind a Corporate VPN](../how-to/corporate-vpn.md) for
the full story.

**`Cannot reach Kubernetes cluster` from any sandbox command.** k3s
isn't running. `sudo systemctl status k3s` then `sudo systemctl start
k3s`; if it won't start, `sudo journalctl -u k3s --no-pager -n 50`.

**`Tier 3 requires at least one of --infra-token or --infra-kubeconfig`.**
You asked for `--tier 3` but didn't pass a credential. Either pass
one of the flags or drop to `--tier 2` if you only need package
registry access.

**`kubeconfig uses exec credential plugin '<binary>'`** at launch.
The detector saw an `exec:` block in your kubeconfig. Answer `n` and
bake static credentials (see [Tier 3 Infra
Credentials](../how-to/tier3-infra-credentials.md)). Answer `y`
only if you also passed `--infra-token` and the kubeconfig is a
non-essential fallback — kubectl calls will fail.

**Hostname for the API server doesn't resolve inside the pod.** The
sandbox auto-pins a `hostAlias` for the API server hostname using
the host's resolver, so this should be rare. If it still fails, your
hostname only resolves via a VPN-side DNS that the host's
`/etc/resolv.conf` doesn't see either — fix `getent hosts <name>` on
the host first, then re-run `sandbox run`.

If a session reaches the cluster but then gets unexpected `403 Forbidden`
from `kubectl`, that's RBAC on the target cluster — the
ServiceAccount your token came from doesn't have the verb/resource the
agent tried. Widen the role, or scope the agent's task narrower. See
the ServiceAccount-token recipe in [Tier 3 Infra
Credentials](../how-to/tier3-infra-credentials.md).
