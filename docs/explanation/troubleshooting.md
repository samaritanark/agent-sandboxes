# Troubleshooting

[← Documentation](../index.md)

Diagnose with `sandbox status` first — it surfaces most install-level
issues. For runtime failures, the patterns below cover the common
cases. See [Diagnostic subcommands](../reference/cli.md#diagnostic-subcommands)
for the full toolkit.

**`⚠ Cross-session messaging is off: its socket directory could not be set up:
'/tmp' is world-writable without the sticky bit ...`** printed once at agent
startup. **Expected inside the sandbox, and harmless — nothing is broken.**
Cross-session messaging lets multiple agent sessions on one machine talk to each
other; a sandbox runs **one agent per pod**, so there is no peer to reach and the
feature does not apply. The pod's `/tmp` is a per-session `emptyDir` that
Kubernetes makes world-writable without the sticky bit (the pod's `fsGroup` owns
it `root:1000`, mode `2777`), and the agent CLI declines to place its messaging
socket in such a directory — the safe choice. The session is otherwise
unaffected and **no action is needed**; `/status` inside the agent will show the
inbox as `unavailable` with this reason. This is deliberate: the sandbox does
**not** make the socket usable, because enabling cross-session messaging inside a
pod would widen what a compromised agent could reach.

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

**`kubectl` hangs or times out reaching the Tier 3 API server, despite a
correct `--infra-kubeconfig`.** If the infra cluster's API server happens to
be running on the *same physical machine* as the sandbox itself (e.g. a
local k3d/podman cluster used for testing), a plain IP-based egress rule
gets masqueraded out the host's primary network interface — which then
needs the interface/switch to "hairpin" the packet back to the same
machine, something not every network supports (seen failing identically
over both Wi-Fi and wired Ethernet). `bin/sandbox` detects this same-node
case (the resolved API server IP matches one of the host's own addresses)
and `lib/policy.sh` then grants the API port via Cilium's `reserved:host`
identity in addition to the ordinary CIDR rule specifically to route around
this — no physical NIC involved, so no hairpin needed. This grant is only
added for the same-node case, never for a genuinely remote cluster — see
[Local k3d cluster on podman](../how-to/local-k3d-podman.md) for why. If
you still see this hang against a local cluster on an up-to-date install,
confirm the applied policy actually carries the rule:
`kubectl get ciliumnetworkpolicy -n sandbox policy-<session-id> -o yaml`
should show a `toEntities: [host]` entry alongside the `toCIDR` one.

If a session reaches the cluster but then gets unexpected `403 Forbidden`
from `kubectl`, that's RBAC on the target cluster — the
ServiceAccount your token came from doesn't have the verb/resource the
agent tried. Widen the role, or scope the agent's task narrower. See
the ServiceAccount-token recipe in [Tier 3 Infra
Credentials](../how-to/tier3-infra-credentials.md).
