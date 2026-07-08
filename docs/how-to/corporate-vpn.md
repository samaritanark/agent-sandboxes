# Reaching Clusters Behind a Corporate VPN (Linux)

[← Documentation](../index.md)

If `--infra-kubeconfig` points at a Kubernetes API server reachable only
through a host VPN tunnel (e.g. an internal `10.x.x.x` address routed
via `tun0`/`wg0`/`utun0`), Cilium needs to know about the VPN interface
so pod egress to VPN-routed subnets gets SNAT'd to the tunnel's source
IP. Otherwise the packet leaves with the raw pod IP and the VPN gateway
drops it as unknown.

**Setup-time** (`setup.sh`): if a VPN interface is up when you run
setup, the installer detects it (via the `POINTOPOINT` link flag) and
applies three Cilium settings via `helm upgrade`:

- `devices='{<primary>,<vpn>}'` — list of interfaces Cilium manages.
- `extraConfig.direct-routing-device=<primary>` — required when
  `devices` has more than one entry.
- `extraConfig.egress-masquerade-interfaces=''` — default behavior;
  Cilium SNATs to the IP of whichever interface a packet exits through.

No VPN at setup time? The installer skips the change and Cilium uses
its single-NIC default.

**When the host network changes.** Two distinct kinds of drift can
strand the cluster:

1. **Interface names change.** You move between wifi, wired ethernet,
   and a dock/USB adapter, or the VPN drops and reconnects — often
   across a reboot. Cilium's pinned `devices` /
   `direct-routing-device` list ends up pointing at an interface that
   is now down or has no IP. Cilium reads that list only at agent
   startup, so the stale pin survives until the DaemonSet restarts.
   Visible symptom: **new sandboxes stuck in `ContainerCreating`** with
   `cilium-cni` endpoint errors and `IPv4 direct routing device IP not
   found` in the Cilium agent log.

2. **Primary IPv4 changes but the interface name stays the same.** The
   canonical case on Windows: every reboot, the WSL2 `sandbox-vm`
   distro comes up with a fresh address from the Hyper-V virtual NAT,
   but `eth0` is still `eth0`. Also happens on Linux laptops with DHCP
   lease changes or SSID swaps. kubelet keeps the old node
   `InternalIP`, the k3s API-server serving cert SANs are stale, and
   Cilium's BPF masquerade source still points at the prior IP — fix
   requires a `systemctl restart k3s` plus a Cilium DaemonSet restart.

You normally don't need to do anything about either: **`sandbox run`
checks both on every launch** and reconciles whichever has drifted. An
IP change triggers a heavier restart (k3s + Cilium + CoreDNS bounce,
~1-2 min); a name-only change is the lighter Cilium-only restart. Any
sandboxes already running may see a brief network blip. When nothing
has changed the checks are silent no-ops.

To re-apply without starting a sandbox — e.g. right after reconnecting
a VPN, or after a WSL2 distro restart, so already-running sandboxes
pick up the new routing — run it explicitly:

```bash
sandbox configure-network
```

That re-detects the current primary IPv4 and the primary + VPN
interface names, reconciles k3s and Cilium to match, and restarts
whichever components need it. It is idempotent — it does nothing if
nothing has drifted. The VPN-down case is handled symmetrically: if a
VPN was configured earlier and is now gone, the stale multi-device
list is reset to a single-NIC pin so the dead `tun0`/`wg0` entry can't
break endpoint creation. Both the explicit command and the automatic
check on `run` are skipped on non-Linux hosts.

**macOS / Lima**: not supported. The cluster runs inside the Lima VM,
which doesn't see the macOS host's `utun*` interfaces — VPN-routed
clusters from macOS would need a different topology (e.g. running the
VPN inside the Lima VM, or an egress proxy on the host).
