# Architecture Notes

[← Documentation](../index.md)

Background on the trickier choices in the install. Operators don't
need to read this to use the sandbox; it's here so that whoever has
to debug an unfamiliar failure mode has the rationale on hand.

## macOS workspace sync

On Linux/WSL, a tier 2/3 `--repo` is bind-mounted straight into the pod and the
agent reads and writes your working tree directly. macOS can't do that. The
repo reaches the pod through Lima's 9p mount of your home directory, and over
that mount the gVisor gofer (which runs as root) presents every file the
container creates as root-owned — so the uid-1000 agent can't create or modify
files, including the objects every `git commit` writes into `.git/`. (This is
the same layer that previously broke agent credential persistence.) We mount
the home share with 9p `securityModel: mapped-xattr` on purpose: it keeps the
sandbox's file-ownership bookkeeping in xattrs instead of writing it through to
your real files, which an earlier passthrough mount did — corrupting host file
ownership during and after sessions. Switching to virtiofs would reintroduce
that, so it's not an option.

Instead, on macOS the agent works on a **per-session VM-local ext4 copy** of
each repo (at `/var/lib/sandbox/workspaces/<session>/<repo>` inside the VM),
which is genuinely writable by the agent. A [Mutagen](https://mutagen.io)
daemon **running inside the VM** keeps that copy in near-live two-way sync with
your host repo. Because your home directory is already visible inside the VM
via the 9p mount, both sync endpoints are VM-local — there's no host-side
agent and no SSH — and because Mutagen is an ordinary VM process rather than
the gVisor gofer, it writes the 9p mount normally while mapped-xattr keeps your
host file ownership intact. Mutagen is installed into the VM automatically on
your first tier 2/3 session (a one-time download; no Homebrew dependency on the
host).

Practical notes:

- Your host repo reflects the agent's edits within a couple of seconds, and the
  agent picks up host-side edits just as quickly — close to the Linux feel.
- The masked secret paths (`.env`, `kubeconfig`, `.kube/`, `*-openrc.sh`, etc.)
  are excluded from the sync, so they never reach the VM-local copy — on top of
  the existing mount-level masking.
- Sync mode is `two-way-safe`: if the same file is changed on both sides at
  once, Mutagen flags the conflict rather than silently picking a winner. Resolve
  it on the host (or just let the agent rewrite the file).
- On a large repo the first session pauses briefly while the initial copy
  populates; subsequent edits are incremental.

## Cluster CIDRs

The setup script passes `--cluster-cidr` and `--service-cidr` to k3s
explicitly:

- **Pod CIDR** (default `100.64.0.0/10`): allocated by Cilium IPAM in
  cluster-pool mode and used by the egress MASQUERADE rule. Also passed
  as k3s `--cluster-cidr` so the Node's `.spec.podCIDR` matches the
  range Cilium actually allocates from — otherwise `kubectl get nodes`
  reports k3s' default `10.42.0.0/24` and operators waste triage time
  chasing a phantom mismatch.
- **Service CIDR** (default `10.43.0.0/16`, k3s' default): used for
  Kubernetes Service VIPs. Override with `--service-cidr` if your host
  network overlaps.

CIDRs are baked in at install time. To change them on an existing
cluster, run `./uninstall.sh` and re-run `./setup.sh` with the new
flags.

## API server port

The Kubernetes API server listens on `6443` by default — the k3s and
upstream-Kubernetes default. That default collides with anything else
on the host that expects a Kubernetes endpoint on `6443`: a common
case is local Ansible or `kubectl` tooling pointed at a cluster on
OpenStack, which silently talks to the sandbox cluster instead once
the sandbox is up.

`--apiserver-port` moves the sandbox cluster off `6443`:

```bash
./setup.sh --apiserver-port 7443
```

Unlike the CIDRs, the port can be changed on an existing cluster —
just re-run setup with the new value:

- **Linux:** `./setup.sh --apiserver-port <PORT>` is idempotent. If
  k3s is already installed on a different port it rewrites the k3s
  config (`/etc/rancher/k3s/config.yaml`, the `https-listen-port`
  key), restarts k3s, refreshes `~/.sandbox/kubeconfig`, and
  `helm upgrade`s Cilium's `k8sServicePort` to match. Running pods
  survive the restart.
- **macOS:** the port is baked into the Lima VM's host port forward
  at VM-creation time. To change it, recreate the VM:
  `limactl delete sandbox-vm` then `./setup.sh --apiserver-port <PORT>`.

The chosen port is recorded in `~/.sandbox/kubeconfig` (the `server:`
URL), so every `sandbox` command picks it up automatically.

## Resource quota sizing

The namespace `ResourceQuota` is **sized to the node at setup time**,
not hardcoded. `lib/resources.sh` reads the node's allocatable
CPU/memory, subtracts a host reservation (default `2` CPU / `6Gi` for
the OS, the k3s/Cilium stack, and your IDE/browser), and derives how
many concurrent sandbox pods fit. `setup` then generates and applies
the quota — re-run `sandbox setup` after a hardware change to resize.

Memory and CPU are treated differently, on purpose:

- **Memory is not overcommitted.** The quota's `limits.memory` equals
  the per-pod memory limit times the pod ceiling, so even if every
  sandbox bursts to its full limit at once it still fits in RAM — no
  host OOM. This is what gates concurrency.
- **CPU is overcommitted.** CPU is compressible: an over-subscribed
  core just throttles, it never OOM-kills. Per-pod CPU limits are
  allowed to sum past the core count, so CPU is not the limiter.

With the defaults (per-pod `2Gi` request / `6Gi` limit), the ceiling
is `floor((allocatable_RAM − 6Gi) ÷ 6Gi)` — e.g. a 30Gi laptop fits
4 concurrent sandboxes. To retune, edit the constants at the top of
`lib/resources.sh` (`POD_MEM_LIMIT_GI`, `HOST_RESERVE_MEM_GI`, …) and
re-run `sandbox setup`: a smaller per-pod memory limit trades single-
session burst headroom for more concurrent sessions.

## gVisor + Cilium ClusterIP routing

Cilium is installed with `socketLB.hostNamespaceOnly=true`. This is
**required** for gVisor pods to reach ClusterIP services (including
CoreDNS).

Cilium's default socket-LB rewrites Service ClusterIPs at the host
kernel's cgroup `connect()` hook. gVisor pods never reach that hook
because their `connect()` syscall is handled by gVisor's userspace
netstack, not the host kernel — so without this flag, ClusterIP→PodIP
translation never happens for sandbox pods. Symptoms include `nslookup`
hangs, TLS handshake timeouts to external services (because DNS to the
in-cluster CoreDNS service times out), and silent packet loss to
`10.43.0.10:53`. The pattern is especially severe on hosts with an
active VPN (`tun0` etc.), where the untranslated ClusterIP packet falls
through to the VPN as the default route and is dropped at the corporate
edge.

With `socketLB.hostNamespaceOnly=true`, Cilium installs TC-based LB
programs on pod veths instead. These run on the host side of the veth
and DNAT the packet in transit — after gVisor builds it, before host
routing — so gVisor pods can reach Service VIPs normally.

To apply this on an existing cluster without a full reinstall:

```bash
helm upgrade cilium cilium/cilium \
  --kubeconfig ~/.sandbox/kubeconfig \
  --namespace kube-system \
  --reuse-values \
  --set socketLB.hostNamespaceOnly=true
kubectl --kubeconfig ~/.sandbox/kubeconfig -n kube-system rollout restart ds/cilium
```
