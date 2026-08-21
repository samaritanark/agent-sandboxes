# Local k3d Cluster on Podman

[← Documentation](../index.md)

If you have your own local Kubernetes cluster — a [k3d](https://k3d.io/)
cluster whose nodes run as [podman](https://podman.io/) containers — you can
give an agent session `kubectl`/`helm` access to it the same way you'd give it
access to any external cluster: **Tier 3** and `--infra-kubeconfig`. See
[Tier 3 infra credentials](tier3-infra-credentials.md) for the general
mechanism; this page covers the one thing that's specific to a cluster
running on the same machine as the sandbox.

Prerequisite: k3d needs a Docker-API-compatible endpoint to talk to, so it's
pointed at podman's socket. On **rootless** podman (the recommended setup on
a machine that also runs agent-sandboxes — rootful podman's netavark can
collide with Cilium for control of the root network namespace) that's
`DOCKER_HOST=unix:///run/user/<uid>/podman/podman.sock`, or a
`/var/run/docker.sock` symlink pointed at the same path. On rootful podman
it's `/run/podman/podman.sock`. If your `k3d cluster create` and `k3d
kubeconfig get` commands already work against your podman containers, you're
past this step — see your platform's podman/k3d setup guide if not.

## Why `127.0.0.1` doesn't work

`k3d kubeconfig get` writes a kubeconfig whose `server:` field points at
`127.0.0.1:<port>` (or `0.0.0.0:<port>`). That's correct for `kubectl` running
directly on your host — but an agent session's `kubectl` runs **inside a pod**,
in its own network namespace. `127.0.0.1` there means "this pod," not "the
machine podman is running on." `sandbox run --infra-kubeconfig` rejects a
loopback `server:` address outright at launch, before creating anything, with
an error pointing at the fix below — rather than silently letting the session
launch against an address that can never work once mounted into the pod.

This isn't a rootless-podman-specific wrinkle, and rootless isn't an extra
obstacle here: a published port's listener (`rootlessport`, or `pasta` in
newer setups) runs in the host's real network namespace regardless of the
container being rootless. The fix below works the same way whether podman is
rootful or rootless — the only thing that actually needs fixing is the
`server:` address itself: rewrite it to the host's **primary** interface IP
instead of loopback (`examples/k3d-podman/bake-kubeconfig.sh` does this for
you — see Steps below).

That address is reachable from inside a Tier 3 pod via Cilium's `reserved:host`
identity: `sandbox run` detects that the resolved API server IP is one of the
host's own addresses and, only in that case, grants the port both via
`toCIDR` and via `toEntities: host` — see `lib/policy.sh`. This detection
matters: `toEntities: host` matches on the sandbox's own node rather than the
resolved IP, so it's granted only for this same-node case, never for a
genuinely remote cluster, to avoid opening every Tier 3 pod's egress to the
sandbox's own control plane. The host-entity path is routed entirely inside
Cilium's kernel datapath, the
same way pods normally reach kubelet, so it doesn't depend on the host's NIC
or switch being able to "hairpin" a packet back to the machine that sent it —
a capability that turns out not to be universal (confirmed absent on both
Wi-Fi and wired Ethernet on real hardware) and would otherwise make this whole
setup flaky depending on what network you're on.

## Steps

1. Bake a rewritten kubeconfig:

   ```bash
   examples/k3d-podman/bake-kubeconfig.sh <k3d-cluster-name>
   ```

   This fetches the cluster's kubeconfig, detects the host's primary routable
   IPv4 (`ip -4 route get 1.1.1.1`), and rewrites `server:` to use it instead
   of `127.0.0.1`/`0.0.0.0`. Output goes to
   `~/.kube/sandbox-k3d-<cluster-name>.yaml`, `chmod 0600`.

2. Smoke-test that the API server is actually listening on that address,
   **from the host**:

   ```bash
   curl -k https://<primary-ip>:<port>/version
   ```

   A response (even a `401` — that's expected, this curl carries no
   credentials) confirms k3d/podman published the port somewhere real. Treat
   this as a check that the port exists, not proof the pod can reach it — a
   bare host-to-itself connection like this one resolves through the
   kernel's local-address shortcut and will "succeed" even in cases that
   don't actually say anything about pod reachability. The real test is
   step 4.

3. Launch a Tier 3 session against it:

   ```bash
   sandbox run --agent claude --tier 3 --repo ~/repos/your-repo \
     --infra-kubeconfig ~/.kube/sandbox-k3d-<k3d-cluster-name>.yaml
   ```

   Watch for `bin/sandbox`'s own `Auto-allowlisting: <ip>:<port>` line at
   launch — it should show the primary IP, confirming the CIDR it derived is
   the one you expect.

4. Inside the session, confirm end-to-end reachability:

   ```bash
   kubectl get nodes
   kubectl get pods -A
   ```

## Scope

This recipe hands the agent k3d's own admin kubeconfig — client-certificate
auth, full cluster-admin on that cluster. That's a reasonable default for a
disposable local dev cluster, but if you want the agent scoped to less than
admin, use the ServiceAccount-token recipe in
[Tier 3 infra credentials](tier3-infra-credentials.md) instead: it's one
`kubectl create sa` / `kubectl create clusterrolebinding` against the same
k3d cluster, with whatever `--clusterrole` you choose.

## Teardown

`sandbox stop` already deletes the session's `kubeconfig-<session_id>` Secret
automatically — no extra cleanup needed. Because the cluster and its CA are
local and disposable, credential-rotation risk is low, but the admin
certificate baked here stays valid until the k3d cluster itself is deleted or
recreated.

## macOS

Not covered by this recipe as written. On macOS, the sandbox's own cluster
runs inside a Lima VM, and podman machine runs in its own, separate VM with
user-mode networking and no shared bridge between the two — the same
Lima-can't-see-the-host's-interfaces problem
[corporate-vpn.md](corporate-vpn.md#macos--lima) describes for VPN tunnels
applies here to podman machine's VM. Reaching a local k3d cluster from a
macOS sandbox session would need either a `portForwards:` entry added to
`lima/sandbox-vm.yaml.tmpl` for the k3d API port, or podman machine's
forwarded port bound to a Mac-host interface that Lima's network can actually
reach.
