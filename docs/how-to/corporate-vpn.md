# Hosts and Clusters Behind a Corporate VPN

[← Documentation](../index.md)

In v3 the sandbox VM has no network device of its own on your machine's
networks. Its only network is `sandbox netd`, a part of the host binary: each
connection the VM opens is made again by netd, as an ordinary connection from
your machine. So the VM's traffic follows your machine's routing table, VPN
routes included, and corporate endpoint software sees it as traffic from a
process on your machine.

That means:

- **A host reached through your VPN** (an internal address routed over
  `utun0`, `tun0`, or `wg0`) is reached the way your machine reaches it, as
  long as the session's allowlist allows it (`--allow-domain`, a profile, or
  [persistent domains](persistent-domains.md)). There is nothing to configure
  in the VM, and nothing to redo when the VPN reconnects or you change
  networks: v2's `sandbox configure-network` is gone.
- **Names your VPN's DNS serves**: the VM's DNS also goes through netd to your
  machine's resolver. Split DNS for VPN zones has not been verified yet.
- **Addresses of your machine itself** (loopback, its LAN addresses) are not
  reachable from the VM, except an address and port a tier 3 launch declares
  for its cluster or `--infra-endpoint` (see [Tier 3 infra
  credentials](tier3-infra-credentials.md#clusters-and-endpoints-on-your-machine)).

> **Not yet verified.** VPN-routed destinations through netd are part of the
> design but have not been tested end to end (spike S7 lists them as open).
> If a VPN-only host is unreachable from a session but reachable from your
> machine, check `sandbox flows <session>` for the connection and report it.

With `--driver lima` the VM uses Lima's network instead of netd; whether VPN
routes apply then depends on Lima.
