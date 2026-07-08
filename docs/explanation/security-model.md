# Security Model

[← Documentation](../index.md)

For the design intent and threat model behind these controls, read
[PRINCIPLES.md](../../PRINCIPLES.md).

- **Kernel isolation**: gVisor (runsc) for all pods
- **Network**: Cilium with `policyEnforcementMode: always`;
  per-session CiliumNetworkPolicy
- **Filesystem**: `.env`, `.npmrc`, `clouds.yaml`, and any `kubeconfig`/`.kube/`
  in the workspace are masked with emptyDir overlays. The only kubeconfig that
  ever enters the pod is one explicitly passed via `--infra-kubeconfig`, which
  is minified to a single context, mounted as a K8s Secret at
  `/home/agent/.kube/config`, and deleted on teardown.
- **Secret gate**: before every Tier 2/3 launch each `--repo` is scanned
  with [betterleaks](https://github.com/betterleaks/betterleaks). A secret
  found in a file the mask would **not** hide aborts the launch — the agent
  never sees a workspace secret you forgot about. The error names the
  offending path and gives a `sandbox mask add` command to hide it (see
  [Extending the mask](#extending-the-mask) below). betterleaks is required for
  Tier 2/3; if it is missing, the launch fails closed.
  `--i-accept-unmasked-secrets` on `sandbox run` prints the findings and
  launches anyway.
- **Credentials**: claude/codex use OAuth (no API key injection);
  opencode key via K8s Secret; tier 3 infra creds via per-session Secrets
  (`--infra-token` → `$INFRA_TOKEN`; `--infra-kubeconfig` → mounted file)
- **Pod security**: non-root UID 1000, all capabilities dropped,
  no privilege escalation
- **Service account**: `automountServiceAccountToken: false`,
  no RBAC bindings

## Extending the mask

The built-in mask covers a fixed root-level set (`.env`, `.env.local`,
`.npmrc`, `clouds.yaml`, `kubeconfig`, `.kube/`, `*-openrc.sh`). To hide
additional files — including nested ones — add them per-repo:

```bash
# Hide a nested config the secret gate flagged
sandbox mask add --repo ~/repos/app config/prod/secrets.yaml

# See the effective mask (built-in + configured) for a repo
sandbox mask list --repo ~/repos/app
```

`mask add` records each path under `masked_paths:` in
`<repo>/.sandbox/config.yaml`; at launch those paths are mounted as empty
overlays exactly like the built-in set (and excluded from the macOS
workspace sync). Re-running `sandbox run` then passes the gate.
