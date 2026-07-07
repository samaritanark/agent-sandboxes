# Running Tests

[← Documentation](../index.md)

```bash
# Cross-platform / unit tests (no cluster needed)
bash tests/test-audit.sh
bash tests/test-blocked-domains.sh
bash tests/test-cross-platform.sh

# Cluster tests (cluster required)
bash tests/test-gvisor.sh
bash tests/test-default-deny.sh
bash tests/test-claude-tier1.sh
bash tests/test-codex-tier1.sh
bash tests/test-opencode-tier1.sh
bash tests/test-tier2-network.sh
bash tests/test-tier3-network.sh
bash tests/test-filesystem.sh
bash tests/test-credentials-claude.sh
bash tests/test-credentials-opencode.sh
bash tests/test-serviceaccount.sh

# Inside-out boundary measurement with controlplaneio/sandbox-probe.
# Needs `go` (to build the probe) or a prebuilt binary via SANDBOX_PROBE_BIN.
# Runs the probe inside Tier 1/2 pods and diffs against a host baseline to
# confirm credentials, host sockets, and the host process table stay hidden.
bash tests/test-probe.sh
```
