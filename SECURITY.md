# Security policy

If you've found a security issue in Agent Sandbox, report it **privately**
— do not open a public issue.

## How to report

**Preferred channel — GitHub Security Advisories.** On the repository
page, click "Security" → "Report a vulnerability." This opens a private
thread with the maintainers where you can share details, get triage
updates, and discuss disclosure timing.

## Scope

**In scope:**

- Escape from an agent's or a dependency's microVM, or from a session's
  gateway, into the appliance VM, another session, or your machine.
- Reaching your machine from the appliance VM beyond the SSH channel and
  the workspace sync (for example a `sandbox netd` bypass), or a VM-to-host
  data flow the host binary accepts without validating.
- Bypasses of the default-deny network egress (the agent reaching hosts
  not on its tier allowlist, or around its gateway).
- Credential leakage: a brokered credential's value reaching the agent, a
  placeholder working toward a host it is not bound to, or a host-side
  secret pushed to the VM for a launch that did not name it.
- Bypasses of the sync gate (an agent's change to a host-exec vector
  reaching your checkout without review) or of the filesystem mask.
- Vulnerabilities specific to the appliance image or the agent images
  built by this repository (not upstream-introduced).

**Out of scope:**

- Vulnerabilities in third-party components (Kata Containers, Cloud
  Hypervisor, containerd, Envoy, the hypervisor on your machine, the LLM
  provider, agent binaries). Report those upstream; we'll track
  and integrate upstream fixes.
- Issues that require root on your machine to exploit.
- What root in the appliance VM can do that PRINCIPLES.md and the
  security model already list as accepted (reading the broker store and
  other sessions' workspace copies).
- Issues that arise only when an operator deliberately weakens the
  configuration. See PRINCIPLES.md "Never permitted regardless of
  tier" — the design does not protect against operator decisions that
  remove sandbox controls.

## Response expectations

This project is maintained at volunteer pace. We aim for an initial
response within roughly a week. We cannot commit to specific patch
timelines, but URGENT reports get prioritized.

## Automated monitoring

Dependabot watches GitHub Actions versions and the Dockerfile base
image; Trivy scans the working tree on every push and weekly for
misconfigurations, secrets, and known CVEs. Findings surface in the
repository's "Security" tab.

CI does not currently build and scan the agent container images
themselves; they are built in the appliance VM with `sandbox rebuild`.
Adopters should run their own image scanner on them as part of their
build pipeline.

## Disclosure

We follow coordinated disclosure: report privately, work together on a
fix, publish details when a patch is available. We will credit
reporters in the release notes unless you ask us not to.
