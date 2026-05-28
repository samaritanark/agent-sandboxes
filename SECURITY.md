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

- Sandbox escape or privilege escalation from inside the agent pod
  into the host or other pods.
- Bypasses of the default-deny network egress (the agent reaching
  hosts not on its tier allowlist).
- Bypasses of the filesystem mask (sensitive paths visible inside the
  pod that should not be).
- Credential leakage — host-side secrets becoming readable inside a
  session that should not have them.
- Vulnerabilities specific to the container images built by this
  repository (not upstream-introduced).

**Out of scope:**

- Vulnerabilities in third-party components (gVisor, Cilium, k3s, the
  LLM provider, agent binaries). Report those upstream; we'll track
  and integrate upstream fixes.
- Issues that require host root access to exploit.
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
themselves. Adopters who build the images locally should run their own
image scanner (e.g. `trivy image sandbox:base`) as part of their build
pipeline.

## Disclosure

We follow coordinated disclosure: report privately, work together on a
fix, publish details when a patch is available. We will credit
reporters in the release notes unless you ask us not to.
