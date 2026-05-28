# Contributing to Agent Sandbox

Thanks for thinking about contributing. A few things to know before
you open a pull request.

## Before you start

**Read PRINCIPLES.md.** It documents the threat model and design
constraints this tool operates under. Changes that conflict with the
documented principles will not be merged even if they're technically
correct — but if you think a principle should change, that's a fine
thing to propose in an issue first.

For larger changes (new features, architectural shifts, anything
touching the network / filesystem isolation layers), open an issue
first to discuss the approach. It saves rework if the design needs
adjustment.

## Developer Certificate of Origin (DCO)

All commits must be signed off with the Developer Certificate of
Origin (DCO). The DCO is a lightweight per-commit affirmation that
you have the right to submit the code under this project's license.
The full text is at <https://developercertificate.org>.

Sign off your commits with `-s`:

```bash
git commit -s -m "your commit message"
```

That adds a `Signed-off-by: Your Name <your@email>` trailer. By
signing off you certify that:

1. The contribution is your own original work, or
2. It's based on a prior contribution covered by a compatible
   open-source license and you have the right to relicense it, or
3. Someone who certified the above provided it to you and you're
   passing it on unmodified.

CI rejects unsigned commits. If you forget, amend or rebase to add
the sign-off and force-push your branch (only your feature branch, not
shared branches).

## Pull request flow

1. Fork the repo and create a feature branch.
2. Make focused commits — one logical change per commit. Use
   conventional-commit-style prefixes where they fit (`feat:`, `fix:`,
   `docs:`, `refactor:`, `test:`, `ci:`).
3. Sign off every commit (`-s`).
4. Run the cluster-free test suite locally: `task test`. The network
   and filesystem tests require a running sandbox cluster.
5. Open a PR against `main`. In the description, cover:
   - What the change does and why.
   - How you tested it.
   - Anything reviewers should pay extra attention to.

## What reviewers will check

- **Does the change preserve PRINCIPLES.md?** Default-deny network,
  filesystem isolation, credential rules, tier model.
- **Scope.** The diff should match the PR description — no drive-by
  refactors or unrelated cleanup.
- **Tests.** New behavior gets new tests. Bug fixes get a regression
  test where practical.
- **Style.** Shell scripts are shellcheck-clean and start with
  `set -euo pipefail`. YAML uses 2-space indent. Prose wraps at 80
  columns; code blocks don't.
- **Backwards compatibility.** If a change is breaking, the commit
  subject ends with `[bump:major]` and the body includes a `BREAKING
  CHANGE:` paragraph explaining the migration.

If a reviewer requests changes, push additional commits to the same
branch — please don't force-push during review (the exception is
rebasing to add a missed sign-off, which is fine if you mention it).

## Reporting security issues

Don't open a public issue or PR for security problems. See
**SECURITY.md** for the private reporting channels.

## Stuck or unsure?

Open a draft PR or a discussion — we'd rather help shape something
useful than receive a polished change that has to be reworked.
