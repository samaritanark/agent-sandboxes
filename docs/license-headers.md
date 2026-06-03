# License header convention

Every source file we author carries a two-line SPDX header. The full
license text lives once at the repository root (`LICENSE`); per-file
headers just point at it, so they stay short and machine-readable
(SPDX tooling and license scanners parse `SPDX-License-Identifier`
directly).

## The header

Use the comment syntax for the file's language. The two lines are
always the same:

```
SPDX-License-Identifier: Apache-2.0
Copyright 2026 Samaritan Ark
```

### Shell scripts (`.sh`, and `bin/sandbox`)

The header goes **after** the shebang, before any code:

```bash
#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan Ark
```

### YAML (`.yaml`, `.yml`) and Dockerfiles

```yaml
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan Ark
```

### PowerShell (`.ps1`)

```powershell
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samaritan Ark
```

## Rules of thumb

- **One header per source file we wrote.** Add it to new files at
  creation time.
- **Update the year on substantive change, don't accumulate ranges.**
  A single `Copyright <current-year> Samaritan Ark` is enough; we don't
  maintain `2024-2026`-style ranges per file.
- **Don't add headers to generated, vendored, or third-party files.**
  If we ever vendor external code, it keeps its original header and is
  listed in `NOTICE` instead.
- **Tiny non-code files don't need a header** (e.g. `.gitignore`,
  fixture data, `*.md` docs). When in doubt, add it — it's harmless.
- **Contributors keep their own copyright.** Apache 2.0 is inbound =
  outbound; a contributor may add their own `Copyright <year> <name>`
  line beneath ours rather than replacing it.
