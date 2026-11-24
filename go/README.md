# Go port of the policy layer (v3, decision D-34)

This module is the in-progress port of the bash policy layer (`bin/sandbox`,
`lib/*.sh`) described in `docs/design/v3-architecture.md` §5.4.1 and spike S8
(`docs/design/spikes/S8.md`).

**Continuing this work?** Start with the "Start here" section near the end of `S8.md`. It holds
the current status, the next steps, and what each development machine has installed. Agent
memory does not travel between machines.

The v2 bash stays in the tree, frozen, as the **oracle** until release. Each ported
unit is checked against it two ways:

- **Golden files** (`internal/*/testdata`): the bash oracle's answers, generated on
  Linux (`awk` is `mawk` there) over fixtures and a seeded mutation corpus, and
  committed. Go tests run anywhere and compare against them.
- **Live oracle** (`SBX_ORACLE=1`, Linux only): runs the bash itself over the same
  cases, so a golden file cannot go stale unnoticed. In CI (`CI` set) a test that
  cannot run its live oracle fails; it does not skip.

Layout so far:

| Path | Port of |
|---|---|
| `internal/bashcompat` | the bash and tool behaviours the port reproduces (field splitting, arithmetic, globs, `printf %q`); a caller of this package is carrying a quirk |
| `internal/config` | `lib/config.sh` and `resolve_overlay_path`: the flat YAML readers, overlay resolution, ignore-file parsing |
| `internal/gate` | the secret gate in `lib/filesystem.sh`: `finding_is_encrypted`, `is_path_masked`, `_leakscan_finding_accepted`, `scan_repo_secrets` and its helpers, `secret_gate_repos` |
| `internal/vetting` | all of `lib/vetting.sh`: posture and configuration, tag verification, the launch gate, committed exceptions, attestation |
| `internal/archtest` | the import-graph rules of section 5.1.1 (a package may import only what the table allows) |

**Deliberate deviations.** Quirks of the bash found while porting are fixed as named
deviations (`internal/deviation`). The differential tests (golden files and live
oracle) run in legacy mode, with every fix off, so they keep proving the port matches the
bash; each fix has its own test in `fixes_test.go`. The fixes are on in production.

Not yet here (see S8): the host binary, the policy CLI, `sandboxd`, and the
import-graph check from §5.1.1.

## Regenerating the corpus and the oracle's answers

From the repo root (Go on the host; the oracle step needs a Linux machine with bash 5 and the repo's `lib/`):

```bash
go/internal/gate/testdata/encrypted/gen-fixtures.sh                      # fixtures extracted from tests/test-secret-gate.sh
(cd go && go run ./internal/gate/internal/gencorpus -base internal/gate/testdata/encrypted -seed 1 -n 250)
# on Linux, from the repo root, with LC_ALL=C:
cd go/internal/gate/testdata/encrypted
LC_ALL=C ./oracle.sh cases-fixtures.tsv > golden-fixtures.tsv
LC_ALL=C ./oracle.sh cases-mutants.tsv  > golden-mutants.tsv
# then, anywhere:
(cd go && go test ./...)
# and on Linux, to re-run the bash live from the Go tests (what CI does, .github/workflows/go.yaml):
(cd go && SBX_ORACLE=1 go test ./...)
```

Pilot 2 (`testdata/masked`, `testdata/accepted`) regenerates the same way:

```bash
(cd go && go run ./internal/gate/internal/genmasked -base internal/gate/testdata/masked -seed 1 -n 75)
go/internal/gate/testdata/accepted/gen-cases.sh
# on Linux, with LC_ALL=C:
go/internal/gate/testdata/masked/oracle.sh masked > go/internal/gate/testdata/masked/golden-masked.tsv
go/internal/gate/testdata/masked/oracle.sh lists  > go/internal/gate/testdata/masked/golden-lists.tsv
GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null go/internal/gate/testdata/accepted/oracle.sh > go/internal/gate/testdata/accepted/golden-accepted.tsv
```

Pilot 3 (`testdata/scan`, a stub scanner plus fixture repos; the oracle prints the gate's output and the stub's log):

```bash
(cd go && go run ./internal/gate/internal/genscan -base internal/gate/testdata/scan -seed 1 -n 63)
# on Linux, with LC_ALL=C, from anywhere:
go/internal/gate/testdata/scan/oracle.sh > go/internal/gate/testdata/scan/golden-scan.txt
```

Pilot 4 (`testdata/gate`, reusing the pilot-3 fixtures and stub; needs `python3` for the pty):

```bash
(cd go && go run ./internal/gate/internal/gengate -base internal/gate/testdata/gate -seed 1 -n 15)
# on Linux, with LC_ALL=C.UTF-8 (printf %q depends on the locale):
LC_ALL=C.UTF-8 go/internal/gate/testdata/gate/oracle.sh > go/internal/gate/testdata/gate/golden-gate.txt
```

Vetting config (`internal/vetting/testdata/config`; the oracle uses a `date` shim for a fixed clock):

```bash
(cd go && go run ./internal/vetting/internal/genvet -base internal/vetting/testdata/config -seed 1 -users 105 -overlays 68)
# on Linux, with LC_ALL=C:
LC_ALL=C go/internal/vetting/testdata/config/oracle.sh > go/internal/vetting/testdata/config/golden-config.txt
```

Vetting verification (`internal/vetting/testdata/verify`; builds git repos with SSH-signed tags, needs `ssh-keygen`):

```bash
go/internal/vetting/testdata/verify/gen-cases.sh
# on Linux, with LC_ALL=C.UTF-8:
LC_ALL=C.UTF-8 go/internal/vetting/testdata/verify/oracle.sh > go/internal/vetting/testdata/verify/golden-verify.txt
```

Vetting gate (`internal/vetting/testdata/gate`; scripted status lines, so no git; needs `python3` for the pty):

```bash
(cd go && go run ./internal/vetting/internal/genvgate -base internal/vetting/testdata/gate -seed 1 -n 55)
# on Linux, with LC_ALL=C.UTF-8:
LC_ALL=C.UTF-8 go/internal/vetting/testdata/gate/oracle.sh > go/internal/vetting/testdata/gate/golden-gate.txt
```

Exceptions and signing-key state (`internal/vetting/testdata/exc`; builds git repos with SSH-signed tags):

```bash
go/internal/vetting/testdata/exc/gen-cases.sh
# on Linux, with LC_ALL=C.UTF-8:
LC_ALL=C.UTF-8 go/internal/vetting/testdata/exc/oracle.sh > go/internal/vetting/testdata/exc/golden-exc.txt
```

Attestation (`internal/vetting/testdata/attest`; real SSH signing, git 2.56 or newer, `python3` for the pty):

```bash
go/internal/vetting/testdata/attest/gen-cases.sh
# on Linux, git >= 2.56, LC_ALL=C.UTF-8:
LC_ALL=C.UTF-8 go/internal/vetting/testdata/attest/oracle.sh > go/internal/vetting/testdata/attest/golden-attest.txt
```

The committed golden files were produced with GNU awk 5.2.1 under `LC_ALL=C` on Ubuntu 24.04
(arm64). `mawk` 1.3.4 gives the same answers in both the C and C.UTF-8 locales; `gawk` under
`C.UTF-8` differs on lines with multibyte text (see `docs/design/spikes/S8.md`).
