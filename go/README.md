# Go port of the policy layer (v3, decision D-34)

This module is the in-progress port of the bash policy layer (`bin/sandbox`,
`lib/*.sh`) described in `docs/design/v3-architecture.md` §5.4.1 and spike S8
(`docs/design/spikes/S8.md`).

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
| `internal/gate` | the secret gate in `lib/filesystem.sh` (`finding_is_encrypted` first) |

Not yet here (see S8): the host binary, the policy CLI, `sandboxd`, and the
import-graph check from §5.1.1.

## Regenerating the corpus and the oracle's answers

From the repo root (Go on the host; the oracle step needs a Linux machine with bash 5 and the repo's `lib/`):

```bash
go/internal/gate/testdata/encrypted/gen-fixtures.sh                      # fixtures extracted from tests/test-secret-gate.sh
(cd go && go run ./internal/gate/internal/gencorpus -base internal/gate/testdata/encrypted -seed 1 -n 1000)
# on Linux, from the repo root, with LC_ALL=C:
cd go/internal/gate/testdata/encrypted
LC_ALL=C ./oracle.sh cases-fixtures.tsv > golden-fixtures.tsv
LC_ALL=C ./oracle.sh cases-mutants.tsv  > golden-mutants.tsv
# then, anywhere:
(cd go && go test ./...)
# and on Linux, to re-run the bash live from the Go test:
(cd go && SBX_ORACLE=1 go test ./internal/gate -run TestLiveOracle)
```

The committed golden files were produced with GNU awk 5.2.1 under `LC_ALL=C` on Ubuntu 24.04
(arm64). `mawk` 1.3.4 gives the same answers in both the C and C.UTF-8 locales; `gawk` under
`C.UTF-8` differs on lines with multibyte text (see `docs/design/spikes/S8.md`).
