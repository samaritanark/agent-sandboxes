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
| `internal/config` | all of `lib/config.sh` (except the unused `load_user_blocked_*`) and `lib/profile.sh`, plus `version_ge` from `lib/platform.sh`: the flat YAML readers and writers, overlay resolution, the ignore-file helpers, the extra-allowed-domains sources, profile lookup, validation and rendering, the overlay's minimum CLI version |
| `internal/gate` | the secret gate in `lib/filesystem.sh`: `finding_is_encrypted`, `is_path_masked`, `_leakscan_finding_accepted`, `scan_repo_secrets` and its helpers, `secret_gate_repos` |
| `internal/checks` | the egress side of `lib/checks.sh`: block lists (org, overlay, user), domain and CIDR matching, over-broad wildcards, the eTLD+1 apex rule, trusted inference endpoints (the manifest greps and `check_prerequisites` are not ported) |
| `internal/tier` | `lib/tier.sh`: tier names, extra egress domains, retention days |
| `internal/catalogue` | `lib/catalogue.sh`: resolving, reading, and validating dependency catalogue entries (cosign is injected; the oracle uses a stub) |
| `internal/audit` | the session-record half of `lib/audit.sh`: `session.json`, override and event records, the session list, with an ordered JSON value that reproduces jq's output byte for byte (transcript capture is not ported) |
| `internal/link` | `lib/link.sh`: link names and recorded state, path normalization, the overlay shape gate, and the run-path sync (git is executed, as in the bash) |
| `internal/onboard` | `lib/onboard.sh`: which host login files each agent stages, the Codex and Grok config hardening, the API-key refusal, and the starter user config |
| `internal/agents` | `lib/agents.sh` (per-agent domains, flags, MCP config, credential type, the opencode endpoint) and the host-environment check of `lib/credentials.sh` |
| `internal/allowlist` | the domain set of `build_cilium_policy` (`lib/policy.sh:42-97`): agent and tier domains, extras, the registrable unblocked apex of each `*.X`, deduplicated; in v3 the session spec's allowlist (design 5.4.1) |
| `internal/mounts` | the workspace mount rules of a Tier 2/3 session from `lib/manifest.sh` and `lib/filesystem.sh`: which paths each repo masks (empty file or directory) and which host-exec vectors it mounts read-only; in v3 part of the session spec (design 5.4.2) |
| `internal/secrets` | the host-side store of `lib/secrets.sh` (one 0600 file per secret, name validation, set, list, delete); v3 keeps it on the host (design 5.1.4) |
| `internal/jqjson` | the part of jq the bash's JSON writers rely on: ordered values, jq's input rules, and its pretty output (used by `audit` and `agents`) |
| `internal/cli`, `cmd/sandbox-vm` | the in-VM `sandbox` command (design 5.1.6): dispatch, usage texts, and the subcommands ported so far (`version`, `profile`, `check`, `mask`, `exceptions`, `vet`, `link`, `list`, `logs`, `cleanup`, `secret`, `onboard`, and the policy halves of `run`, `allow`, and `resume`, which then stop because sandboxd does not exist yet); the others print their v2 help and say they are not yet ported |
| `internal/workspace` | `validate_repo_path` and `workspace_prescan` from `lib/filesystem.sh` (which directories may be a workspace; the warn-only filename heuristics), tested through the CLI corpus; and the workspace baseline and diff (`capture_workspace_baseline`, `capture_workspace_diff`, `files.log`), with their own corpus |
| `internal/vetting` | all of `lib/vetting.sh`: posture and configuration, tag verification, the launch gate, committed exceptions, attestation |
| `internal/archtest` | the import-graph rules of section 5.1.1 (a package may import only what the table allows; the host binary's whole dependency closure stays within `internal/host/`) |
| `internal/host/...`, `cmd/sandbox` | the v3 host binary (design 5.1, 5.2), new code with no bash to port: `driver` (the VM driver interface and a mock), `release` (the version handshake on `/etc/sandbox/release`), `app` (the dispatcher: `vm start\|stop\|status\|shell`, removed commands, and proxying every other command to the in-VM `sandbox`). Its tests run on Linux, macOS, and Windows in CI |

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

Config writers and readers (`internal/config/testdata/write`; each case's return code, output, and resulting file bytes and mode):

```bash
(cd go && go run ./internal/config/internal/genwrite -base internal/config/testdata/write -seed 1 -n 40)
# on Linux, with LC_ALL=C:
LC_ALL=C go/internal/config/testdata/write/oracle.sh > go/internal/config/testdata/write/golden-write.tsv
```

Profiles and `version_ge` (`internal/config/testdata/profile`; each case's return code, stdout, and stderr):

```bash
(cd go && go run ./internal/config/internal/genprofile -base internal/config/testdata/profile -seed 1 -n 150)
# on Linux, with LC_ALL=C:
LC_ALL=C go/internal/config/testdata/profile/oracle.sh > go/internal/config/testdata/profile/golden-profile.tsv
```

Egress checks (`internal/checks/testdata`; return code, stdout, and stderr per case):

```bash
(cd go && go run ./internal/checks/internal/genchecks -base internal/checks/testdata -seed 1 -n 200)
# on Linux, with LC_ALL=C:
LC_ALL=C go/internal/checks/testdata/oracle.sh > go/internal/checks/testdata/golden-checks.tsv
```

Tiers (`internal/tier/testdata`; every input in `inputs.txt`) and the catalogue (`internal/catalogue/testdata`; each entry travels inside its case, so there are no fixture files):

```bash
(cd go && go run ./internal/catalogue/internal/genentries -base internal/catalogue/testdata -seed 1 -n 200)
# on Linux, with LC_ALL=C:
LC_ALL=C go/internal/tier/testdata/oracle.sh > go/internal/tier/testdata/golden-tier.txt
LC_ALL=C go/internal/catalogue/testdata/oracle.sh > go/internal/catalogue/testdata/golden-catalogue.tsv
```

Audit session record (`internal/audit/testdata`; step sequences over one `session.json`, with a fixed clock):

```bash
(cd go && go run ./internal/audit/internal/genaudit -base internal/audit/testdata -seed 1 -n 150)
# on Linux, with LC_ALL=C (needs jq):
LC_ALL=C go/internal/audit/testdata/oracle.sh > go/internal/audit/testdata/golden-audit.tsv
```

Team-overlay links (`internal/link/testdata`; overlay trees travel inside their cases, and `setup-sync.sh` builds each git sync scenario with fixed identities and dates, so commit IDs match everywhere):

```bash
(cd go && go run ./internal/link/internal/genlink -base internal/link/testdata -seed 1 -n 120)
# on Linux, with LC_ALL=C (needs git):
LC_ALL=C go/internal/link/testdata/oracle.sh > go/internal/link/testdata/golden-link.tsv
```

Onboarding (`internal/onboard/testdata`; each case builds a home from a spec, runs one onboard step, and records the whole resulting tree):

```bash
(cd go && go run ./internal/onboard/internal/genonboard -base internal/onboard/testdata -seed 1 -n 80)
# on Linux, with LC_ALL=C:
LC_ALL=C go/internal/onboard/testdata/oracle.sh > go/internal/onboard/testdata/golden-onboard.tsv
```

Agents (`internal/agents/testdata`; each case runs under `env -i` with only its own variables):

```bash
(cd go && go run ./internal/agents/internal/genagents -base internal/agents/testdata)
# on Linux, with LC_ALL=C (needs jq):
LC_ALL=C go/internal/agents/testdata/oracle.sh > go/internal/agents/testdata/golden-agents.tsv
```

The session allowlist (`internal/allowlist`; the oracle sources `lib/policy.sh` and reads back the entries `build_cilium_policy` renders):

```bash
# on Linux:
(cd go && go run ./internal/allowlist/internal/genallowlist -base internal/allowlist/testdata)
LC_ALL=C go/internal/allowlist/testdata/oracle.sh > go/internal/allowlist/testdata/golden-allowlist.tsv
```

The workspace baseline and diff (`internal/workspace/testdata/baseline`; GNU `find`, `sha256sum`, and `diff`):

```bash
# on Linux:
(cd go && go run ./internal/workspace/internal/genbaseline -base internal/workspace/testdata/baseline)
LC_ALL=C go/internal/workspace/testdata/baseline/oracle.sh > go/internal/workspace/testdata/baseline/golden-baseline.tsv
```

The workspace mounts (`internal/mounts`; the oracle sources `lib/manifest.sh` and prints `build_volume_mounts_block` and `_readonly_workspace_entries`):

```bash
# on Linux:
(cd go && go run ./internal/mounts/internal/genmounts -base internal/mounts/testdata)
LC_ALL=C go/internal/mounts/testdata/oracle.sh > go/internal/mounts/testdata/golden-mounts.tsv
```

The in-VM CLI (`internal/cli`; the oracle runs `bin/sandbox` itself from a copy of the install, and the usage texts are captured from it; for `run`, `testdata/cmd-stub.sh` sources the script with the cluster calls, the removed v2 host workarounds, the clock, and `/dev/urandom` stubbed, so a case ends with its session record written, where the cluster work would begin):

```bash
# on Linux:
go/internal/cli/testdata/gen-usage.sh
(cd go && go run ./internal/cli/internal/gencli -base internal/cli/testdata)
LC_ALL=C go/internal/cli/testdata/oracle.sh > go/internal/cli/testdata/golden-cli.tsv
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
