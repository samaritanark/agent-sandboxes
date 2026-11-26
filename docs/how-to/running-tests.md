# Running Tests

[← Documentation](../index.md)

v3 is Go (`go/`). Its tests run on Linux and macOS without a VM; a few packages (sandboxd, the
gateway, the VM's network code) build for Linux only, and their Linux parts are checked with
`GOOS=linux go vet`.

```bash
cd go

# The whole suite (CI runs it on Linux with a 40-minute limit)
go test ./...

# Linux-only code, vetted from a Mac
GOOS=linux go vet ./...

# The import-graph rules (which package may depend on which, and that the host binary stays
# policy-free). Run it uncached: it shells out to `go list`.
go test -count=1 ./internal/archtest
```

The suite is CPU-heavy. On a laptop, `GOFLAGS=-p=2 nice go test ./...` keeps the machine usable.

## The differential corpora

The policy layer (gates, vetting, masks, the CLI's flags and messages) was ported from v2's bash,
and its tests compare the Go code against that bash on generated cases: the "golden" tests check
recorded outputs, and the "live oracle" tests run the frozen bash next to the Go code. They need
bash 5, `ssh-keygen`, `jq`, and `python3`, and Linux-shaped tools (the goldens were recorded with
GNU tools; set `LC_ALL=C`). Fixes to bugs found in the bash are named in
`go/internal/deviation` and turned off in these comparisons, so the bash still matches.

## Mutation testing

`go/tools/mutate.py` plants known bugs (`go/tools/mutants.py`, one exact replacement each) and runs
the tests that should catch them; a planted bug that survives is a gap in the tests, unless it is
marked equivalent.

```bash
cd go
python3 tools/mutate.py --list              # the planted bugs, numbered
python3 tools/mutate.py --jobs 3 --from 1100 # run from one index on
python3 tools/mutate.py --pick 1104,1105     # run some
python3 tools/mutate.py --check              # only check that each still applies
```

`archtest` also fails when a planted bug no longer matches its source (`--check`'s test), so a
change to covered code must update its planted bugs. Keep `--jobs` low on a laptop.

## The appliance image and end-to-end runs

Building the appliance image needs Linux (mkosi v27.1; see `image/build.sh`).
`image/build-in-lima.sh` builds one in a Linux Lima VM from your checkout. End-to-end checks
install it with `sandbox install --dev-image`; see [Installing](installing.md).

## v2's tests

`tests/` holds v2's bash test suite (cluster tests need v2's k3s install). It stays with the frozen
bash until the bash is removed at the v3 release.
